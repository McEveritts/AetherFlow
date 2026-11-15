use crate::config::Config;
use anyhow::{bail, Context, Result};
use axum::extract::{ConnectInfo, Request};
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, warn};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const TLS_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_TLS_CONNECTIONS: usize = 512;

pub fn build_tls_acceptor(config: &Config) -> Result<TlsAcceptor> {
    if config.tls_cert_file.as_os_str().is_empty() {
        bail!("enable_tls=true requires a non-empty tls_cert_file path in settings.toml");
    }
    if config.tls_key_file.as_os_str().is_empty() {
        bail!("enable_tls=true requires a non-empty tls_key_file path in settings.toml");
    }

    ensure_regular_readable_file(&config.tls_cert_file, "tls_cert_file")?;
    ensure_regular_readable_file(&config.tls_key_file, "tls_key_file")?;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&config.tls_cert_file)
        .with_context(|| {
            format!(
                "failed to open TLS certificate chain {}",
                config.tls_cert_file.display()
            )
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed to parse PEM certificate(s) from {}",
                config.tls_cert_file.display()
            )
        })?;

    if certs.is_empty() {
        bail!(
            "no PEM certificates found in tls_cert_file {}",
            config.tls_cert_file.display()
        );
    }

    let key = PrivateKeyDer::from_pem_file(&config.tls_key_file).with_context(|| {
        format!(
            "failed to load PEM private key from {}",
            config.tls_key_file.display()
        )
    })?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server_cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed configuring safe TLS 1.2/1.3 protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid TLS certificate / private key pair")?;

    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_cfg)))
}

fn ensure_regular_readable_file(path: &Path, field: &str) -> Result<()> {
    let meta = fs::metadata(path).with_context(|| {
        format!(
            "{field} does not exist or cannot be read: {}",
            path.display()
        )
    })?;
    if !meta.is_file() {
        bail!("{field} is not a regular file: {}", path.display());
    }
    Ok(())
}

pub async fn serve_tls<F>(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: Router,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let conn_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TLS_CONNECTIONS));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let (tcp_stream, peer_addr) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        warn!(error = %err, "TCP accept error on TLS listener");
                        continue;
                    }
                };
                let Ok(permit) = conn_semaphore.clone().try_acquire_owned() else {
                    debug!(peer = %peer_addr, "Dropping TLS connection above concurrency cap");
                    continue;
                };
                let acceptor = acceptor.clone();
                let router = app.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = tcp_stream.set_nodelay(true);
                    let tls_stream = match tokio::time::timeout(
                        TLS_HANDSHAKE_TIMEOUT,
                        acceptor.accept(tcp_stream),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(err)) => {
                            debug!(peer = %peer_addr, error = %err, "TLS handshake failed");
                            return;
                        }
                        Err(_) => {
                            debug!(peer = %peer_addr, "TLS handshake timed out");
                            return;
                        }
                    };

                    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let router = router.clone();
                        async move {
                            let (mut parts, body) = req.into_parts();
                            parts.extensions.insert(ConnectInfo(peer_addr));
                            let axum_req = Request::from_parts(parts, axum::body::Body::new(body));
                            router.oneshot(axum_req).await
                        }
                    });

                    let io = TokioIo::new(tls_stream);
                    let mut builder = AutoConnBuilder::new(TokioExecutor::new());
                    builder
                        .http1()
                        .timer(TokioTimer::new())
                        .header_read_timeout(HTTP_HEADER_READ_TIMEOUT);
                    if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
                        debug!(peer = %peer_addr, error = %err, "TLS HTTP connection closed with error");
                    }
                });
            }
        }
    }

    drop(listener);
    let _ = tokio::time::timeout(TLS_SHUTDOWN_DRAIN_TIMEOUT, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    tasks.abort_all();

    Ok(())
}
