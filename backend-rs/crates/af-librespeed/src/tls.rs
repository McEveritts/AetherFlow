use crate::config::Config;
use anyhow::{bail, Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request};
use axum::response::Response;
use axum::Router;
use hyper::body::{Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::convert::Infallible;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, warn};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
const HTTP_IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP2_MAX_CONCURRENT_STREAMS: u32 = 32;
const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_TLS_CONNECTIONS: usize = 512;

#[derive(Debug, Clone, Copy)]
pub struct ListenerLimits {
    pub max_connections: usize,
    pub header_read_timeout: Duration,
    pub idle_connection_timeout: Duration,
    pub http2_max_concurrent_streams: u32,
}

impl Default for ListenerLimits {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONCURRENT_TLS_CONNECTIONS,
            header_read_timeout: HTTP_HEADER_READ_TIMEOUT,
            idle_connection_timeout: HTTP_IDLE_CONNECTION_TIMEOUT,
            http2_max_concurrent_streams: HTTP2_MAX_CONCURRENT_STREAMS,
        }
    }
}

#[derive(Clone)]
pub struct ConnectionAbortSignal(pub Arc<Notify>);

impl ConnectionAbortSignal {
    pub fn abort(&self) {
        self.0.notify_one();
    }

    pub fn abort_after_flush(&self) {
        let notify = Arc::clone(&self.0);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            notify.notify_one();
        });
    }
}

struct ConnStreamGuard {
    active_streams: Arc<AtomicUsize>,
    stream_changed: Arc<Notify>,
}

impl ConnStreamGuard {
    fn acquire(active_streams: &Arc<AtomicUsize>, stream_changed: &Arc<Notify>) -> Self {
        active_streams.fetch_add(1, Ordering::SeqCst);
        stream_changed.notify_one();
        Self {
            active_streams: Arc::clone(active_streams),
            stream_changed: Arc::clone(stream_changed),
        }
    }
}

impl Drop for ConnStreamGuard {
    fn drop(&mut self) {
        if self.active_streams.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.stream_changed.notify_one();
        }
    }
}

struct GuardedBody {
    inner: Body,
    _guard: ConnStreamGuard,
}

impl hyper::body::Body for GuardedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

async fn wait_for_idle_expiry(
    active_streams: Arc<AtomicUsize>,
    stream_changed: Arc<Notify>,
    idle_timeout: Duration,
) {
    loop {
        if active_streams.load(Ordering::SeqCst) == 0 {
            tokio::select! {
                _ = tokio::time::sleep(idle_timeout) => {
                    if active_streams.load(Ordering::SeqCst) == 0 {
                        return;
                    }
                }
                _ = stream_changed.notified() => {}
            }
        } else {
            stream_changed.notified().await;
        }
    }
}

fn configure_conn_builder(builder: &mut AutoConnBuilder<TokioExecutor>, limits: ListenerLimits) {
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(limits.http2_max_concurrent_streams)
        .max_header_list_size(16 * 1024)
        .max_frame_size(16 * 1024)
        .keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT);
}

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

pub async fn serve_http<F>(listener: TcpListener, app: Router, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_http_with_limits(listener, app, shutdown, ListenerLimits::default()).await
}

pub async fn serve_http_with_limits<F>(
    listener: TcpListener,
    app: Router,
    shutdown: F,
    limits: ListenerLimits,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let conn_semaphore = Arc::new(Semaphore::new(limits.max_connections.max(1)));
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
                        warn!(error = %err, "TCP accept error on HTTP listener");
                        continue;
                    }
                };
                let Ok(permit) = conn_semaphore.clone().try_acquire_owned() else {
                    debug!(peer = %peer_addr, "Dropping HTTP connection above concurrency cap");
                    continue;
                };
                let router = app.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = tcp_stream.set_nodelay(true);
                    let abort_notify = Arc::new(Notify::new());
                    let active_streams = Arc::new(AtomicUsize::new(0));
                    let stream_changed = Arc::new(Notify::new());

                    let req_abort = Arc::clone(&abort_notify);
                    let req_active = Arc::clone(&active_streams);
                    let req_changed = Arc::clone(&stream_changed);
                    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let router = router.clone();
                        let conn_abort = Arc::clone(&req_abort);
                        let guard = ConnStreamGuard::acquire(&req_active, &req_changed);
                        async move {
                            let (mut parts, body) = req.into_parts();
                            parts.extensions.insert(ConnectInfo(peer_addr));
                            parts.extensions.insert(ConnectionAbortSignal(conn_abort));
                            let axum_req = Request::from_parts(parts, Body::new(body));
                            let resp: Response = router.oneshot(axum_req).await?;
                            let (resp_parts, resp_body) = resp.into_parts();
                            Ok::<_, Infallible>(hyper::Response::from_parts(
                                resp_parts,
                                GuardedBody {
                                    inner: resp_body,
                                    _guard: guard,
                                },
                            ))
                        }
                    });

                    let io = TokioIo::new(tcp_stream);
                    let mut builder = AutoConnBuilder::new(TokioExecutor::new());
                    configure_conn_builder(&mut builder, limits);
                    tokio::select! {
                        res = builder.serve_connection_with_upgrades(io, service) => {
                            if let Err(err) = res {
                                debug!(peer = %peer_addr, error = %err, "HTTP connection closed with error");
                            }
                        }
                        _ = abort_notify.notified() => {
                            debug!(peer = %peer_addr, "Aborted stalled HTTP connection after stream deadline");
                        }
                        _ = wait_for_idle_expiry(active_streams, stream_changed, limits.idle_connection_timeout) => {
                            debug!(peer = %peer_addr, "Closed idle HTTP connection after idle timeout");
                        }
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

pub async fn serve_tls<F>(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: Router,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    serve_tls_with_limits(listener, acceptor, app, shutdown, ListenerLimits::default()).await
}

pub async fn serve_tls_with_limits<F>(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: Router,
    shutdown: F,
    limits: ListenerLimits,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let conn_semaphore = Arc::new(Semaphore::new(limits.max_connections.max(1)));
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

                    let abort_notify = Arc::new(Notify::new());
                    let active_streams = Arc::new(AtomicUsize::new(0));
                    let stream_changed = Arc::new(Notify::new());

                    let req_abort = Arc::clone(&abort_notify);
                    let req_active = Arc::clone(&active_streams);
                    let req_changed = Arc::clone(&stream_changed);
                    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let router = router.clone();
                        let conn_abort = Arc::clone(&req_abort);
                        let guard = ConnStreamGuard::acquire(&req_active, &req_changed);
                        async move {
                            let (mut parts, body) = req.into_parts();
                            parts.extensions.insert(ConnectInfo(peer_addr));
                            parts.extensions.insert(ConnectionAbortSignal(conn_abort));
                            let axum_req = Request::from_parts(parts, Body::new(body));
                            let resp: Response = router.oneshot(axum_req).await?;
                            let (resp_parts, resp_body) = resp.into_parts();
                            Ok::<_, Infallible>(hyper::Response::from_parts(
                                resp_parts,
                                GuardedBody {
                                    inner: resp_body,
                                    _guard: guard,
                                },
                            ))
                        }
                    });

                    let io = TokioIo::new(tls_stream);
                    let mut builder = AutoConnBuilder::new(TokioExecutor::new());
                    configure_conn_builder(&mut builder, limits);
                    tokio::select! {
                        res = builder.serve_connection_with_upgrades(io, service) => {
                            if let Err(err) = res {
                                debug!(peer = %peer_addr, error = %err, "TLS HTTP connection closed with error");
                            }
                        }
                        _ = abort_notify.notified() => {
                            debug!(peer = %peer_addr, "Aborted stalled TLS connection after stream deadline");
                        }
                        _ = wait_for_idle_expiry(active_streams, stream_changed, limits.idle_connection_timeout) => {
                            debug!(peer = %peer_addr, "Closed idle TLS connection after idle timeout");
                        }
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
