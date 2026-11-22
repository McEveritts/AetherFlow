use anyhow::Context;
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::env;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::{TlsAcceptor, TlsConnector};

// ─────────────────────────────────────────────────────────────────────────────
// Cluster mTLS Transport, HTTP/2 gRPC (`cluster.ClusterService`), & HTTP JSON
// ─────────────────────────────────────────────────────────────────────────────

pub(super) const MAX_PREAUTH_HEADER_BYTES: usize = 16 * 1024;
pub(super) const MAX_CLUSTER_CONCURRENT_CONNS: usize = 64;
const MAX_CLUSTER_PEM_BYTES: u64 = 1024 * 1024;
pub(super) const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_JSON_BODY_BYTES: usize = 4 * 1024 * 1024;
pub(super) const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
pub(super) const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
pub(super) const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const GRPC_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(65);

pub(super) fn env_flag_true(name: &str) -> bool {
    env::var(name)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub(super) fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn is_loopback_host(host: &str) -> bool {
    let clean = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if clean.eq_ignore_ascii_case("localhost") {
        return true;
    }
    clean
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterBindConfig {
    pub host: String,
    pub port: String,
    pub bind_addr: String,
}

/// Resolves the cluster master bind address, defaulting to `127.0.0.1:50051` so the listener
/// is never exposed on `0.0.0.0` unless explicitly configured by the operator.
pub fn resolve_master_bind_config() -> MasterBindConfig {
    let port = non_empty_env("CLUSTER_GRPC_PORT")
        .or_else(|| non_empty_env("GRPC_PORT"))
        .unwrap_or_else(|| "50051".to_string());
    let host = non_empty_env("CLUSTER_GRPC_HOST")
        .or_else(|| non_empty_env("GRPC_HOST"))
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let bind_addr = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    MasterBindConfig {
        host,
        port,
        bind_addr,
    }
}

fn read_tls_pem_nofollow(path: &Path, label: &str) -> anyhow::Result<Vec<u8>> {
    if path.as_os_str().is_empty() {
        anyhow::bail!("{} path must not be empty", label);
    }

    #[cfg(unix)]
    let file = {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
        use std::path::Component;

        let Some(leaf_os) = path.file_name() else {
            anyhow::bail!(
                "{} at {} must include a regular filename",
                label,
                path.display()
            );
        };
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut cur_dir: Option<OwnedFd> = None;

        for comp in parent.components() {
            let dirfd = cur_dir.as_ref().map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
            match comp {
                Component::Prefix(_) | Component::ParentDir => {
                    anyhow::bail!(
                        "{} at {} must not contain parent-directory traversal",
                        label,
                        path.display()
                    );
                }
                Component::CurDir => {}
                Component::RootDir => {
                    let c_root = CString::new("/").context("invalid root path")?;
                    let fd = unsafe {
                        libc::open(
                            c_root.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(std::io::Error::last_os_error()).with_context(|| {
                            format!("failed opening root directory for {}", label)
                        });
                    }
                    cur_dir = Some(unsafe { OwnedFd::from_raw_fd(fd) });
                }
                Component::Normal(seg) => {
                    let c_seg = CString::new(seg.as_bytes()).with_context(|| {
                        format!("invalid path segment in {} at {}", label, path.display())
                    })?;
                    let fd = unsafe {
                        libc::openat(
                            dirfd,
                            c_seg.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(std::io::Error::last_os_error()).with_context(|| {
                            format!(
                                "failed opening ancestor directory for {} at {} (symlinked directories forbidden)",
                                label,
                                path.display()
                            )
                        });
                    }
                    cur_dir = Some(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
        }

        let dirfd = cur_dir.as_ref().map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd);
        let c_leaf = CString::new(leaf_os.as_bytes())
            .with_context(|| format!("invalid filename for {} at {}", label, path.display()))?;
        let leaf_fd = unsafe {
            libc::openat(
                dirfd,
                c_leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if leaf_fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed opening {} at {} (symlinks forbidden)",
                    label,
                    path.display()
                )
            });
        }
        let opened = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(leaf_fd) });

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstat(opened.as_raw_fd(), &mut st) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("fstat failed for {} at {}", label, path.display()));
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            anyhow::bail!("{} at {} must be a regular file", label, path.display());
        }
        if (st.st_mode & 0o002) != 0 {
            anyhow::bail!("{} at {} must not be world-writable", label, path.display());
        }
        if st.st_size <= 0 {
            anyhow::bail!("{} at {} is empty", label, path.display());
        }
        if (st.st_size as u64) > MAX_CLUSTER_PEM_BYTES {
            anyhow::bail!(
                "{} at {} exceeds maximum PEM size ({} bytes)",
                label,
                path.display(),
                MAX_CLUSTER_PEM_BYTES
            );
        }
        opened
    };

    #[cfg(not(unix))]
    let file = {
        let meta = std::fs::symlink_metadata(path).with_context(|| {
            format!(
                "failed reading metadata for {} at {}",
                label,
                path.display()
            )
        })?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            anyhow::bail!(
                "{} at {} must be a regular non-symlink file",
                label,
                path.display()
            );
        }
        if meta.len() == 0 || meta.len() > MAX_CLUSTER_PEM_BYTES {
            anyhow::bail!(
                "{} at {} has invalid size ({} bytes)",
                label,
                path.display(),
                meta.len()
            );
        }
        std::fs::File::open(path)
            .with_context(|| format!("failed opening {} at {}", label, path.display()))?
    };

    let mut bytes = Vec::new();
    file.take(MAX_CLUSTER_PEM_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed reading {} from {}", label, path.display()))?;
    if bytes.is_empty() {
        anyhow::bail!("{} at {} is empty", label, path.display());
    }
    if (bytes.len() as u64) > MAX_CLUSTER_PEM_BYTES {
        anyhow::bail!(
            "{} at {} exceeds {} bytes",
            label,
            path.display(),
            MAX_CLUSTER_PEM_BYTES
        );
    }
    Ok(bytes)
}

pub(super) fn load_root_cert_store(ca_path: &Path, label: &str) -> anyhow::Result<RootCertStore> {
    let ca_bytes = read_tls_pem_nofollow(ca_path, label)?;
    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&ca_bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed parsing CA PEM certificates in {}",
                ca_path.display()
            )
        })?;
    if ca_certs.is_empty() {
        anyhow::bail!("no PEM CA certificates found in {}", ca_path.display());
    }
    let mut store = RootCertStore::empty();
    let (added, _) = store.add_parsable_certificates(ca_certs);
    if added == 0 {
        anyhow::bail!(
            "failed adding any valid CA certificate from {}",
            ca_path.display()
        );
    }
    Ok(store)
}

fn load_cert_chain_and_key(
    cert_path: &Path,
    cert_label: &str,
    key_path: &Path,
    key_label: &str,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_bytes = read_tls_pem_nofollow(cert_path, cert_label)?;
    let key_bytes = read_tls_pem_nofollow(key_path, key_label)?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed parsing PEM certificate chain in {}",
                cert_path.display()
            )
        })?;
    if certs.is_empty() {
        anyhow::bail!("no PEM certificates found in {}", cert_path.display());
    }
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)
        .with_context(|| format!("failed parsing PEM private key in {}", key_path.display()))?;
    Ok((certs, key))
}

/// Builds a TLS 1.3 mutual-TLS (`RequireAndVerifyClientCert`) server acceptor with ALPN `h2` + `http/1.1`.
pub fn build_master_mtls_acceptor(
    ca_path: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<TlsAcceptor> {
    let root_store = load_root_cert_store(ca_path, "CLUSTER_CA_CERT")?;
    let (server_certs, server_key) = load_cert_chain_and_key(
        cert_path,
        "CLUSTER_SERVER_CERT",
        key_path,
        "CLUSTER_SERVER_KEY",
    )?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(root_store), Arc::clone(&provider))
            .build()
            .context("failed building mandatory cluster mTLS client certificate verifier")?;

    let mut server_cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed enforcing TLS 1.3 minimum version for cluster mTLS server")?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_certs, server_key)
        .context("invalid cluster server certificate or private key")?;
    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_cfg)))
}

/// Builds a TLS 1.3 mutual-TLS client connector with ALPN `h2` + `http/1.1`.
pub fn build_worker_mtls_connector(
    ca_path: &Path,
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<TlsConnector> {
    let root_store = load_root_cert_store(ca_path, "CLUSTER_CA_CERT")?;
    let (client_certs, client_key) = load_cert_chain_and_key(
        cert_path,
        "CLUSTER_CLIENT_CERT",
        key_path,
        "CLUSTER_CLIENT_KEY",
    )?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("failed enforcing TLS 1.3 minimum version for cluster mTLS worker")?
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .context("invalid cluster worker client certificate or private key")?;
    client_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

#[derive(Clone)]
pub enum MasterTransportSecurity {
    Mtls {
        acceptor: TlsAcceptor,
        admin_cert_sha256: Option<String>,
    },
    InsecureLoopback,
}

fn load_pinned_admin_client_cert_sha256() -> anyhow::Result<Option<String>> {
    let Some(admin_cert_path) = non_empty_env("CLUSTER_ADMIN_CLIENT_CERT") else {
        return Ok(None);
    };
    let pem_bytes =
        read_tls_pem_nofollow(Path::new(&admin_cert_path), "CLUSTER_ADMIN_CLIENT_CERT")?;
    let mut certs = CertificateDer::pem_slice_iter(&pem_bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| {
            format!(
                "failed parsing CLUSTER_ADMIN_CLIENT_CERT PEM at {}",
                admin_cert_path
            )
        })?;
    let Some(leaf) = certs.drain(..).next() else {
        anyhow::bail!(
            "no PEM certificate found in CLUSTER_ADMIN_CLIENT_CERT at {}",
            admin_cert_path
        );
    };
    Ok(Some(hex::encode(Sha256::digest(leaf.as_ref()))))
}

/// Evaluates `CLUSTER_CA_CERT`, `CLUSTER_SERVER_CERT`, and `CLUSTER_SERVER_KEY` (plus optional
/// exclusive `CLUSTER_ADMIN_CLIENT_CERT` pin).
/// Enforces mandatory TLS 1.3 mTLS in production; only allows unencrypted loopback when all three
/// cert variables are unset, `CLUSTER_ALLOW_INSECURE_LOOPBACK=true`, and `bind_host` is loopback.
pub fn load_master_transport_security(bind_host: &str) -> anyhow::Result<MasterTransportSecurity> {
    let ca = non_empty_env("CLUSTER_CA_CERT");
    let cert = non_empty_env("CLUSTER_SERVER_CERT");
    let key = non_empty_env("CLUSTER_SERVER_KEY");

    match (ca, cert, key) {
        (Some(ca_path), Some(cert_path), Some(key_path)) => {
            let acceptor = build_master_mtls_acceptor(
                Path::new(&ca_path),
                Path::new(&cert_path),
                Path::new(&key_path),
            )?;
            let admin_cert_sha256 = load_pinned_admin_client_cert_sha256()?;
            Ok(MasterTransportSecurity::Mtls {
                acceptor,
                admin_cert_sha256,
            })
        }
        (None, None, None) => {
            if env_flag_true("CLUSTER_ALLOW_INSECURE_LOOPBACK") && is_loopback_host(bind_host) {
                tracing::warn!(
                    bind_host = %bind_host,
                    "CLUSTER_ALLOW_INSECURE_LOOPBACK=true enabled without mTLS certificates on loopback"
                );
                Ok(MasterTransportSecurity::InsecureLoopback)
            } else {
                anyhow::bail!(
                    "CLUSTER_CA_CERT, CLUSTER_SERVER_CERT, and CLUSTER_SERVER_KEY must be set to enable secure cluster mTLS (refusing unencrypted listener on '{}')",
                    bind_host
                )
            }
        }
        _ => anyhow::bail!(
            "CLUSTER_CA_CERT, CLUSTER_SERVER_CERT, and CLUSTER_SERVER_KEY must all be set together for cluster mTLS"
        ),
    }
}
