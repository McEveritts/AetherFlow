# AetherFlow v4 Native Declarative Package Execution (Backlog #10)

## Overview

`backend-rs/crates/af-runner/src/package_executor.rs` implements the native Rust declarative package execution engine for AetherFlow v4 Backlog #10 (`fail2ban`, `quassel`, and `threadfin`).

Instead of invoking arbitrary `bash -c` or `sh -c` lifecycle scripts, the declarative engine executes strongly typed, validated `DeclarativeStep` operations with:

- **Cross-Process & In-Process Serialization**: Coordinated via `crate::PACKAGE_MUTEX` and persistent inode-stable `/install/.af-package-executor.flock` `flock(LOCK_EX | LOCK_NB)`.
- **Cooperative Cancellation**: Process-group (`killpg`) cancellation and pre/post-boundary checks across every mutating step, queued lock wait, and streaming download chunk.
- **Transactional Rollback Journal**: `RollbackJournal` snapshots existing configuration files, systemd units, and binaries before mutation and automatically restores or removes newly created files if any step fails or is cancelled.
- **Systemd Sandboxing**: Automatically writes `/etc/systemd/system/<unit>.d/aetherflow-sandbox.conf` (`ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true`, and scoped `ReadWritePaths`) prior to service activation.

---

## Native Declarative Recipes

| Package ID | Systemd Unit | Default Port | Service User | Lock File | Version / Verification Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `fail2ban` | `fail2ban.service` | Host SSH port | `root` | `/install/.fail2ban.lock` | APT (`fail2ban`, `whois`, `python3-systemd`) + `sshd_config` port probe |
| `quassel` | `quasselcore.service` | `4242` (`req.app_port` override) | `quasselcore` | `/install/.quassel.lock` | APT (`quassel-core`, `openssl`, `ca-certificates`) + `dpkg-query` version probe + narrow `EnsureSelfSignedCert` |
| `threadfin` | `threadfin.service` | `34400` (`req.app_port` override) | `threadfin` | `/install/.threadfin.lock` | Pinned upstream release `1.2.37` over HTTPS with per-architecture SHA-256 + ELF `e_machine` verification |

---

## Quassel Native Recipe (`quassel`)

### Parity & Security Guarantees
1. **APT Dependencies**: `quassel-core`, `openssl`, `ca-certificates`.
2. **System User & Directories**: Ensures system user `quasselcore` and directories `/var/lib/quassel` and `/var/log/quassel` (`0750`, owned by `quasselcore:quasselcore`).
3. **Certificate Preservation (`EnsureSelfSignedCert`)**:
   - Checks `/var/lib/quassel/quasselCert.pem` before running `openssl`.
   - Existing certificate bytes are preserved; mode `0600` and service ownership are enforced. The rollback journal records an existing certificate as restorable, never as a newly created file, and retains its pre-operation mode and ownership.
   - If absent, generates a 4096-bit RSA self-signed certificate (`-x509 -nodes -days 3650 -newkey rsa:4096 -subj /CN=quassel.aether.local`) via direct argv `openssl` invocation before installing `quassel-core`. This prevents Debian's post-install script from generating a stock certificate.
4. **Port & Config Parity**:
   - Uses `req.app_port` when in `1024..=65535` (or `AF_QUASSEL_PORT`), defaulting to `4242`.
   - Writes `/etc/default/quasselcore` before installing `quassel-core` and uses the distribution's `quasselcore.service`. Sandbox drop-ins are staged and systemd is reloaded before APT can activate the daemon.
5. **Data Preservation on Remove**:
   - When `DELETE_DATA=false` (default), removes the APT package without purging it, stops/disables `quasselcore.service`, and removes runtime metadata and `/install/.quassel.lock`, while preserving `/var/lib/quassel` (SQLite backlog database and `quasselCert.pem`) and `/var/log/quassel`.
   - When `DELETE_DATA=true`, purges the APT package and removes `/var/lib/quassel` and `/var/log/quassel`.

---

## Threadfin Native Recipe (`threadfin`)

### Pinned Upstream Verification (`1.2.37`)
Official Threadfin release `1.2.37` (`https://github.com/Threadfin/Threadfin/releases/expanded_assets/1.2.37`) publishes trusted SHA-256 digests. Unverified `releases/latest` lookups and runtime `go build` fallbacks are prohibited.

| Architecture | Upstream Asset | Pinned SHA-256 Digest | ELF `e_machine` |
| :--- | :--- | :--- | :--- |
| `amd64` (`x86_64`) | `Threadfin_linux_amd64_glibc_2.31_compat` | `0b80a1bb5dc270c35288531408657189fd27c2e4346686743ebd36f3b6acbe42` | `EM_X86_64` (`62`) |
| `arm64` (`aarch64`) | `Threadfin_linux_arm64` | `1e5e6f065cf2470d1460fae80c68c9631ca79e67ff76f83d47ab4bcb9ceb6213` | `EM_AARCH64` (`183`) |
| `armhf` (`armv7l`) | `Threadfin_linux_arm` | `d64e6b7f8a1ab8aebdd37d06bfb0bddb991c68c9fed52e25530b92ead10c8328` | `EM_ARM` (`40`) |
| `amd64` (plain reference) | `Threadfin_linux_amd64` | `19183058cf28b0080df059113e546a8e8cac16cae210d13be51bda42af94dfc2` | `EM_X86_64` (`62`) |

### Verification & Fail-Closed Controls
1. **HTTPS Fail-Closed**: `validate_step` and `fetch_artifact_to_temp` reject any non-`https://` URL with `PackageExecutorError::SecurityViolation`.
2. **Bounds & Streaming Cap**: Enforces `min_size_bytes` (`1024` bytes) and `max_size_bytes` (`128 MiB`) during streaming download so oversized payloads abort immediately.
3. **ELF Magic & Architecture Check**: `verify_artifact_file_for_arch` validates the `\x7fELF` magic header, little-endian encoding, and the 16-bit ELF `e_machine` header field against the target architecture before comparing the full SHA-256 digest.
4. **Port & Service Parity**:
   - Uses `req.app_port` when in `1024..=65535`, defaulting to `34400`.
   - Runs as dedicated `threadfin` system user with `HOME=/var/lib/threadfin` and `-port={{APP_PORT}} -config=/var/lib/threadfin/conf`.
   - Seeds only a missing/empty `bindIpAddress` in `settings.json` to `127.0.0.1`. Threadfin 1.2.37 overwrites its command-line bind flag during host-IP discovery, so this supported JSON setting is necessary for the local proxy. Other settings and any explicit nonempty binding are preserved; malformed settings fail closed.
   - A newly seeded settings object includes schema version `0.5.0`, required by Threadfin's migration checks. Existing nonempty settings must provide a version string.
   - Reloads systemd, enables the service, and explicitly restarts it after installing the verified binary and writing configuration. `enable --now` alone does not replace an already-running daemon or apply a changed port on update.
   - Preserves `/var/lib/threadfin` on remove unless `DELETE_DATA=true`.

## Removal Failure Semantics

APT maintainer scripts are not reversible file transactions. Failed or cancelled
removal therefore invalidates the installed completion marker and reports an
incomplete operation; it does not claim that an already removed package or
service was magically restored. Operators can retry removal or reinstall to
reconcile state. Fail2ban and Quassel default to APT `remove`, not `purge`, and
require `DELETE_DATA=true` for configuration/data deletion. Sandbox drop-ins are
journaled for install/update and applied before APT service activation.

The 33 passing runner unit tests and strict runner Clippy result are bounded
source-level evidence. Live guest results are tracked separately in
`v4-native-package-testing.md` and `v4-backlog-verification.md`.
