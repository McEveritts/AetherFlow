# AetherFlow v4 Native Declarative Package Execution

## Overview

The [package executor](../backend-rs/crates/af-runner/src/package_executor.rs) supports 9 [built-in Rust recipes](../backend-rs/crates/af-runner/src/package_executor/declarative_recipes.rs) for `fail2ban`, `quassel`, `threadfin`, `znc`, `xrdp`, `x2go`, `netdata`, `mergerfs`, and `rclone`. Set `AETHERFLOW_ENABLE_RUST_PACKAGES=1` in `/etc/aetherflow/aetherflow.env` (or an `aetherflow-runner.service` drop-in) and restart `aetherflow-runner.service` to opt in. Bash is the default for all 77 packages, and `AETHERFLOW_FORCE_BASH_PACKAGES=1` takes precedence over the opt-in.

Most declarative operations execute typed, validated `DeclarativeStep` variants via direct `execve` rather than shell pipelines (exception: `DeclarativeStep::RunCommand`, currently used by `build_rclone_recipe` to execute `/bin/sh -c` during removal cleanup), paired with:

- **Cross-Process & In-Process Serialization**: Coordinated via `crate::PACKAGE_MUTEX`, the shared maintenance lock, and persistent inode-stable `/install/.af-package-executor.flock` `flock(LOCK_EX | LOCK_NB)`.
- **Cooperative Cancellation**: Process-group (`killpg`) cancellation and pre/post-boundary checks across every mutating step, queued lock wait, and streaming download chunk.
- **Transactional Rollback Journal**: `RollbackJournal` snapshots existing configuration files, mutable state directories, systemd units, and binaries before mutation and restores or removes newly created files if a step fails or is cancelled.
- **Systemd Sandboxing**: For non-privileged units, `apply_sandbox_in_root_with_journal` (`package_executor/helpers.rs`) writes both `aetherflow-sandbox.conf` and `10-aetherflow-sandbox.conf` under `/etc/systemd/system/<unit>.d/` (`ProtectSystem=strict`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, and scoped `ReadWritePaths`) before `AptInstall` and before service activation (refreshing after `WriteSystemdUnit`). Units configured with `sandbox_profile: "privileged"` or `"none"` in `config/package_automation.json` (which exempts `xrdp.service` and `xrdp-sesman.service`), or matched by `is_exempt_sandbox_unit` (`sandbox_ops.rs`: exact `"fail2ban.service"` and `"netdata.service"`, prefixes `x2goserver*`, `mergerfs*`, and `rclone-vfs*`, `.timer`/`.socket` units, and host-infrastructure units), skip sandboxing and have any pre-existing sandbox drop-ins removed.

---

## Native Declarative Recipes (9 Built-In)

| Package ID | Systemd Unit(s) | Default Port | Service User | Sandbox Profile | Lock File | Version / Verification Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `fail2ban` | `fail2ban.service` | Host SSH port | `root` | `privileged` (exempt) | `/install/.fail2ban.lock` | APT (`fail2ban`, `python3-systemd`, `iptables`) + `sshd_config` port probe |
| `quassel` | `quasselcore.service` | `4242` (`req.app_port`) | `quasselcore` | Sandboxed | `/install/.quassel.lock` | APT (`quassel-core`, `openssl`) + `dpkg-query` + `GenerateSelfSignedTlsCert` |
| `threadfin` | `threadfin.service` | `34400` (`req.app_port`) | `threadfin` | Sandboxed | `/install/.threadfin.lock` | Pinned GitHub release `1.2.37` + SHA-256 + ELF `e_machine` + HTTP `/status` |
| `znc` | `znc.service` | `6501` (`req.app_port`) | `znc` | Sandboxed | `/install/.znc.lock` | APT (`znc`) + `znc.conf` (`SSL = false`) + `dpkg-query` + `WaitForHttpReady` |
| `xrdp` | `xrdp.service`, `xrdp-sesman.service` | `3389` | `xrdp` / `root` | `privileged` (exempt) | `/install/.xrdp.lock` | APT (`xrdp`, `xorgxrdp`, `xfce4`, `xfce4-goodies`, `dbus-x11`) + `dpkg-query` |
| `x2go` | `x2goserver.service` | Host SSH | `root` | `privileged` (exempt) | `/install/.x2go.lock` | APT (`x2goserver`, `x2goserver-xsession`, `xfce4`, `dbus-x11`) + `dpkg-query` |
| `netdata` | `netdata.service` | `19999` (`req.app_port`) | `netdata` | `privileged` (exempt) | `/install/.netdata.lock` | APT (`netdata`) + `MergeIniSettings` (`{{BIND_ADDRESS}}`, `{{APP_PORT}}`) + `dpkg-query` + HTTP `/api/v1/info` |
| `mergerfs` | `mergerfs.service` | None | `root` | `privileged` (exempt) | `/install/.mergerfs.lock` | APT (`mergerfs`, `fuse3`) + `dpkg-query` + safe `UnmountPaths` on removal |
| `rclone` | `rclone.service`, `rclone-vfs.service` | `5572` (`req.app_port`) | `rclone` / `root` | `rclone` sandboxed; `rclone-vfs` exempt | `/install/.rclone.lock` | APT (`fuse3`) + upstream binary (`InstallRcloneBinary`) + `/etc/rclone/rclone.env` |

---

## Quassel Native Recipe (`quassel`)

### Parity & Security Checks

1. **APT Dependencies**: `openssl` (staged first) and `quassel-core`.
2. **System User & Directories**: Ensures system user `quasselcore` and directories `/var/lib/quassel` and `/var/log/quassel` (`0750`, owned by `quasselcore:quasselcore`).
3. **Certificate Preservation (`GenerateSelfSignedTlsCert`)**:
   - Checks `/var/lib/quassel/quasselCert.pem` before running `openssl`.
   - Existing certificate bytes are preserved; mode `0600` and service ownership are enforced. The rollback journal records an existing certificate as restorable, never as a newly created file, and retains its pre-operation mode and ownership.
   - If absent, generates a 4096-bit RSA self-signed certificate (`-x509 -nodes -days 3650 -newkey rsa:4096 -subj /CN=quassel.aether.local`) via direct argv `openssl` invocation before installing `quassel-core`, preventing Debian's post-install script from generating a stock certificate.
4. **Port, Config & Systemd Unit**:
   - Uses `req.app_port` when in `1024..=65535` (or `AF_QUASSEL_PORT`), defaulting to `4242`.
   - Writes `/etc/default/quasselcore` before installing `quassel-core`, writes `/etc/systemd/system/quasselcore.service` via `DeclarativeStep::WriteSystemdUnit` (overriding the distribution unit), stages sandbox drop-ins, and reloads systemd before activation.
5. **Data Preservation vs. Purge on Remove**:
   - When `DELETE_DATA=false` (default): removes `quassel-core` and `quassel-data` via `AptRemove` without purging, runs `PurgeSystemdUnit` on `/etc/systemd/system/quasselcore.service`, removes `/install/.quassel.lock`, and writes `/install/.quassel.retained` while preserving `/var/lib/quassel` (SQLite backlog database and `quasselCert.pem`), `/var/log/quassel`, and the `quasselcore` user.
   - When `DELETE_DATA=true`: purges the APT packages, deletes `/var/lib/quassel`, `/var/log/quassel`, `/etc/default/quasselcore`, and `/var/log/quasselcore.log`, and purges the `quasselcore` system user.

---

## Threadfin Native Recipe (`threadfin`)

### Pinned Upstream Verification (`1.2.37`)

Official Threadfin release `1.2.37` (`https://github.com/Threadfin/Threadfin/releases/expanded_assets/1.2.37`) provides published upstream SHA-256 digests. Unverified `releases/latest` lookups and runtime `go build` fallbacks are prohibited.

| Architecture | Upstream Asset | Pinned SHA-256 Digest | ELF `e_machine` |
| :--- | :--- | :--- | :--- |
| `amd64` (`x86_64`) | `Threadfin_linux_amd64_glibc_2.31_compat` | `0b80a1bb5dc270c35288531408657189fd27c2e4346686743ebd36f3b6acbe42` | `EM_X86_64` (`62`) |
| `arm64` (`aarch64`) | `Threadfin_linux_arm64` | `1e5e6f065cf2470d1460fae80c68c9631ca79e67ff76f83d47ab4bcb9ceb6213` | `EM_AARCH64` (`183`) |
| `armhf` (`armv7l`) | `Threadfin_linux_arm` | `d64e6b7f8a1ab8aebdd37d06bfb0bddb991c68c9fed52e25530b92ead10c8328` | `EM_ARM` (`40`) |
| `amd64` (plain legacy cache fallback) | `Threadfin_linux_amd64` | `19183013ec8da826e556bde3b511d9f93b9269f6d7eddd78a9df128529f45e4e` | `EM_X86_64` (`62`) |

### Verification & Fail-Closed Controls

1. **URL Scheme Validation**: `validate_step` and `fetch_artifact_to_temp_with_source` permit `https://` and local `file://` URLs (for isolated fixture testing) and reject all other schemes with `PackageExecutorError::SecurityViolation`.
2. **Artifact Size Bounds**: Enforces `min_size_bytes` (`1024` bytes) and `max_size_bytes` (`128 MiB`) post-download inside `verify_artifact_file_for_arch` before promoting the binary.
3. **ELF Magic & Architecture Check**: `verify_artifact_file_for_arch` validates the `\x7fELF` magic header and decodes the 16-bit ELF `e_machine` header field according to the ELF data-encoding byte against the target architecture before verifying the full SHA-256 digest.
4. **Port, Bind Address & Readiness**:
   - Uses `req.app_port` when in `1024..=65535`, defaulting to `34400`.
   - Runs as dedicated `threadfin` system user with `HOME=/var/lib/threadfin` and `ExecStart` flags `-port={{APP_PORT}} -bind={{BIND_ADDRESS}} -config=/var/lib/threadfin/conf`.
   - Seeds only a missing or empty `bindIpAddress` in `settings.json` to the effective bind address (`AF_BIND_ADDRESS`, defaulting to `127.0.0.1`), because Threadfin 1.2.37 overwrites its CLI bind flag during host-IP discovery. Existing nonempty bindings are preserved; malformed settings fail closed.
   - A newly seeded settings object includes schema version `0.5.0`, required by Threadfin's migration checks. Existing nonempty settings must provide a version string.
   - Reloads systemd, enables and explicitly restarts `threadfin.service`, and verifies HTTP readiness via `WaitForHttpReady { path: "/status" }`.
   - Preserves `/var/lib/threadfin` on remove unless `DELETE_DATA=true`.

## Removal Failure Semantics & Verification

APT maintainer scripts are not reversible file transactions. On a failed or cancelled removal, the declarative lifecycle runner **retains** the installed completion marker (`/install/.<pkg>.lock`) and logs `[WARN] Removal incomplete; installed marker retained. Retry removal to reconcile package state.`, rather than falsely claiming removal completed or that an already-removed package was restored. Operators can retry removal or reinstall to reconcile state.

Fail2ban and Quassel default to APT `remove`, not `purge`, and require `DELETE_DATA=true` for configuration/data deletion.

Source-level verification (bounded unit tests and Clippy):

```bash
cargo test --manifest-path backend-rs/Cargo.toml -p af-runner --locked
cargo clippy --manifest-path backend-rs/Cargo.toml -p af-runner --all-targets --locked -- -D warnings
```

Live Debian guest results are tracked separately in [v4-native-package-testing.md](./v4-native-package-testing.md).
