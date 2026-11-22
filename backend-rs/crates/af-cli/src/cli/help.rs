use super::HelpTopic;

/// Renders structured human help text for the requested [`HelpTopic`].
pub fn render_help_text(topic: HelpTopic) -> String {
    match topic {
        HelpTopic::General => "\
AetherFlow Unified Rust Administrative CLI (`af` v4.0.0)
Pure bare-metal systemd + Apache2 control plane (Zero Docker).

USAGE:
  af [GLOBAL_OPTIONS] <COMMAND> [ARGS...]

GLOBAL OPTIONS:
  --json                Emit machine-readable JSON response envelope
  --socket <path>       Override runner Unix socket (default: /run/aetherflow/runner.sock)
  --root <dir>          Override filesystem root for isolated inspection/testing
  --dry-run, -n         Validate & plan without mutating live services or disk state
  -h, --help            Print help (or 'af help <topic>')
  -V, --version         Print version information

LEGACY COMPATIBILITY SHORTHANDS (`packages/system/af`):
  af install <pkg1> [pkg2...] [--port <port>]
  af reinstall <pkg1> [pkg2...] [--port <port>]
  af remove <pkg1> [pkg2...] [--purge]
  af list [--installed]
  af update [pkg] [--target-version <ver>] [--channel <stable|nightly>]
  af upgrade [--channel <stable|nightly>]

ADMINISTRATIVE DOMAINS:
  package     Runner-mediated package install/reinstall/remove/update/list/info (/v1/package)
  service     Runner-mediated systemd service control (/v1/systemctl)
  quota       Runner-mediated user disk quota enforcement (/v1/quota)
  sandbox     Runner-mediated systemd unit drop-in hardening (/v1/sandbox)
  release     Atomic release status, deploy, rollback, cleanup & systemd migration (af-release)
  backup      Host backup bundle create/list/verify & non-destructive restore-preflight (af-host)
  provision   Resumable bare-metal provisioning foundation & safe config overlay (STATE_VERSION=2)
  maintenance Host maintenance utilities: tune, sentinel, clean-logs, showspace (af-host)
  hosts       Runner-mediated /etc/hosts and local DNS reconciliation (/v1/hosts)
  health      Verify connectivity to the privileged runner Unix socket (/v1/health)

NOTE ON UNSUPPORTED INTERACTIVE / DESTRUCTIVE FLOWS:
  - Calling 'af' with no arguments returns an explicit unsupported error (the interactive
    whiptail TUI remains in the legacy shell wrapper).
  - 'af backup restore' fails closed by design; use 'af backup restore-preflight' for
    non-destructive verification before offline maintenance window replacement.
"
        .to_string(),
        HelpTopic::Package => "\
USAGE:
  af package install <pkg1> [pkg2...] [--port <port>]
  af package reinstall <pkg1> [pkg2...] [--port <port>]
  af package remove <pkg1> [pkg2...] [--purge]
  af package update [pkg] [--target-version <ver>] [--channel <stable|nightly>]
  af package upgrade [--channel <stable|nightly>]
  af package list [--installed]
  af package info <pkg>

Mediates privileged package lifecycle operations over /run/aetherflow/runner.sock (/v1/package)
using af-runner's declarative installer primitives and script allowlist.
"
        .to_string(),
        HelpTopic::Update => "\
USAGE:
  af update <package> [--target-version <ver>]
  af package update <package> [--target-version <ver>]
  af update [--channel <stable|nightly>]
  af release deploy [--channel <stable|nightly>] [--local] [--offline]

Updates an installed application package over /run/aetherflow/runner.sock (/v1/package).
When --target-version is omitted, af resolves the target version from local state/DB or probes
/v1/package/probe-version before invoking CoordinatedOperation admission.
When no package argument is passed, triggers control-plane self-update (/v1/self-update);
see 'af help release' for atomic release deployment, rollback, and cleanup options.
"
        .to_string(),
        HelpTopic::Service => "\
USAGE:
  af service <start|stop|restart|reload|enable|disable|status> <service_name>

Dispatches validated SystemctlRequest payloads to /run/aetherflow/runner.sock (/v1/systemctl).
"
        .to_string(),
        HelpTopic::Quota => "\
USAGE:
  af quota set <username> <size>
  af quota check-size <size>

Dispatches validated QuotaRunnerRequest payloads to /run/aetherflow/runner.sock (/v1/quota)
and reuses af-runner's 1K block quota parser without duplicating setquota logic.
"
        .to_string(),
        HelpTopic::Sandbox => "\
USAGE:
  af sandbox apply <package>
  af sandbox render <package> [--user <username>]

Applies or previews systemd security drop-ins via af-runner (/v1/sandbox & render_systemd_sandbox_dropin).
"
        .to_string(),
        HelpTopic::Release => "\
USAGE:
  af release status [--config <path>]
  af release deploy [--channel <stable|nightly>] [--local | --via-runner] [--offline] [--from-source] [--keep-releases <n>] [--config <path>]
  af release rollback [--channel <stable|nightly>] [--local | --via-runner] [--config <path>]
  af release cleanup [--keep-releases <n>] [--config <path>]
  af release migrate-systemd [--config <path>]

Deploy and rollback use the runner by default. Local execution uses the Rust release engine.
"
        .to_string(),
        HelpTopic::Backup => "\
USAGE:
  af backup create [--archive | --sqlite-only] [--backup-dir <dir>] [--db-path <file>] [--app-version <ver>] [--chunk-size <size>] [--operator-privileged]
  af backup list [--backup-dir <dir>]
  af backup verify <filename> [--backup-dir <dir>]
  af backup restore-preflight <filename> --target-root <staging_dir> [--backup-dir <dir>] [--host-version <ver>] [--allow-staging-overwrite]
  af backup restore <filename> --target-root <dir> --confirm-destructive-restore [--backup-dir <dir>] [--allow-overwrite] [--operator-privileged]
  af backup recover-interrupted [--target-root <dir>] [--backup-dir <dir>] [--operator-privileged]
  af backup delete <filename> [--backup-dir <dir>] [--operator-privileged]
  af backup prune [--backup-dir <dir>] [--max-retained <n>] [--retention-days <days>] [--operator-privileged]
  af backup chunk <filename> <size> [--backup-dir <dir>] [--operator-privileged]
  af backup assemble --output <filename> --sha256 <hex> <chunk1> [chunk2...] [--backup-dir <dir>] [--operator-privileged]
  af backup ownership

Run restore-preflight against the selected target before authorizing a restore.
"
        .to_string(),
        HelpTopic::Provision => "\
USAGE:
  af provision preflight [--os-release <path>] [--require-root]
  af provision status
  af provision list-steps
  af provision run [<step1> ...] [--fresh | --resume] [--no-root-check]
  af provision repair <step1> [step2...] [--no-root-check]
  af provision overlay-config <source> <target> [--force]
  af provision reset --confirm

Implements persisted resumable step state (/install/.aetherflow.state # STATE_VERSION=2),
preflight verification, explicit repair semantics, and SHA-256 sidecar config overlays.
Retains setup/AetherFlow-Setup for interactive shell bootstrap.
"
        .to_string(),
        HelpTopic::Maintenance => "\
USAGE:
  af maintenance tune [--root <path>] [--dry-run]
  af maintenance sentinel [--log-path <path>] [--threshold <n>]
  af maintenance clean-logs [--root <path>] [--max-size <bytes>] [--dry-run]
  af maintenance showspace [--root <path>] [--user <user>]
  af maintenance ownership

SHORTHANDS:
  af tune [--root <path>] [--dry-run]
  af sentinel [--log-path <path>] [--threshold <n>]
  af clean-logs [--root <path>] [--max-size <bytes>] [--dry-run]
  af showspace [--root <path>] [--user <user>]

Pure-Rust replacements for legacy packages/system/* utilities:
  tune:      writes /etc/sysctl.d/99-aetherflow-tune.conf with optimized network buffers
  sentinel:  scans /var/log/auth.log for failed login attempts and identifies offending IPs
  clean-logs: safely truncates oversized .log files under /var/log or /srv/aetherflow/lock
  showspace: calculates disk usage for /home/<user> entries with human-readable formatting
"
        .to_string(),
        HelpTopic::Hosts => "\
USAGE:
  af hosts <update|remove|reconcile> [ip] [domains...]

Manage local /etc/hosts, dnsmasq, and Pi-hole DNS mappings.
  update <ip> <domains...>      Map domains to IP in managed block
  remove <domains...>           Remove domains from hosts
  reconcile [ip] [domains...]   Reconcile /etc/hosts to authoritative domain set (defaults to 127.0.0.1)
"
        .to_string(),
    }
}
