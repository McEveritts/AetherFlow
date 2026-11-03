# Self-update lifecycle

The privileged runner starts updates in the independent
`aetherflow-self-update.service`. Native execution uses the running release's
physical `af` binary with `release deploy --local`; it must not dispatch back
through the runner socket. Bash compatibility updates use the same isolated
systemd launcher. A process thread or task inside the runner cannot survive
restarting that runner, regardless of `KillMode=process`.

Launch requests are validated, serialized, acknowledged only after systemd
accepts execution, and assigned an operation ID. Active jobs reject duplicate
requests. The root-only native recovery journal and the updater unit provide
restart-surviving status through authenticated `/system/update/status`. A
root-owned `0700` runtime directory and an atomic `0600` environment handoff
keep forwarded credentials out of command arguments and public unit properties.
The handoff is removed after systemd acknowledges execution. A retained success
supersedes only the exact pre-swap journal recorded when that unit launched;
later or post-swap interrupted journals still require recovery. A
completed unit is retained until the next launch so early launch failures and
terminal outcomes remain observable. The native journal preserves the operation
ID after the transient unit is gone. Status errors are not successful updates.

The API captures its version from the physical running executable at startup,
not the mutable `current` symlink. Readiness includes that version. The release
engine verifies both systemd services' actual executable paths against the
candidate before marking deployment complete; a healthy old API is insufficient.
The settings UI independently checks fresh runtime, selected-release, operation,
and upstream-version data before claiming the latest release is running.

## First fixed release and interrupted recovery

An older installed runner still contains the faulty in-process launcher. Install
the first fixed release from a standalone root `af release deploy --local
--channel nightly` invocation or an independent root systemd service, not the old
UI updater. This is a source/release change, not authorization to deploy it.

If a previous deployment stopped after switching `current`, take an online
database backup and preserve its recovery journal. Run the existing native
`af release rollback --local --channel nightly` before a fresh standalone
deployment. The native guard intentionally blocks overwriting the previous
known-good release. Do not forge or delete recovery state to bypass that guard.

## Validation

Run Rust workspace tests and frontend TypeScript, lint, Jest, and static-export
checks. The self-update tests cover command validation, launcher failure,
duplicates, native/Bash isolation, runtime mismatch, and stale/failed UI status.

The explicit ignored Rust integration test
`self_update::tests::updater_survives_caller_restart` executes the actual launcher
argument builder against disposable services. It requires a functioning systemd
manager; set `AF_SYSTEMD_TEST_USER=1` for a user manager. CI runs it against the
system manager on its disposable Linux runner. It verifies both native and Bash
updaters survive their calling service being restarted. It never names or
restarts the production AetherFlow services.
