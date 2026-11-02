# Marketplace and Services pipeline repairs - November 2, 2026

## Scope and delivery

This repair set follows the Maintainerr lifecycle baseline and the verified 75-app catalog audit. It repairs Marketplace installation, update, removal, version reporting, ingress, Services controls, health aggregation, and log selection. Gemini 4 Argon High and Gemini 3.8 Flash High contributed implementation and independent logic, security, and contract reviews.

Changes are source-level repairs, not a deployment or live certification of every catalog application. No live package was installed/removed, production service restarted, or application database migrated during validation.

## Audit disposition

| Finding | Repair / supported behavior |
| --- | --- |
| P01 | Repair helper, logging, user, and lock contracts in install/remove scripts for Dispatcharr, Duplicati, FileBot, Listenarr, Notifiarr, noVNC, pyLoad, Quassel, Requestrr, Seedcross, Unmanic, and X2Go. |
| P02 | Preserve Dispatcharr, Duplicati, and noVNC config/data on ordinary removal; destructive purge requires `DELETE_DATA=true`. |
| P03 | Preserve Cloudplow live configuration across staged runtime updates. |
| P04 | Stage and verify updates with runtime/unit rollback for Cloudplow, Overseerr, Tautulli, FlareSolverr, SABnzbd, Calibre-Web, Home Assistant, and Paperless-ngx. Build Python environments at their canonical path so moved console-script shebangs remain valid. |
| P05 | Reject an unsupported fresh Calibre-Web custom port before changing the installation; fresh setup uses port 8083 unless a matching configured app.db already exists. |
| P06 | Explicit pip upgrades for Home Assistant, pyLoad, and Unmanic. |
| P07 | Retain Paperless configuration/secrets and back up SQLite before activation; restore prior runtime/config/units on failure. |
| P08 | Retain Vaultwarden environment, admin policy, and signup settings. |
| P09 | Retain KasmVNC, McVNC, and LibreSpeed credentials and tuning; repair config patching and shell interpolation. |
| P10 | Align noVNC installation and version automation with the distribution APT channel. |
| P11 | Require a supported Node runtime for n8n; honor explicit targets without a silent obsolete fallback. |
| S01 | Normalize nested Rust and legacy Go update-check responses. |
| S02 | Expose update-check failures without falsely offering stale updates; retain last-known versions/availability to avoid duplicate recovery notifications. |
| S03 | Prevent unreachable remote direct links to loopback-only services while retaining domain gateway access. |
| S04 | Own Apache listeners per package for Nextcloud, ruTorrent, and Organizr; preserve shared listeners and block shared-vhost daemon controls. |
| S05 | Expose component health and per-unit logs; distinguish required/timer, optional, and oneshot policies. |
| S06 | Respect direct HTTP schemes and serialize explicit TLS false in service and Marketplace contracts. |
| S07 | Fail lifecycle jobs when required post-script persistence or restoration fails; do not report false completion. |
| S08 | Honor journal unit selection and avoid mislabeling unrelated file logs as the requested unit. |
| S09 | Refresh update metadata after successful lifecycle work; derive installed state from the physical lock rather than a transient job status. |
| S10 | Reject unsupported native listen-port changes before persistence with HTTP 409 / PORT_RECONFIGURATION_UNSUPPORTED. This is not automatic native app rebinding. |
| S11 | Preserve omitted ingress fields, explicit TLS false, and runtime port fallback; fail closed on database errors and avoid rewriting native configs during domain-only updates. |
| S12 | Apply component policies consistently to controls, update pre-stop/restoration, health, and recovery. |

The security review additionally caught unsafe Notifiarr sed credential interpolation. Replacement uses literal JSON-compatible TOML quoting and a callable regex replacement; regression coverage includes delimiter, ampersand, backslash, quote, and newline characters.

## Validation

Validation runs in an isolated Linux source tree, not the live installation. Tooling: Rust/Cargo 1.99.1, Go 1.25, and an isolated SHA256-verified Node 24.22.2 runtime. No Node/npm processes run on the Windows workstation.

- 152 Bash syntax checks and 26 embedded Python syntax checks passed.
- 45 mocked-host Marketplace package tests passed, including preparation failures, runtime rollback, config retention, upgrade, listener ownership, and credential handling.
- Rust: af-api 269 passed / 2 ignored; af-services 34 passed; af-models 3 passed (306 passed total).
- Go: `go test ./services ./api` passed.
- Frontend: 43 Jest suites passed / 1 skipped; 401 tests passed / 5 skipped.
- Production TypeScript passed using an isolated validation config excluding tests.
- ESLint on touched production frontend files: zero errors, three existing warnings.
- Full-project TypeScript remains blocked by four pre-existing StreamingTab.test.tsx getByRole option errors; those unrelated tests were not changed.

Representative commands, from the relevant package directory:

```sh
python3 -m unittest discover -s tests -p 'test_marketplace*.py' -v
cargo test -p af-models -p af-services -p af-api
go test ./services ./api
node ../node_modules/jest/bin/jest.js --config jest.config.mjs --runInBand --forceExit
```

## Operational limits and rollout

- Review and deploy through the normal release process; this patch does not restart or deploy services.
- Take application/database backups before updates. Runtime rollback does not guarantee reversal of upstream database migrations. Paperless SQLite backups are retained for backup-aware recovery.
- Live fresh-install/update/remove certification for all 75 apps remains operational follow-up. External credentials, upstream builds, GPU/display hardware, and production network/certificate issuance were not exercised by mocked-host tests.
- Fresh Calibre-Web custom-port bootstrap and automatic native port rebinding remain intentionally unsupported and fail safely.
- Experimental Piped/Invidious and unrelated native Rust recipes outside the audited 75-app baseline are not included.
- The authoritative checkout is on hetzner-t3 at /home/betheenvy/AetherFlow. Preserve its unrelated untracked frontend/AGENTS.md and do not overwrite the dirty Windows experimental checkout.
