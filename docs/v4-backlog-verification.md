# v4 backlog verification ledger

This ledger tracks the 15-item backlog requested on November 3, 2026. A code
change, a scaffold, or a passing mock-only test does not establish production
readiness. Each item remains unverified until the stated evidence is recorded.
Existing working-tree changes must be preserved. Production deployment, stable
promotion, and destructive live-host testing are not implied by this ledger.

## Nightly publication checkpoint: November 4, 2026

This development-track integration preserves the newer published nightly base
`32f324e1dbb2a515e755fb5e10e49161d0f0a0e9` and incorporates the bounded v4
repairs. The active release channels are stable and nightly; legacy experimental
input migrates to nightly. Historical releases and tags remain unchanged.
The records below this checkpoint describe earlier snapshots, not certification
of this merged tree.

The integration fixes the competing migration-20 assignments by applying the
streaming migration as 20 and the plugin registry as 21, with a coexistence
regression. Plugin fixtures that replace process-global authentication state
run their real assertions in isolated child processes. Embedded acceptance
captures the real settings response at initial dashboard hydration rather than
requiring a redundant request when the cached settings tab opens.

| Merged-source gate | Result and limitation |
| --- | --- |
| Locked Rust workspace tests | 636 passed; three pre-existing manual/isolated-systemd tests ignored. The workspace uses `--test-threads=1` for global fixtures; explicit concurrency tests still exercise concurrent operations. |
| Actual non-root restore tests | All 47 `af-host` tests pass under verified UID/GID 65534, in addition to the root workspace run. |
| Clippy | Full workspace/all-targets completes with existing warnings visible. The restore/release subset (`af-models`, `af-host`, `af-release`, `af-cli`) also passes `--all-targets -- -D warnings`. No warning-free workspace claim. |
| Dependency and secret policy | Gitleaks and cargo-deny pass. The cargo-audit policy gate passes with the existing documented `RUSTSEC-2023-0071` exception; raw audit is not advisory-free. |
| Frontend | TypeScript, static export, 49 Jest suites / 491 tests pass; one suite / five tests remain skipped. ESLint reports zero errors and 48 existing warnings. |
| Python compatibility | Full non-YouTube discovery ran 306 tests. After integration fixture repairs, the affected bootstrap and marketplace subsets pass all 22 tests. One untouched upstream McVNC unit-text assertion remains failing: it expects a literal bind address while the unit uses the environment-file variable. The entire Python suite is not claimed clean. |
| Embedded runtime | The real debug Rust API binary passes all 387 live HTTP checks and one Chromium acceptance test covering authenticated navigation, persisted telemetry, plugin runtime/security, reload, and reconnect. This is not a portable release artifact. |

Evidence is under
`/var/tmp/aetherflow-v4-validation-20261103-052723/logs/nightly-integrated-gates`.
Source digests are checked against the isolated integration manifest; the original
Windows working tree, index, HEAD, and deferred YouTube/Piped/Invidious work are
preserved. No YouTube-specific tests or application edits are included.

Publication to nightly is not stable promotion, production deployment, blanket
security signoff, or fresh Debian/Ubuntu multi-OS certification. Those operational
claims remain outside this development-track publication. No production services,
databases, or configuration are modified by these validation runs.

## Earlier acceptance and evidence (November 3)

| # | Requirement | Evidence needed | Current evidence |
| --- | --- | --- | --- |
| 1 | Fresh installations use verified prebuilt v4 Rust releases. | Bootstrap consumes a release-layout artifact; tampered artifacts fail closed; normal installation does not compile the Go backend. | Real clean Debian 12/13 and Ubuntu 22.04/24.04 guests pass provisional prebuilt bootstrap, tampered-digest rejection, real systemd activation and ready health. Final merged artifact certification remains open. |
| 2 | Rust security checks gate the shipping branches. | Workflow covers `experimental`; Rust advisory and static checks fail on actionable findings instead of silently succeeding. | Provisional locked Rust tests, strict workspace Clippy, Gitleaks and cargo-deny pass. Raw cargo-audit reports the documented public-key-only RSA advisory; policy audit passes with that explicit exception. Final merged-source security rerun remains required; no zero-advisory claim. |
| 3 | Release dependency resolution is locked. | Generated workspace `Cargo.lock`; test/build/package commands pass with `--locked`; no unlocked fallback. | Generated lock, locked metadata, workspace tests, and both binary builds verified locally. Changes remain uncommitted as requested. |
| 4 | Browser tests exercise the embedded Rust server. | Built binary serves frontend and authenticated API for login, settings, marketplace, and connection-recovery tests. | Independently passed 68 frontend tests, 387 live API checks and one real Chromium acceptance test on provisional product snapshot 150700. Parent decoded and checked the Playwright report, with no retries, skips or flaky results. Final merged-binary rerun remains required. |
| 5 | Clean-host installation and rollback are tested. | Supported Debian/Ubuntu installation and failed/interrupted-update drills report OS, artifact identity, health, and recovery outcomes. Mock filesystem drills do not prove the OS matrix. | All four mandatory lifecycle phases pass on clean Debian 12/13 and Ubuntu 22.04/24.04 guests using identical provisional archive and source bundle: 16 mandatory passes, plus four separately labeled auxiliary fixtures. Parent independently verifies OS versions, command exits, every source-file digest and teardown. The older frozen host engine is retained; final merged-source four-OS certification remains open. |
| 6 | Native self-update is integrated and safely graduated. | Runner uses `af-release`; artifact verification, service lifecycle, failure recovery, and experimental-channel preservation are tested. | Six bounded native Debian 13 phases pass 29/29 assertions; a separate forced-shell guest passes 12/12 assertions. Both use the real runner and an explicitly labeled API lifecycle sleeper, not a live application writer. Release/runner pass 53 Rust tests and strict Clippy; 28 mocked-systemd shell tests pass. Successful remote deploy, live-writer acceptance, final merged source, and portable artifact certification remain open. |
| 7 | Release artifacts install the native `af` CLI. | Built CLI appears in archive and installed command path; status, package, service, backup, and release smoke checks pass. | The provisional portable artifact contains identical `af` and `bin/af`, both GLIBC 2.34 compatible. Real clean-guest bootstrap verifies installed CLI version, health and release status; earlier native-package and backup drills cover their respective CLI routes. Final merged-artifact comprehensive CLI acceptance remains open. |
| 8 | API and scheduled backups share the native engine. | Runner boundary, API, and scheduler produce verified WAL-safe snapshots/host backups without divergent legacy execution. | Real Debian guest runner/CLI roundtrips and WAL snapshot recovery pass. Final API/scheduler and artifact certification remain open. |
| 9 | Restore is a real, safe, tested workflow. | Real data recovers; preflight, integrity, path/permission checks, quiescence, atomic replacement, and failure rollback pass isolated drills. | The completed host repair is integrated; independent merged checks pass 173 workspace tests, strict all-target Clippy, and 35 actual non-root host tests. Live Debian 13 packaged-runner backup now exposes a shared-lock parent-ownership mismatch, and privileged guest acceptance still has failures. The bounded independent review and runtime closure remain open. Not certified. |
| 10 | Native package execution expands beyond its first package. | `fail2ban`, `quassel`, and `threadfin` have correct dependencies/config/units, bounded progress, cancellation, serialization, and recovery tests. | All 47 assertions across five real Debian 13 amd64 guest phases pass on derived candidate `package-fixes-7dfac856f608`; 33 runner tests and strict runner Clippy pass. Final merged-source and other-OS certification remain open. |
| 11 | Overview charts hydrate persisted history. | Refresh/reconnect, timestamp windows, bounded merge/deduplication, and missing-data handling pass tests against the existing history contract. | Independently passed real Chromium acceptance for persisted history, window queries, reload, and WebSocket reconnect on provisional product snapshot `150700`; 68 frontend tests also pass. This snapshot deliberately retains the older frozen host engine. Final merged-source acceptance remains open. |
| 12 | Experimental YouTube packages are validated. | Deferred by explicit user request on November 3, 2026; excluded from current completion gates until resumed. | Leave Piped/Invidious and existing YouTube WIP untouched. No further edits, installs, playback tests, or certification; no readiness claim. |
| 13 | Plugins work end to end with enforced capabilities. | Discovery, lifecycle, health/ports, proxy, mounted UI, scoped tokens work; escalation, token confusion, traversal, and proxy-boundary checks fail closed. | Independently passed real Chromium acceptance against the managed telemetry-inspector runtime: start/stop, allocated port, proxy, UI sandbox headers, scoped token allow/deny, and stopped-runtime boundaries. Locked workspace tests pass on provisional product snapshot `150700`. Independent security review and final merged verification remain open. |
| 14 | Shared assets no longer require the legacy Go layout. | Rust embedding, release, setup, and catalog loading use neutral paths; Go is not deleted before parity. | Canonical OpenAPI now joins root config/web assets; the old Go copy remains byte-identical. All-target Rust API checking and 36 API tests pass with the legacy backend directory withheld in an isolated source stage; 16 Linux packaging/CI contracts pass. Final merged artifact and clean-host runtime verification remain open. |
| 15 | Deployment documentation matches v4. | Instructions match Rust binaries, configuration, SQLite revocation, installed CLI, privilege boundaries, and unverified operations. | Runbooks and this ledger record current evidence and limits. Final requirement-by-requirement reconciliation remains open; no production-readiness claim. |

## Verification environment

- Local workspace: Windows; local `node`, `npm`, and `npx` are prohibited.
- Inspected Linux host: Debian 13, x86_64, on November 3, 2026.
- Tests use isolated `/var/tmp/aetherflow-v4-*` directories. The host's `/tmp`
  was almost full; unrelated files must not be deleted.
- Live services and `/opt/AetherFlow` are outside the test workspace.
- Builder: Gemini 4 Argon, high thinking.
- Independent auditors: Gemini 3.8 Flash, high thinking, and GPT Terra, max.

## Recording rules

Record command, source fingerprint, environment, result, and limitations. Keep
unit, mocked integration, real-process integration, clean-OS, and production
evidence distinct. A failed test or missing external dependency leaves an open
requirement; it must not weaken the acceptance test.

## Baseline runs

The first isolated source snapshot contains 1,498 files and has SHA-256 manifest
fingerprint `ec1756e66448b4ef1b529643741fcbbdf0a8536962bb430f7f7d19bbf53013f0`.
It predates the builders' new changes; its results are not final sign-off.

| Command or check | Result | Scope and limitation |
| --- | --- | --- |
| `python3 -m unittest discover -s tests -p 'test_*.py' -v` | 49 tests; two failures and one error. | Jellyseerr fixture fails to resolve `common.sh`, and one assertion reads a command log never created; Invidious fixture cannot import `yaml` in that run. Builders received the exact traces. |
| `npm ci --no-fund --no-audit` | Installed 946 packages. | Host Node 22.12.0 is below several declared dependency engine requirements. This is not a security audit. |
| `npm run test:ci --workspace frontend` | Failed before test discovery. | `frontend/jest.config.ts` requires undeclared `ts-node`; a real project configuration fix is required. |
| Isolated Linux Node runtime | v24.22.2; archive SHA-256 matches official manifest. | Installed only inside the validation workspace, not on the host's global PATH. |
| Isolated QEMU tools | QEMU and qemu-img 10.0.13 execute; `/dev/kvm` is available. | Debian packages and missing libraries were extracted into the validation workspace; no host package installation and no clean-OS drill yet. |
| `NEXT_STATIC_EXPORT=1 npm run build --workspace frontend` with isolated Node 24 | Passed, including TypeScript and all eight static pages. | Baseline snapshot only; not the builders' final UI or browser integration tests. |
| `cargo generate-lockfile` followed by `cargo test --workspace --locked` | Passed on isolated Debian 13 using Rust 1.99.1. | Baseline generated lock is preserved; final dependency changes require regeneration and retesting. No live service or API daemon was started. |

## Integration snapshot: November 3, 2026, 05:50:20

Source manifest fingerprint:
`7a2b524d1dc917905451cbde051676b836842576a99e4a6278b550d4f2c4dc18`
(1,503 files). Logs are under
`/var/tmp/aetherflow-v4-validation-20261103-052723/logs/integration-055020`.
This is an immutable intermediate snapshot, not the final builders' source.

| Command | Result | Limitation |
| --- | --- | --- |
| `cargo generate-lockfile` | Passed. | Lock belongs to this snapshot; regenerate after dependency edits. |
| `cargo test --workspace --locked` | Compilation failed: `af-host/src/restore.rs` moves `artifact_path` into one closure and borrows it in another (`E0382`). | Builder received the exact trace; no tests ran. |
| `python3 -m unittest discover -s tests -p 'test_*.py' -v` | 51 tests; two YouTube diagnostic subtest failures. | Both expected `local_ready_playback_untested` but observed `service_down`; all other tests in this snapshot passed. |
| `npm ci --no-fund --no-audit` | Passed using isolated Node 24.22.2. | No Windows-local Node workloads. |
| `npm run test:ci --workspace frontend` | 18 suites, 62 tests passed. | Unit tests only; not authenticated embedded-browser evidence. |
| `NEXT_STATIC_EXPORT=1 npm run build --workspace frontend` | Passed TypeScript checks and generated all eight static pages. | Not the later plugin implementation or a final release artifact. |

## Independent initial audit and clean-OS evidence

Flash High and Terra Max completed initial audits, not final sign-off. Critical
open findings include caller-controlled privileged backup deletion, restore
quiescence/recovery/ownership/path-race handling, release extraction and
channel fail-closed behavior, divergent dispatch/locks, plugin token boundaries,
and source integration errors. Findings describe inspected source paths; they
do not establish exploitation of a deployed binary. Builders received their
findings. Final independent audits must use the converged source.

The VM builder reports real checksum-verified image boots, pinned SSH,
cloud-init, and systemd readiness for Debian 12, Debian 13, Ubuntu 22.04, and
Ubuntu 24.04. Evidence:
`/var/tmp/aetherflow-v4-vm-matrix/evidence/boot-matrix-1793703307.json`.
Guest boot success does not certify application installation, update, rollback,
or interrupted-update recovery. Final artifact certification remains open.

## Integration snapshot: November 3, 2026, 06:10:49

Source manifest fingerprint:
`3a643c480e66778a478f0a243f49e098d63fe75959f5126076d8df1d3a8d4c95`
(1,509 files). Logs are under
`/var/tmp/aetherflow-v4-validation-20261103-052723/logs/integration-20261103-061049`.
This snapshot also predates the final builders' changes.

| Command | Result | Limitation |
| --- | --- | --- |
| `python3 -m unittest discover -s tests -p 'test_*.py' -v` | 75 tests passed, including YouTube diagnostic status, release symlink rejection, and prebuilt fail-closed regressions. | Shell lifecycle/install tests use fixtures or mocked tools; not real package playback or final-artifact OS certification. |
| `npm ci --no-fund --no-audit` and `npm run test:ci --workspace frontend` | Installation passed; 19 suites, 63 tests passed. | Unit tests, not embedded authentication/API acceptance. |
| `NEXT_STATIC_EXPORT=1 npm run build --workspace frontend` | TypeScript and eight-page static export passed. | Generated assets belong to this snapshot. |
| `npm run lint --workspace frontend` | Passed with 59 warnings and no errors. | Warnings remain; this is not a warning-clean frontend claim. |
| `cargo generate-lockfile` | Passed. | Final workspace lock still requires import after dependency convergence. |
| `cargo test --workspace --locked` | Fails to compile `af-runner`: 21 integration errors. | Includes mismatched release/backup model types, validation results, and checksum fields; builder received the exact trace. |
| `cargo test -p af-host -p af-release -p af-db --locked` | 34 tests passed: host 17, release 15, database 2. | Isolated temporary files and mocked lifecycle control; does not establish real UDS authorization, live service quiescence, held-open WAL recovery, or process interruption safety. |

The coordinator read the four-guest boot JSON directly and confirmed each
target reports `boot_verified` and `systemd_state: running`. Observed GLIBC
versions are Debian 12: 2.36, Debian 13: 2.41, Ubuntu 22.04: 2.35, and Ubuntu
24.04: 2.39. A portable release must target the lowest supported baseline;
compiling a dynamic binary on the Debian 13 validation host is not sufficient.

## Locked security integration: November 3, 2026, 06:34:32

Source manifest fingerprint:
`7370b50ca993af7eeb2a2771f2c05303ea3fcb43c071e52abf11cea018f234bf`
(1,514 files; existing `.dependabot-audit` investigation outputs excluded).
Immutable source and logs are under
`/var/tmp/aetherflow-v4-validation-20261103-052723/source-20261103-063432`
and the corresponding `logs/integration-20261103-063432` directory.

| Command | Result | Limitation |
| --- | --- | --- |
| `cargo metadata --locked --no-deps --format-version 1` | Passed with the imported generated workspace lock and exact local workspace versions. | Resolves dependency contracts; does not compile or test the application. |
| `cargo deny --locked check advisories bans sources` | Passed with cargo-deny 0.20.2: advisories, bans, and sources all OK. | Multiple-version warnings remain; the narrow documented verification-only `RUSTSEC-2023-0071` RSA exception remains. License checks are not included in this invocation. |
| `cargo audit --file Cargo.lock --ignore RUSTSEC-2023-0071` | Passed on the preceding 06:28:43 snapshot with the same lock contents, using cargo-audit 0.22.2 (334 dependencies, 1,403 advisories). | Does not establish runtime security; the documented advisory exception is explicit, not blanket suppression. |
| `python3 -W error -m unittest discover -s tests -p 'test_*.py' -v` | 89 tests passed. | Includes fixtures and mocked shell tools; not real application lifecycle, playback, privileged-socket, or browser acceptance. |

The lock file SHA-256 is
`4b37ebe6423397585e54ae4a343a58b2326d55008e406c0b6ab8a29230bd5ce0`.
The cargo-deny policy now uses valid advisory scope selectors and the workspace
path dependencies carry exact versions rather than implicit wildcard versions.
Full workspace compilation, warning-clean clippy, authenticated embedded E2E,
real restore/authorization tests, and final-artifact clean-OS certification
remain required. No final independent audit or production deployment is claimed.

## Converged workspace tests: November 3, 2026, 06:50:23

Source manifest fingerprint:
`630f10d44f7ccb2515c07543deb1997799dc97ccca5af25ea21f9a5572ea4a9a`
(1,518 files). Source is
`/var/tmp/aetherflow-v4-validation-20261103-052723/source-20261103-065023`;
logs are under `logs/integration-20261103-065023` in that validation root.

| Command | Result | Limitation |
| --- | --- | --- |
| `cargo test --workspace --locked` | All 133 tests passed after rebuilding the nine local workspace crates. | Temporary-file, mock-controller, and handler tests; not clean-host install, systemd lifecycle, playback, or authenticated browser certification. |
| `cargo clippy --workspace --all-targets --locked -- --cap-lints warn` | Diagnostic collection completed and identified remaining lint findings. | Diagnostic only: this is explicitly **not** the required `-D warnings` release gate. That gate remains open. |
| `python -W error -m unittest discover -s tests -p test_v4_privileged_guest_drills.py -v` | Ten validation-helper tests passed locally. | Does not execute the privileged guest drills; their six real-binary phases remain pending. |

The coordinator corrected the shared-lock acquisition order (maintenance before
release), removed nested runner/shell acquisition and contention fallback to a
different lockfile, added local CLI backup serialization, and mapped all restore
failure variants to nonzero CLI errors. A new real-POSIX-lock shell regression
passed with the preceding 90-test Python suite. The guest drill harness now
exists but is not runtime-certified.

Preserved archive mtimes plus a shared Cargo target initially caused stale
local-crate outputs to hide the actual model definitions. Rebuilding only the
local workspace packages eliminated the phantom missing-model errors. Future
source-snapshot runs must rebuild those packages (or use a fresh target) before
their results can be accepted. Third-party dependency caches can be retained.

## Integration evidence: November 3, 2026, 07:12:56

Source manifest fingerprint:
`1e863b3c300d5793ff26f0f342277cb9981cb0c18fcdfad8acb2acd0eeaf3aa7`
(1,518 files). Source is
`/var/tmp/aetherflow-v4-validation-20261103-052723/source-20261103-071256`;
logs are under `logs/browser-20261103-071256` in that validation root.

| Command | Result | Limitation |
| --- | --- | --- |
| `python3 -W error -m unittest discover -s tests -p 'test_*.py' -v` | All 100 tests passed. | Includes mocked privileged tools and harness contract tests; not real guest or application certification. |
| `python3 tests/check_shell_hygiene.py` | All 308 shell scripts passed, with no syntax failures, `apt-key`, or `NOPASSWD: ALL`. | Static hygiene only. |
| `bash scripts/smoke_v4_release_lifecycle.sh` | All isolated release lifecycle smoke phases passed, including bad checksum rejection, upgrade, failed-health rollback/SQLite recovery, and manual rollback. | Mocked system tools and isolated filesystem; not the real multi-OS lifecycle matrix. |
| `NEXT_STATIC_EXPORT=1 npm run build --workspace frontend` | Production static export and TypeScript checks passed using Node 24.22.2. | Export alone does not establish embedded-browser acceptance. |
| `cargo build --locked --bin aetherflow-api --bin af` | Both debug binaries built successfully from a fresh target directory. | Debug `rust-embed` uses runtime source assets, so this is not a portable embedded release artifact or a browser pass. |

On the preceding `source-20261103-070735` snapshot, frontend unit tests passed
all 19 suites and 63 tests. The lint command exited successfully but downgraded
two hook rules globally; removing that weakening and repairing source
diagnostics is required before accepting the lint gate.

The embedded acceptance test now requires Overview history windows,
Marketplace/plugin iframe content, Settings, real native WebSocket closure and
reconnection with backend history rehydration, and authenticated reload. It no
longer silently skips those assertions when selectors are absent. The harness
seeds twelve explicitly synthetic telemetry rows in its real isolated SQLite
database; it does not intercept HTTP or fabricate WebSocket traffic.

Early real launch attempts failed closed before browser acceptance: the
unprivileged account could not traverse the private validation binary path,
and a staged debug binary could not serve source-backed assets. Release-profile
validation with an accessible staged executable is in progress. No browser
success is inferred from those failures.

Flash's independent review of the older 06:50:23 snapshot withheld production
signoff and identified serial plugin health probes and an unindexed normalized
history query. Both findings are assigned for repair. Its references to a
"committed" lock file are inaccurate: the generated lock exists only in the
preserved working tree and snapshots. Terra's follow-up audit failed without a
review result and supplies no approval.

## Real-process acceptance and recovery: November 3, 2026

The Debian 13 disposable QEMU guest ran both real binaries from the 07:12:56
source snapshot. Machine-readable evidence is under
`logs/privileged-guest-20261103-132517` in the validation root, including
`guest-drills-report.json`, `vm-execution.json`, and the preserved guest work
archive. The VM was torn down after evidence collection. These debug-profile
binary drills test backup/runner behavior, not embedded UI portability.

| Real guest behavior | Observed result |
| --- | --- |
| Authorized runner and CLI backup creation, inventory, verification, deletion, and checksum-sidecar tamper rejection with a held-open WAL database | Passed. |
| Request-selected backup/DB roots and out-of-policy restore roots; traversal and uninventoried sentinel deletion | Rejected; root-owned sentinel bytes, ownership, modes, and inode remained unchanged. |
| Default socket permissions and kernel peer-credential enforcement with deliberately permissive socket mode | Unauthorized UID rejected; CLI returns the real expected exit codes 3 and 5. |
| Real systemd quiescence | Disposable writer unit stopped and restarted with a changed MainPID. A failed stop returns HTTP 500 before target mutation. |
| Held-open uncheckpointed WAL recovery through runner and CLI | Passed integrity/quick checks, user version 404, all committed rows, and exclusion of the uncommitted write. |
| Restored metadata | Failed: archive SQLite entry records temporary snapshot ownership/mode instead of source metadata; a restored DB becomes root-owned 0600. The legacy `.Lock` target retains a corrupt existing 0777 mode instead of its archived 0640. Both defects are assigned to the lifecycle builder. |

The six-phase suite still reports **failed**, not certified. Initial harness
assumptions about nested backup payloads, a nonexistent inner `success` flag,
CLI `errors[]` instead of `error_kind`, stderr output, and custom-directory
privilege policy were corrected against the actual Rust models and real output.
SQLite restore verification now compares the verified archive snapshot checksum
and logical rows, not the byte hash of the original pre-`VACUUM INTO` file.
These corrections do not relax ownership, permission, quiescence, or integrity
requirements. Twelve focused harness tests pass locally after the corrections.

The optimized Debian 13 release binary built successfully with `--locked` and
serves its embedded root/login pages from an unprivileged process. The live-mode
Python suite reports 387 passing cases; many are contract assertions, so this
is not represented as 387 independent runtime HTTP transactions. Real Chromium
then authenticates, checks the HttpOnly session cookie, sees live telemetry and
persisted history, and fails at the plugin UI request (HTTP 403 while the plugin
is disabled). Plugin lifecycle prerequisites and server-side sandbox headers
remain assigned to the product builder. Marketplace, Settings, and reconnect
are not claimed passed before the full mandatory test completes.

An actual embedded-harness isolation defect was also reproduced: killing its
wrapper shell left a test API daemon alive, allowing a subsequent run to read
that old daemon's health response. The harness now uses `exec setsid`, owns and
terminates its process groups, and refuses an occupied port before launch.
The reproduced orphan was terminated only after checking its exact test binary,
working directory, and isolation flags. A real occupied-listener regression
passes, and the subsequent Chromium failure leaves no listener on its test
port. Evidence is in `logs/browser-20261103-071256`, including
`occupied-listener-guard.json` and `post-browser-cleanup-listeners.txt`.

## Independent integration gates: November 3, 2026, snapshot 080109

Frozen source: `source-20261103-080109` under the isolated validation root.
The exact-byte source manifest SHA-256 is
`5e78fdcad3e6c9823f01b08e73a9161c760452b8a76393bca56d4b2417e92a74`
(1,522 files). Logs are in `logs/integration-20261103-080109`.
The nine local workspace packages were cleaned before compilation; the
third-party cache was retained. The native-package delegate's separate binary
target was not overwritten.

| Gate | Independently observed result |
| --- | --- |
| `cargo test --workspace --locked` | 135 tests passed; no ignored or failing tests. |
| `cargo build --locked --bin aetherflow-api --bin af` | Both debug binaries built successfully. These Debian 13 binaries are not the portable release artifact. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Failed on one `clippy::mut_range_bound` diagnostic in `af-api/src/plugins.rs:2172`; assigned to the active product builder. No warning suppression was added. |
| `cargo deny --locked check advisories bans sources` | Passed the repository policy. |
| `cargo audit --file Cargo.lock` | Unfiltered run failed on `RUSTSEC-2023-0071`. Repeating the exact shipping policy, `cargo audit --file Cargo.lock --ignore RUSTSEC-2023-0071`, passed. The existing verification-only RSA exception is documented in `backend-rs/deny.toml`; this is not an assertion of zero advisories. |
| `python3 -W error -m unittest discover -s tests -p 'test_*.py' -v` | 103 tests passed on Linux. |
| `python3 tests/check_shell_hygiene.py` | All 308 shell scripts passed. |
| `bash scripts/smoke_v4_release_lifecycle.sh` | Passed isolated bootstrap/update/rollback/database smoke checks using mocked system tools, not clean-OS certification. |

The snapshot includes the lifecycle builder's SQLite source-metadata and
archived-mode fixes, mandatory writer union, external transient self-update unit,
and normalized metrics-history expression index. Passing workspace tests does
not replace a fresh privileged guest run or establish that the self-update job
survives an actual runner restart. Those runtime gates remain open.

## Terra lifecycle review: repairs required before certification

GPT Terra Max independently inspected the frozen `080109` snapshot without
launching tests or modifying files. The source review found nine P1 and seven
P2 issues or coverage gaps; it did not grant operational signoff. Important
remaining repair groups are:

- A durable terminal restore decision before writers restart, durable journal
  directory entries, and recorded intent before service quiescence.
- Protected recovery-journal provenance and strict validation of destination,
  rollback-copy, service, and metadata records before privileged recovery.
- Explicit trust for the packaged service-owned state directory and a shared
  maintenance lock usable in either root/service-UID acquisition order.
- Exact isolated release-root/config handoff to the external CLI, consistent
  database/backup path selection, and the configured active restore destination.
- Fail-closed missing-database backups, stable archived bytes, complete uploaded
  bundles, checked WAL/SHM cleanup, and full interrupted-recovery metadata.
- Canonical preflight/execution parity and durable update-job completion exposed
  to the UI rather than interpreting an initiation acknowledgment as success.

Two Argon repair tasks own the host engine and control-plane integration
separately. The product builder also owns the UI completion state. Previous
passing unit/smoke counts do not close these findings. Fresh independent reviews
and real-process guest tests are required after convergence.

The additional self-update lifecycle harness has 14 independently passing local
Python unit tests. It has not yet executed in a guest. In particular, its fixture
must be checked against the corrected root/config handoff before privileged
execution; no instruction to remove existing service units is authorized on a
non-disposable host.

## Real native-package findings and repair retest

### Follow-up host review remains blocking

Terra's independent review of `af-host-terra-stage-20261103-090600`
does not accept the host builder's blanket closure claim. The seven source files
were hash-compared with the local workspace and match exactly. Missing-database
failure and archive/manifest byte consistency are narrowly closed, but seven P1
and six P2 findings remain. These include service-owned journal provenance and
self-asserted destination trust, sidecar symlink reads, duplicate resolved
destinations, rollback after writer readmission, non-SQLite sidecar deletion,
cold-start lock splitting, unchecked parent-directory fsync, journal/checksum
generation skew, archive-supplied ownership trust, preflight destination drift,
lock chmod races, partial-stop compensation, and ignored non-root ownership
failures. A further host-engine repair pass is required. The 23 passing crate
tests do not close these findings and no data-integrity signoff is claimed.

The first real Debian 13 package run used source `071256` and failed closed on
five defects: Fail2ban's `/var/run` removal path, Quassel's unconditional APT
purge and certificate ordering, and Threadfin's incorrect asset name and missing
writable service `HOME`. Cancellation, duplicate-operation rejection, and
checksum-tamper rollback passed. The full run was **39/47 assertions**, not a
certification. Original evidence is preserved under
`/var/tmp/aetherflow-v4-native-package-validation/logs` on the validation host.

The parent repaired the recipe defects and added regression assertions. A new
derived source, `package-fixes-d70f72a9c47d`, is based on frozen `080109` with
only `af-runner/src/package_executor.rs` changed (SHA-256
`d70f72a9c47d958599135255f5dc6b7af90bacf7ae82d5b2ec73763d5df76a2c`).
All 30 runner tests, strict runner Clippy, and both debug binary builds pass;
12 native guest-harness unit tests also pass locally. The previously combined
Quassel dependency-install assertion was updated to require both separate
installs and certificate generation before `quassel-core` installation.

The real Debian 13 retest completed with **45/47 native assertions**: Fail2ban
12/12, Quassel 13/13, provenance 8/8, and cancellation/serialization/rollback
4/4 passed. Threadfin passed 8/10; only loopback TCP/HTTP reachability on ports
34405 and 34406 failed. Its service started successfully after the HOME fix,
but upstream 1.2.37 overwrites the command-line bind address during host-address
discovery. The supported `bindIpAddress` settings field is required. A narrow
default-setting repair and further package audit repairs are awaiting retest;
this native suite is not certified.

All **six mandatory privileged-backup phases passed** in the same disposable
guest, including held-open WAL recovery, real systemd quiescence, UID/GID/mode
restoration, and unauthorized socket/request rejection. Evidence is preserved
under `/var/tmp/aetherflow-v4-validation-20261103-052723/logs/guest-suites-20261103-144633`
on the validation host. This bounded pass uses the old frozen source plus
package repairs, not the later restore-journal/control-plane changes. It does
not close Terra's outstanding findings. The VM was torn down; production host
state remains untouched.

Flash's independent package review confirmed the original fixes and identified
partial-removal marker retention, APT post-install activation before defaults
and sandboxing, Fail2ban's unconditional purge semantics, and existing-certificate
metadata enforcement as remaining repair targets. Unit tests are not evidence
of real Debian maintainer-script or kernel-sandbox behavior.

The subsequent Debian 13 run against `package-fixes-11da1dda4706` reached
**46/47 native assertions**. Initial Threadfin TCP/HTTP on port 34405 now passes;
the sole failure is update reachability on port 34406 despite preserved fixture
bytes and a complete progress stream. The recipe reloaded the rewritten unit and
ran `enable --now`, but never restarted the already-running service. An explicit
restart and a regression checking the final update command are added for retest.
Evidence is preserved under
`/var/tmp/aetherflow-v4-validation-20261103-052723/logs/guest-suites-20261103-153445`.
No native-package certification is claimed until that retest passes.

The next native retest against `package-fixes-7dfac856f608` passed **47/47**
assertions across all five phases. Evidence and binary/report digests are in
`v4-native-package-testing.md`. This closes the bounded Debian 13 recipe failure,
not final merged-source or four-OS certification.

## Frozen control-plane review remains blocking

Terra reviewed the 24-file control overlay in `control-review-20261103-095151`
(manifest SHA-256
`c6f2990798ac7a7991c01bf2dbe8d9527fcd6cdfe53926f71a93781fafe59468`).
Its source-derived findings identify eleven P1 and two P2 gaps, including silently
discarded isolated CLI overrides, host lifecycle/bin and database fallback under
an isolated root, upload replacement/concurrency and visibility, existing-parent
chmod, divergent lock initialization/selection, shell interpretation of config
values, cross-identity database selection, mismatched job-receipt directories,
indeterminate launches/abrupt termination, receipt identity/state validation,
and CLI restore containment parity. Several behaviors predate the repairs, but
remain incompatible with the requested isolation and completion guarantees.
No runtime exploitation or production operation is claimed by this review.
Passing unit tests do not close these findings. A further focused control-plane
repair and converged integration test pass is required before signoff.

The second host-engine builder reports 27 passing crate tests and strict Clippy
in `af-host-repair-stage-20261103-101500`. All seven local Rust source hashes
match that staging snapshot. Privileged recovery now requires an explicit
`RecoveryContext`; the legacy overload fails closed. The actual code uses
`for_canonical_host` / `for_target_root` / `from_host_config`, includes both UID
and GID trust fields, and places default provenance under
`/etc/AetherFlow/.restore-provenance` or `<target_root>/.restore-provenance`.
These source contracts differ from parts of the builder narrative; caller
integration follows the verified source. Fresh independent review and real
cross-UID/crash-boundary validation remain mandatory. In particular, journal
and checksum publication still consists of separate writes, so the builder
result is not accepted as blanket durability closure.


## Convergence evidence after sequential agent handoff

The previous product task is authoritatively terminal with an interrupted result,
not a clean completion. Its claimed passes are preserved as reported evidence:
20 frontend suites / 68 tests, lint with zero errors and 48 warnings, 387 live
API checks, and one live Chromium test. Parent SHA-256 comparison confirms all
154 selected frontend, plugin-runtime, SDK, and acceptance-harness files match
`/var/tmp/aetherflow-v4-impl-20261103/source`. This proves source correspondence,
not the reported runtime outcomes or final merged-binary acceptance.

The control-plane builder reports closure of the 13 frozen review findings in
`control-repair2-20261103-162050`, including contextual host recovery callers.
The parent independently matched 20 selected control/config/test files and
`af-host/src/restore.rs` to that stage. Its package executor was older than the
47/47 guest candidate, so its whole-workspace results are not treated as final
merged-source evidence.

The next independent host review of
`af-host-repair-stage-20261103-101500` still identifies seven P1 and five P2 gaps:
provenance overlap; pathname substitution of authenticated restore sources;
partial commit publication followed by contradictory rollback; recovery stop
compensation readmitting writers; lock selection/name replacement; SQLite
sidecar races; checksum-sidecar reads; checkpoint-generation recovery; cleanup
ordering; relative preflight parity; non-root lock GID enforcement; and trusted
custom database ownership. These are assigned together to one new fixed-scope
host repair task after the prior agents became terminal. No blanket closure or
operational certification is inferred from the existing 27 host tests.

Separately, the parent found that the new isolated-systemd safety opt-in was
missing from transient-unit environment propagation. The runner now forwards an
explicit server-owned `AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE` to both native
and shell jobs, without inventing it when absent. The lifecycle harness requires
a root-owned regular `/etc/aetherflow-disposable-guest` with the exact guest token
before work-root mutation; descriptor and inode checks reject marker replacement.
The guest driver and runbook now stage both required guest markers.

All 23 focused Python lifecycle tests pass locally. A provisional frozen
control/package integration at `parent-lifecycle-handoff-20261103-133847` passes
the targeted handoff regression, all 34 runner tests, and strict all-target runner
Clippy on Linux. Its source-manifest SHA-256 is
`91249d2070429bca5780750855eb11ffab73a9d4adb1aa22520104bd8d1614a2`.
Logs are under `logs/parent-lifecycle-handoff-20261103-133847` in the validation
root. This stage deliberately retains the pre-repair host engine and is not the
final candidate. Real lifecycle guest execution, final merged review, portable
release construction, and the four-OS certification matrix remain separate gates.
YouTube/Piped/Invidious remain explicitly deferred and excluded from these gates.

## First Passing Real Lifecycle Run

`parent-rollback-integrity-20261103-140144` passes all five lifecycle phases
and **24/24 real Debian 13 guest assertions**. Evidence is preserved at
`logs/guest-suites-20261103-200302`; exact source, binary, harness, report, and
work-archive hashes are in `v4-lifecycle-testing.md`. The driver confirms its
owned QEMU PID is absent after teardown. Final host repairs are deliberately
not included in this provisional source.

The real updater remains in its own cgroup while the runner PID changes. Native
rollback restores the golden SQLite rows, integrity `ok`, mode `0600`, removes
WAL/SHM, and quarantines the corrupt database. Durable terminal success survives
runner restart/unit collection; an unpublished deploy produces terminal failure
with nonzero exit and preserves the active release.

Failed preliminary runs exposed and corrected several fixture/wire assumptions
without weakening assertions. They also exposed a genuine native rollback
false-success defect: database recovery errors were logged but returned as
successful completion. The native repair retains failed recovery state, attempts
writer quiescence, returns an error, and does not restart writers. All 19 release
tests and 34 runner tests plus strict all-target Clippy pass. The specific
post-fix malformed-snapshot failure is tested by Linux regression, not yet by a
new real guest negative drill. Shell-fallback parity, final merged acceptance,
successful remote deployment, and four-OS portable-artifact certification remain
open. This evidence is not production signoff.

## Six-Phase Native Failure Gate

The later provisional `parent-rollback-shm-20261103-143504` source passes all six
native lifecycle phases, **29/29 real Debian 13 assertions**, including the
post-fix malformed-snapshot negative scenario. Evidence is
`logs/guest-suites-20261103-203828`; exact source, binary, harness, report, and
work-archive fingerprints are in `v4-lifecycle-testing.md`. QEMU PID `2502044`
is confirmed absent after teardown.

The new negative phase first exposed SHM mutation by a read-only SQLite
integrity check. The native and shell helpers now reject invalid file headers
before opening SQLite, and the native regression checks SHM as well as DB/WAL.
The final guest verifies a failed receipt with exit 7, failed recovery state,
unchanged corrupt DB/WAL/SHM, and stopped writers; starting only the control
runner preserves that failure and does not start the API writer. This is not
a general valid-header/WAL race or host-recovery crash-boundary guarantee.

Shell rollback no longer swallows recovery, stop, or mutation failures and now
verifies the backup digest. All 28 Linux shell regressions pass, including
invalid manifests and failed service stops, but use mocked systemd. The later
`logs/shell-guest-20261103-204721` run also passes 12/12 top-level assertions
against the real forced-shell runner/transient-unit path, covering successful
SQLite recovery and wrong-digest failure with preserved bytes and stopped units.
Five nested setup checks pass separately. Owned QEMU PID `2506884` is absent.
The API lifecycle unit is explicitly a sleeper, not a live application writer.
Exact hashes and limits are in `v4-lifecycle-testing.md`. The final host repair
is not present in these candidates. Successful remote deploy, actual API/writer
acceptance, final merged acceptance, and four-OS portable artifact certification
remain open. YouTube applications remain deferred.

## Neutral OpenAPI Compile-Time Dependency

Rust's remaining compile-time OpenAPI dependency on the Go tree is removed:
`af-api/src/routes.rs` now embeds `config/openapi-v1.yaml`. The canonical asset
has SHA-256 `f63ccf1bb9e24e1d17fb4996293c906622d95a7223d7bf788051015a3772270d`
and remains byte-identical to the preserved `backend/api/spec` compatibility
copy. No Go source or YouTube application file is changed or removed.

In isolated stage `parent-neutral-assets-20261103-145323`, all 16 Linux
packaging/CI contracts pass. Only in that disposable derived source, the
`backend` directory is renamed to `legacy-go-tree-withheld`. With no `backend`
path present, `cargo check --locked -p af-api --all-targets` and all 36 API
binary unit tests pass. This verifies the Rust compilation boundary, not a final
release artifact or clean-host installation. The older frozen host engine is
deliberately retained while its assigned repair finishes.

The withheld-source manifest is
`228ce85aee0d2334ea7d6e163c1c8160bdb6abebfaf74e6d5041e6732883d9bb`.
Logs and a verification summary are under
`logs/parent-neutral-assets-20261103-145323` in the validation root. The packaging
contracts now assert the deliberate shared `DATA_DIR`/database-parent lock
resolution rather than the removed hardcoded service `DB_PATH` and old lock
fallback strings; behavioral lock tests remain separate.

## Independent Provisional Product And Browser Acceptance

The source input for `parent-product-20261103-150700` contains 1,538 files,
fingerprinted by manifest
`b0abc79bcaf361fb1a62938e05eac8868da7cdadfead82f021b76b632b31f146`.
It combines the current non-host input at snapshot time with the explicitly
frozen earlier host engine from `parent-rollback-shm-20261103-143504`.
The active host-repair agent's files were neither read nor modified. This is
not the final merged candidate and does not close the outstanding host findings.

Logs are in
`/var/tmp/aetherflow-v4-validation-20261103-052723/logs/parent-product-20261103-150700`.

| Independently executed gate | Result | Limit |
| --- | --- | --- |
| Python discovery excluding `test_youtube_packages.py` | 146 passed; no skips, failures, or errors. | Includes mocked tools and harness evaluators, not just live operations. |
| Frontend unit tests | 20 suites, 68 tests passed. | Unit tests do not replace the browser run. |
| Frontend lint and static export | No lint errors; 48 warnings remain. Static export passed. | No warning-clean frontend claim. |
| Locked Rust workspace tests | 165 passed: API 36, CLI 15, DB 2, hardware 3, host 27, models 7, release 19, runner 34, services 22. | The 27 host tests cover the older frozen implementation, not the pending repair. |
| Strict workspace all-target Clippy | Passed with `-D warnings`. | Source analysis, not privileged lifecycle certification. |
| Release embedded acceptance suite | 387 checks passed in live mode, no skips or failures. | This is the suite's assertion count, not a count of distinct network requests. |
| Playwright Chromium | One test passed, no retries, flaky results, skips, or failures. | One real browser scenario; not exhaustive browser or OS coverage. |

The Chromium scenario uses real authentication and an HttpOnly session cookie,
persisted metrics history with window changes and WebSocket reload/reconnect,
Overview/Marketplace/Settings navigation, and the managed telemetry-inspector
plugin. It verifies plugin start/stop, health and allocated port, proxy responses,
UI sandbox headers, scoped token allow/deny behavior, and stopped-runtime access
rejection. No YouTube application installation or playback is exercised.

The parent decoded Playwright's embedded report archive and checked its actual
result records, rather than relying on a builder summary. Evidence:
`browser-parent-verification.json`, `browser-release/e2e-report.json`, and
`embedded-assets-manifest.json` in the log directory. The API listener on 19371
is closed after cleanup; no process referencing the owned runtime work directory
remains. The preserved work directory is
`/var/tmp/aetherflow-embedded-e2e.oewB4f`.

Release fingerprints:

- `aetherflow-api`: `4f5dcbe588bd07e04c522da93540c4f84d8273c3765afdd2174923e571ca2171`.
- `af`: `4f2f1f5d94e50b41e91e661dd3258295acd67713509259d46950909629ed8a3f`.
- Embedded asset manifest: `6eef61808f176c4bb93754847e01dde7f1c26210b4bbbb440503858bb3014f67` (190 files).
- Live HTTP check report SHA-256: `6985d9ef56d62b68bc7143349f5197ec6a3396d1da03343f4d63faf248254d07`.
- Playwright HTML report: `b8c348bbbc26351599a3da4e0edbb91d4955da1e75caa53b95756ab658a3e441`.

The release build matters: `rust-embed`'s debug filesystem mode returned a root
404 in an earlier probe, and a private build directory blocked the deliberately
unprivileged runtime. Both unsuccessful probes are preserved. Executable-only
public staging and a proper release build resolve those setup issues without
opening the private validation directory or relaxing acceptance assertions.
These Debian-host-built binaries are not the portable GLIBC 2.35 artifact.

## Provisional Security Gates And Synthetic Credential Repair

The initial raw scan reported one fixed synthetic guest JWT credential and 34
hash-shaped matches in the validation-only generated source manifest. The guest
fixture now generates 32 random bytes per provisioned environment; a new
deterministic regression verifies fresh entropy for each fixture. All 33 lifecycle
harness unit tests pass on both Windows and Linux. No secret-scanner allowlist
was broadened. Generated evidence manifests are stored outside the scanned
source input rather than mixed into the source being evaluated.

The corrected security input is a fresh extraction of the exact product input
plus only the updated lifecycle harness and its test. Its 1,538-file manifest is
`6cc605d76c940cda16cdc67f21120fb1e51cdc242baa9b7c731bf8406c283d1b`.
Evidence is under `security-corrected-3094375a3c82` within the product log
directory, including a separate source manifest and `security-summary.json`.

- Gitleaks 8.24.2: exit 0, no findings in this corrected source input.
- `cargo deny --locked check advisories bans sources`: exit 0; duplicate-version warnings remain.
- Raw `cargo audit --file Cargo.lock --json`: exit 1, exactly `RUSTSEC-2023-0071` reported.
- Policy audit with the documented public-key-only RSA exception: exit 0.

This is not a zero-advisory claim. License checks are not included in that
cargo-deny invocation. The security input still deliberately retains the older
host engine; all security gates must run again on the final merged candidate.

## Portable Certification Prerequisites

An independent provisional certification-input stage,
`parent-certification-5b93900c8f71`, has 1,538 source files with manifest
`ff3963701651e6a46b364df2f9c73a8cb9adf1487dbe99c9e70a076068570923`.
All 152 non-YouTube Python tests pass on Linux without skips, failures, or
errors. Gitleaks passes with no findings when invoked from that source root.
The existing scanner configuration remains unchanged, and a separate random-JWT
negative control is detected by the generic API key rule. No broad exemption
was introduced to obtain a clean scan. This source still has the explicitly
frozen older host implementation, not the active agent's repair.

The VM certification harness now requires a fresh HTTP success response with
JSON `status: ready` at the end of each of its four mandatory lifecycle scripts.
Previously an exhausted polling loop could continue after reading an empty
response file or discarding a failed readiness response. New regressions reject
empty, malformed, non-object, and non-ready responses and require the checked
pipeline in every mandatory script.

Artifact verification now inspects GLIBC requirements for `aetherflow-api`,
`af`, and `bin/af`, requires identical bytes for the two CLI copies, and treats a
failed remote `readelf` inspection as an error. The maximum requirement across
the binaries must fit GLIBC 2.35. These are certification-gate repairs, not
evidence that a final artifact has already passed. All 26 VM harness unit tests
pass on Windows and Linux, including API-compatible/CLI-incompatible artifacts,
CLI copy mismatch, and failed-inspection rejection.

A disposable Ubuntu 22.04 guest verified GLIBC 2.35 and prepared the pinned
Rust 1.99.1 and Node toolchain plus locked Cargo dependencies. Its owned QEMU PID
`2556401` is absent after teardown. The dependency-only build cache is recorded
under `portable-builder-cache/20261103-213137` in the private validation root;
its image SHA-256 is
`61cad5583aaa5d4784998e50a8c56177e0a625732620a47a78b1e13f3d13013c`.
This modified build image must never substitute for the official clean images
used in OS certification. A provisional source build can warm compiled dependency
caches, but final binaries must be rebuilt from the converged source and the
same final archive and independent checksums must pass all four clean OSes.

### Provisional Ubuntu Build Completed

The cache-warming build completed in a disposable Ubuntu 22.04 guest using the
provisional `ff396370` input, locked/offline Cargo compilation, a fresh static
frontend export, and the real release-packaging script. This is explicitly
`v4.0.0-provisional-build-probe`, not the final merged release.

Evidence is under
`portable-build-probe/20261103-214215` in the private validation root. The archive
SHA-256 is `2ca0938ee62a56ef0b76448b6820b9d87b273e7256eb9f6912c9a159bffeaf88`;
the independent `SHA256SUMS` file hashes to
`63e9716c0a20cf947c066c68a7b3fcb8a2095f18fae817d0a8e8bf2e9344e69f`.
The artifact contract passes, both CLI copies match, embedded frontend markers
are present, and actual `readelf` inspections report maximum GLIBC 2.34 for the
API and both CLI entries. The owned QEMU PID `2573077` is absent after teardown.

The compiled-dependency cache image hashes to
`859680dcd0e9248de33ca6ff723e148e94a65bcb0afc3ca8711100fdd288f182`.
It may accelerate the later final build; all local workspace crates must be
cleaned before rebuilding final source in this cache. This cache is not a clean
certification base. No operating-system lifecycle pass or final host-security
closure follows from a successful build or compatible GLIBC symbols alone.

### Clean Debian Bootstrap Regression Discovery

Three clean Debian 13 guest attempts using the provisional portable artifact
failed closed before application lifecycle certification. Evidence is retained
under `logs/provisional-debian13-20261103-214850`,
`logs/provisional-debian13-20261103-215241`, and
`logs/provisional-debian13-20261103-215743` in the private validation root. Each
includes the execution report, guest diagnostics, and archived guest evidence.
The first two runs exposed missing harness prerequisites (`dos2unix` and the
installer's `_init_state` call); both are corrected without weakening checks.
The third exposed a real installer strict-shell failure:
`06-state.sh: line 227: !key: unbound variable`.

An isolated Linux reproduction confirms `_init_state` creates an empty config
file and `_load_config` then expands an unset indirect variable under
`set -euo pipefail`. The helper now returns an empty value for an absent key,
while preserving configured values. Its regression covers absent files,
initialized empty files, partially populated files, explicit empty values, and
saved values using the real state module. A separate strict-shell regression
also confirms the readiness retry counter survives its first failed attempt
and stops after 20 attempts; its postincrement previously exited under
`set -e`.

The resulting explicitly provisional input is
`parent-certification-52d22d244ce0`, with 1,538 files and manifest SHA-256
`1079677f00da1ef1c64ea6de4e5f0ed6a5ee52fcca22a624e25cf4a015809753`.
All 154 non-YouTube Python tests pass on Linux, with zero skips, failures, or
errors. This input retains the older frozen host engine; the active host
repair files are neither read nor modified during these parent checks.
Guest lifecycle validation and final merged-source certification remain open.

### Python 3.10 Shell Rollback Compatibility

The subsequent clean Debian 13 retry passed all four mandatory lifecycle
phases and the separately labeled auxiliary fixture. Its evidence is under
`logs/provisional-debian13-20261103-220540`; report SHA-256 is
`f494e28ad213c7536c031e8641db286aff9bb6c8a159ee944e0eeb5a6e029d79`.
The owned QEMU PID `2603784` is absent after teardown. A separate Debian 12
guest also passed, with evidence under
`logs/provisional-debian-12-20261103-220843` and owned PID `2605269` absent.
Both use the provisional portable artifact, not final merged host repairs.

The first Ubuntu 22.04 attempt passed bootstrap and update, but rollback failed
closed: the shipped checksum verifier called `hashlib.file_digest`, which is
absent in the guest's Python 3.10. Correct snapshot bytes were rejected and
services stayed stopped; the drill did not pass. Preserve
`logs/provisional-ubuntu-22.04-20261103-220935` as the failing evidence, with
owned QEMU PID `2605873` absent after teardown.

The verifier now hashes the same no-follow-opened file descriptor incrementally
with SHA-256, retaining checksum enforcement without that runtime dependency.
A deterministic regression first removes the newer helper in child Python
processes, proves it is absent, checks tampered snapshots still fail closed,
and verifies a valid snapshot restores the database and removes WAL/SHM.
The regression fails against the old script with the same `AttributeError`;
its preserved log is in `parent-python310-regression-d82608ba41`.

All 155 non-YouTube Python tests now pass on Linux, with no skips, failures, or
errors, for `parent-certification-6c1956ff9516`, manifest SHA-256
`ee7d1782f9f5edab956383da12364a2f09280291169f62cd510a6de300515b47`.
Four-OS retries on this updated installer input now pass, as recorded below.
This input still uses the explicitly frozen older host engine; final
merged-source and artifact certification remain required.

### Identical-Input Provisional Four-OS Lifecycle Pass

The same provisional portable archive and identical updated source bundle pass
all four mandatory phases on separate official, clean OS guests, one at a time:
prebuilt bootstrap and health/CLI, release update, deliberate failed-health
rollback with corrupt-database recovery, and real updater termination followed
by shipped CLI recovery. The synthetic recovery fixture is separately labeled
and does not substitute for the real interrupted-process phase.

| OS verified inside guest | Evidence directory under private `logs/` | Mandatory phases | Owned QEMU PID after teardown |
| --- | --- | --- | --- |
| Debian 12, GLIBC 2.36 | `provisional-debian-12-20261103-221735` | 4/4 passed | `2616634`, absent |
| Debian 13, GLIBC 2.41 | `provisional-debian-13-20261103-221855` | 4/4 passed | `2617349`, absent |
| Ubuntu 22.04, GLIBC 2.35 | `provisional-ubuntu-22.04-20261103-221509` | 4/4 passed | `2615373`, absent |
| Ubuntu 24.04, GLIBC 2.39 | `provisional-ubuntu-24.04-20261103-221620` | 4/4 passed | `2615974`, absent |

Each guest also passes one labeled auxiliary fixture, for 16 mandatory passes
and four auxiliary fixture passes in total. Parent verification independently
checks every phase command has exit code zero without a timeout, actual guest
OS IDs and versions, all 1,538 archived source-file hashes against the frozen
manifest, identical artifact/checksum identities, and absence of all four
owned VM PIDs. The parent VM slot is free.

The common source bundle SHA-256 is
`ac7607351a3d404330db8ec3c9cea51cd18e599d6c01c554baf04b9abcc91fa4`.
The artifact SHA-256 remains
`2ca0938ee62a56ef0b76448b6820b9d87b273e7256eb9f6912c9a159bffeaf88`.
The independent verification record is
`logs/parent-certification-6c1956ff9516/provisional-four-os-parent-verification.json`,
SHA-256 `f1f0829dcf8f32ae8250a0b3903698f17c6ab925f2d5abfe6f209ffd8501eb98`.
It records each report and archived evidence digest. This closes the observed
bootstrap and Python 3.10 portability regressions for this provisional input,
not the active host-security repairs or final merged-source release. No
production operation or YouTube-specific validation is performed.

## Frozen merged candidate: November 3, 2026

The bounded host implementation task completed naturally, without interruption.
The parent independently matched all eight delivered file hashes against its
remote manifest and inspected the actual root, non-root, compatibility and
selected-crate Clippy logs. Those selected-crate checks are not mislabeled as
whole-workspace checks.

The full merged source is `source-20261103-172058`, with 1,529 input files and
manifest SHA-256
`648717c5c50618d60fdd075dcef944c3614cdcb1c2c2eee0c23ed8c2196e481b`.
It includes both the completed host implementation and the parent bootstrap
and Python 3.10 portability fixes. Independent parent logs are under
`logs/merged-20261103-172058` in the established validation root.

| Check | Observed result | Limit |
| --- | --- | --- |
| Clean all nine workspace crates, then `cargo test --workspace --locked -j 2` | 173 tests passed. | Deterministic crate evidence, not live systemd acceptance. |
| `cargo clippy --workspace --all-targets --locked -j 2 -- -D warnings` | Passed, zero warnings. | All nine workspace crates, unlike the earlier selected-crate handoff. |
| Actual UID/GID `65534:65534` host test executable | 35 tests passed after correcting the parent fixture's inaccessible temporary-directory ancestry. | The initial 33 permission failures remain preserved separately; no validation-root permissions were broadened. |
| Non-YouTube Python suite with warnings treated as errors | 155 tests passed, no skips or errors. | YouTube-specific tests remain excluded by user instruction. |
| Frontend lint, unit tests, static export | Zero lint errors, 48 existing warnings; 20 suites and 68 tests passed; static build passed. | Embedded-browser acceptance is separately required. |
| `cargo deny` and documented policy audit | Passed advisories/bans/sources and policy audit. | Raw audit still reports only the documented `RUSTSEC-2023-0071` exception; not a zero-advisory claim. |
| Gitleaks on the frozen input | One false positive: the previous live-HTTP report checksum label in this ledger. | The current local label is clarified without changing the scanner policy. Corrected-source rescan and refreeze remain required. |

The portable build uses a disposable Ubuntu 22.04 guest with cached third-party
dependencies, offline locked Rust dependency resolution, and a fresh rebuild
of all nine local crates. The cache image is not a certification image. Its
owned QEMU PID `2674337` is absent after teardown. The candidate archive
SHA-256 is
`1cb3e74daf0ddd13088f6f437a1a296e9e170ae5bc2a55b2fc730e97297bace8`;
`aetherflow-api`, `af`, and `bin/af` require at most GLIBC 2.34, and the two CLI
copies match. Build evidence is
`portable-merged-build/20261103-232805/build-report.json`.

### Live acceptance remains fail-closed

The candidate passes all four mandatory install/update/failed-health rollback/
real-process interruption phases on a fresh Debian 13 guest. This is one OS,
not a new four-OS pass, and the auxiliary recovery fixture remains labeled.

An additional drill uses the actual packaged API, authenticated HTTP profile
writes, and the installed privileged runner rather than a sleeper service.
The API persists the golden pre-snapshot value, but native backup returns HTTP
409 before restore: `/var/lib/aetherflow` is service-owned UID 999, while the
new privileged lock guard correctly rejects a replaceable non-root-owned lock
parent. The packaged API unit declares `StateDirectory=aetherflow` with
`User=aetherflow`, so this is a real integration mismatch, not evidence that
the guard should be weakened. Detailed failure evidence is
`logs/merged-debian-13-20261103-234328/live-api-writer-report.json`.

The independent source reviewer completed its bounded assignment naturally.
Its source-only report records six P1 and five P2 findings, including the
default lock incompatibility independently reproduced by the live API drill.
Other open findings concern installed-inode substitution, uncertain commit
publication, lock-ancestor replacement, SQLite connection identity, stale
local journal sidecars, relative checksum traversal, explicit GID zero,
custom SQLite ownership propagation, pending provenance ancestors, and early
cleanup diagnostics. These are not eleven executed exploit reproductions.

The subsequent Debian 13 guest suites use the same merged binaries and retain
their separate outcomes in `logs/guest-suites-20261103-234439`:

| Suite | Observed result | Limit |
| --- | --- | --- |
| Native packages | All five required phases pass, including fail2ban, quassel preservation, threadfin artifact verification, and cancellation/serialization safety. | Debian 13 candidate evidence, not final four-OS certification. |
| Systemd lifecycle | All six required phases pass, including transient-unit survival, native rollback/recovery, and rejected-snapshot quiescence. | Does not close the separate default packaged API maintenance-lock failure. |
| Privileged restore | Four of six phases pass; ownership/quiescence and held-open WAL restore remain failed. | The golden-source fixture uses UID 65534 without a configured trusted owner. The CLI WAL fixture supplies a backup directory outside its isolated root and correctly receives a validation error on stderr; this is not evidence of successful restore or a reason to relax containment. |

Owned guest PID `2690269` is absent and the parent VM slot is free after this
run. The archived failure reports remain unchanged. The same portable API
binary also passes all 387 live HTTP checks; its Chromium step does not launch
because the parent omitted the existing private browser-cache environment
setting. Browser acceptance remains open until a corrected launch succeeds.

No final restore, shared-lock, four-OS, or production signoff is granted.
YouTube applications and their existing working-tree changes remain untouched.

### Bounded repair handoff and parent regressions

The implementation delegate completed its exact eleven-finding assignment
naturally. Its stage is `restore-closure-impl-20261103-191050`; the recorded
root tests, actual non-root host/model/release tests, 29 shell compatibility
tests, and strict Clippy logs pass. Those are handoff evidence, not a new
packaged-systemd or four-OS acceptance claim.

Parent verification identified that the connection-identity test did not yet
cover restoring the original database name after opening the substitute.
The added deterministic regression fails on that handoff with a successful
substitute snapshot, then passes after checking the actual connection's
SQLite VFS identity and main database name. The parent also replaces loose
install temporary names with an executor-private, descriptor-pinned directory.
All 42 host tests pass on the strengthened candidate. The before/after logs
are `logs/parent-s05-regression-before-fix/regression.log` and
`logs/parent-s05-regression-after-fix.log`; the failed evidence is preserved.

The browser-cache-only correction on the preceding frozen binary succeeds:
387 live HTTP checks and the Chromium embedded test pass, with log SHA-256
`c64e3755cc0bf6d2e7c5d08b5e78a22d22b7b744edf67f1c89ce17a0424d48bd`.
This does not substitute for rerunning the repaired artifact. Final merged
gates, rebuilt artifact, installed API writer restore, and the same artifact
on the four official OS targets remain the final delivery gates. The user
authorizes a scoped GitHub commit/push after these repairs and verification;
YouTube and unrelated working-tree changes remain excluded.
