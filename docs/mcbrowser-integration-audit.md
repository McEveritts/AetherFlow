# McBrowser integration audit checkpoint

## November 2 GitHub update checkpoint

- Validated an isolated export of the staged McBrowser update, excluding unrelated
  marketplace changes: **262 af-api tests passed, 2 ignored opt-in fixtures**;
  **40 frontend suites / 375 tests passed**, using the existing Streaming contract
  fixtures. TypeScript and targeted workspace/tab ESLint passed. Logs:
  `/tmp/mcbrowser-push-{api,frontend,ts,lint}.log`. Jest used `--forceExit`;
  this does not establish zero open handles. The earlier 264-test current-tree
  run also included two unrelated marketplace tests excluded from this snapshot.
- The latest workspace fix refreshes quota after directory results change,
  ignores stale usage responses, and removes stale usage on retrieval failure.
  A regression covers refresh, stale-response suppression and recovery.
- Disposable mounted-API browser testing confirmed multi-file upload, a zero-byte
  file, a 2 MiB payload, confined-alias UTF-8 editing with the link preserved,
  exact quota/audit deltas, and creation of a password-protected alias share.
  Public unlock/download was not completed. The fixture's seeded session is not
  production-authentication acceptance.
- The replacement COPY implementation and independent sharing/recovery review
  agents are interrupted, not successfully completed. Their current changes pass
  these gates but final independent review and outstanding acceptance remain due.
  **This is an experimental checkpoint, not a full-parity completion claim.**

## November 2 fair recovery, bounded archive planning and alias sharing

- The independent public-upload review found two further recovery gaps. Expiry
  cleanup now advances a durable `(expires_at, id)` keyset cursor over bounded
  128-row pages, wrapping when exhausted. Ambiguous sessions retain their quota,
  staging and pending audit without starving later safely expired sessions.
  A native regression creates 128 ambiguous sessions across four users plus a
  safe fifth-user session and verifies reclamation on the next cleanup call.
- Audit-intent repair now creates and binds the event inside one savepoint;
  binding failure rolls back the event and leaves the in-memory binding unchanged.
  A public HEAD regression injects a binding-update abort, verifies no orphan
  intent or publication, and retries to exactly one completed bound event.
  **32 upload tests passed** (`/tmp/mcbrowser-upload-fair-cleanup.log`).
- Archive ticket creation now shares archive admission with both download routes.
  Blocking planners own the permit until failure or transfer to the encoder.
  Dropping the request signals cooperative cancellation, checked throughout
  traversal and authorization, with a 30-second planning deadline. Regressions
  cover all three handler admission gates, cancellation while a blocking planner
  is confirmed active, exact 10,000-entry admission and overflow, deadlines and
  hardlinks introduced after planning across all nine codecs. **25 operations
  tests passed** (`/tmp/mcbrowser-archive-planning-tests.log`). Blocking filesystem
  syscalls are not preemptible; identity pinning is not content immutability.
- Sharing now supports confined root file/directory aliases with pinned identity,
  every-hop owner permission checks, alias-preserving names and public paths.
  Descendant aliases resolve inside the pinned public-share subtree, not the
  entire owner's root, matching upstream `http/public.go:58-76` rebasing. Child
  escapes, loops, special files and hardlinks remain rejected or filtered. Native
  and mounted tests cover live denies, retargeting, public listing/download and
  Range. **11 share tests passed** (`/tmp/mcbrowser-share-alias-tests.log`), and
  **48 workspace tests passed**, including sharing aliases in all four views
  (`/tmp/mcbrowser-share-alias-ui-current.log`). Independent re-review remains due.
- Combined current-tree gates: **264 af-api tests passed, 2 ignored fixture entry
  points**, API build passed; **40 frontend suites / 374 tests passed** with the
  existing Streaming contract fixtures; TypeScript, targeted workspace ESLint and
  production Next build passed. Logs: `/tmp/mcbrowser-integrated-current-{api,
  build,frontend,next-build}.log` and `/tmp/mcbrowser-share-copy-{ts,lint}.log`.
  Jest used `--forceExit`; this is not evidence of zero open handles. The two
  ignored tests are opt-in transport/browser server fixtures, not failed features.
- The replacement Gemini COPY implementation is still in flight; current-tree
  tests include its partial integration but do not replace its final review.
  Operator accounting/retention recovery, remaining source-pinned workflows and
  actual browser/abuse acceptance still block full parity. No commits or
  deployment were performed, and no Streaming sources were changed.

## November 2 public upload retry recovery and confined archive sources

- Reproduced the independent review's pre-publication Skip collision bug through
  PATCH preparation, body streaming and finalization: a failed audit update left
  SQLite offset zero despite four synced staging bytes. The regression failed
  before repair (`/tmp/mcbrowser-public-skip-repro.log`). Every synced chunk now
  persists its offset before fallible completion, skip or publication work.
  HEAD can recover regular and same-content skips without truncating staging;
  nonregular collisions discard atomically after audit recovery. Retrying a
  recovered skipped PATCH returns idempotent 204 with skipped metadata.
- HEAD now reports a proven-unpublished bound-target conflict instead of
  swallowing it and advertising successful resumability. Public upload phases
  exercise Error, Overwrite and Resume races; the competing target remains
  unchanged, audit stays pending until cancellation, and quota releases once.
  Successful nonregular and zero-byte session discard also removes its private
  publication journal. **30 upload tests passed**
  (`/tmp/mcbrowser-public-recovery-fixed.log`). Independent re-review remains due.
- Archive planning follows confined internal file and directory aliases, checks
  requested/intermediate/final authorization paths, preserves requested names,
  bounds traversal and detects directory cycles. Authorized source descriptors
  remain pinned through encoding; positional readers have independent offsets,
  ignore growth beyond the planned size and reject truncation. This pins file
  identity, not an immutable snapshot against concurrent in-place writes.
  Native CreateArchive also checks Execute on every source resolution path and
  rejects canonical destination overlap. **21 operations tests**, the mounted
  all-nine-codec alias/ticket/action regression, and **43 workspace tests** passed
  (`/tmp/mcbrowser-alias-archive-{ops,http-current,ui-current}.log`). These do not
  prove large-download/browser acceptance or archive resource admission safety.
- The combined backend rerun encountered in-flight COPY test/helper signature
  mismatches (`/tmp/mcbrowser-alias-archive-recovery-integrated.log`), so there is
  no newer combined-green claim. The Gemini copy connection then failed; its
  partial edits are retained and require implementation recovery and validation.
  Alias sharing, accounting repair/operator workflows, independent audits and
  real-browser/source-pinned acceptance still block full parity.

## November 2 durable publication identity and deletion accounting

- Upload recovery no longer treats equal payloads or lengths as evidence that
  a session published. An atomic, private per-session journal records
  `unpublished`, `prepared`, or `published`. Before publication, the prepared
  record binds the pending file's device/inode and random xattr nonce. Recovery
  checks that exact identity on the pinned target, avoiding false completion
  when another writer publishes identical bytes or an inode is reused.
- In-process publication errors persist known-unpublished state before cleanup.
  Public HEAD recovery now distinguishes a skipped collision from a completed
  mutation, handles nonregular collisions safely, and allows cancellation of
  proven-unpublished full-offset sessions. Cancellation and expiry roll back
  quota/session cleanup if recording failed audit state fails. Initialization
  removes the journal only after atomic session discard succeeds.
- Missing, malformed or unmatched proof retains the session row, quota and
  pending audit, including after expiry. Filesystems without usable user xattrs
  can complete normal publication, but a crash in the prepared/commit gap stays
  conservatively ambiguous. Legacy full-offset sessions without journals also
  remain ambiguous. This is safe retention, not automatic reconciliation or
  completed operator recovery UX; expired retained sessions still need that work.
- Journal reads reject symlinks, hardlinks, nonregular files, unsafe permissions,
  oversized documents and unknown JSON fields. Nonblocking open prevents a
  hostile FIFO from hanging recovery. The new regression exposed Serde's unit
  variant unknown-field behavior; empty struct variants now enforce strictness.
- Confirmed single and recursive deletions return success with
  `accounting_pending: true` if quota release fails after removal. Audit remains
  pending and no completion task is queued. Partial recursive deletion retains
  an honest error/pending audit. The workspace removes confirmed deletions from
  retry targets while displaying the accounting warning.
- Verified gates: **137 McBrowser tests passed, 1 ignored**
  (`/tmp/mcbrowser-publication-proof-integrated-green.log`), actual API build
  passed (`/tmp/mcbrowser-publication-proof-build.log`), **40 frontend suites /
  368 tests passed**, TypeScript and targeted ESLint passed
  (`/tmp/mcbrowser-publication-proof-{frontend,tsc,lint}.log`). Jest used
  `--forceExit`; no absence-of-open-handles claim is made. These are scoped
  gates, not whole-API, browser or full-parity acceptance.
- **Still open:** independent review of the new publication proof, a durable
  idempotent accounting repair ledger/operator retention workflow, remaining
  alias copy/archive/share parity, source-pinned inventory and browser acceptance.
  Full parity remains incomplete. No Streaming edits, deployment, commit or
  branch creation was performed for this checkpoint.

## November 2 accounting outcomes and subtitle alias authorization

- Local repairs replace the no-result accounting delegate's unverified work.
  `AccountingPending` now distinguishes unpublished operations whose quota
  compensation failed from clean failures. The generic mutation audit wrapper
  leaves those intents pending rather than recording a false failed/zero-delta
  outcome. New-file creation and raw-upload publication failures use this path.
- Published content saves, copy overwrites and move overwrites no longer return
  a mutation failure merely because quota release failed. Explicit accounting
  status propagates through the live handlers: responses retain success and
  include `accounting_pending`, while their audit intent remains pending and
  no completion task is enqueued. Copy-growth rollback now checks removal and
  compensation instead of silently releasing quota for an unremoved target.
  The workspace warns about pending accounting, accepts the returned save ETag
  and keeps a published save clean; batch outcomes preserve allocated paths
  and show reconciliation notices without putting successful items into retry.
- New deterministic SQLite quota-release fault tests cover published shrink,
  pinned-target replacement conflicts, copy/move overwrite publication and
  copy collision compensation. An audit-wrapper test verifies that both
  published-but-unaccounted and unpublished-but-uncompensated operations remain
  pending with no queued completion. The workspace regression verifies that a
  published save closes without an unsaved-changes prompt.
- The independent media re-check found additional real defects: subtitle
  discovery could expose resolved child paths, bypass alias-specific sidecar
  rules and omit the video's intermediate/final Read checks. Discovery now
  authorizes the video trace, authorizes each listed directory trace, rewrites
  child paths to the requested alias prefix, and authorizes each child trace.
  Native media inspection restores alias path/name and pinned modification
  time. The new mounted video regression covers directory and leaf aliases,
  requested/intermediate/final video denies, alias-specific subtitle denies,
  returned sidecar paths and native-action identity. Leaf sidecars are searched
  beside the requested alias, not through a disclosed canonical target path.
- Verification: **130 McBrowser tests passed, 1 ignored**
  (`/tmp/mcbrowser-accounting-copy-gate.log`); **40 frontend suites / 367 tests
  passed** (`/tmp/mcbrowser-accounting-frontend-green.log`); TypeScript and
  targeted ESLint passed (`/tmp/mcbrowser-accounting-tsc-green.log`,
  `/tmp/mcbrowser-accounting-lint-green.log`); actual API build passed
  (`/tmp/mcbrowser-accounting-build.log`). Jest uses `--forceExit`; this does
  not establish absence of open handles. No whole-API or browser parity claim
  is made by these scoped gates.
- **Still open:** pending accounting is conservative retention, not an
  automatic/idempotent quota-repair ledger. Upload recovery still uses unsafe
  digest-only publication inference and needs durable known-unpublished proof
  across transient DB cleanup failures; ambiguous upload expiry can still
  discard its session row while retaining quota. Single/recursive deletion
  also needs the same post-publication accounting-outcome treatment. Broader
  alias copy/archive/share parity, remaining media/browser acceptance and the
  source-pinned inventory remain incomplete. Full parity is not achieved.
  No Streaming modules, deployments, commits or branches were changed here.

## November 2 alias primary-activation repair

- The independent editor review's missing activation cases exposed a real UI
  defect: explicit alias Edit buttons worked, but stale primary-open guards
  still excluded file aliases from grid/gallery/mosaic title activation and
  single-click card/row activation. All three renderers now admit resolved file
  or directory targets. Unknown aliases and special entries remain excluded;
  editor opening still enforces Read and saving still enforces Modify.
- Eight new regressions cover title and single-click activation in list, grid,
  gallery and mosaic. Each fetches the requested alias exactly once, loads its
  content and never invokes directory navigation. Workspace suite: **40 passed**
  (`/tmp/mcbrowser-alias-activation-green.log`); full frontend: **40 suites,
  366 tests passed** (`/tmp/mcbrowser-alias-activation-frontend-all.log`).
  TypeScript and targeted lint pass (`/tmp/mcbrowser-alias-activation-tsc.log`,
  `/tmp/mcbrowser-alias-activation-lint.log`).
- Both upload-publication-identity and mutation-accounting implementation
  delegates terminated without assistant results or verified repairs. Their
  defects remain open, not resolved by task completion status. Local repair is
  the next implementation step; no accounting/publication safety claim is made.
  Media independent re-review, browser acceptance and broader inventory gaps
  also remain open. No Streaming or production/deployment changes were made.

## November 2 mounted alias media parity and host-listing assessment

- A new mounted regression reproduced a real gap: media bytes could be read
  through a confined directory alias, but media-info rejected the same path
  before its authorized-open fallback. Metadata now resolves confined paths,
  checks Read on every resolution hop and final target, and preserves the
  requested alias path/name. File size and modification time are refreshed from
  the authorized pinned file used for signature/dimension inspection. Open
  failures no longer silently produce successful file metadata responses.
- The tab's rich-preview dispatch no longer restricts media to raw `kind=file`
  after the existing resolved-file gate. Confined image/video/audio/PDF/CSV/EPUB
  aliases reach the rich viewer rather than incorrectly entering the UTF-8
  reader. Twelve routing cases cover regular files and aliases across all six
  categories; unresolved and directory targets retain the existing exclusion.
- Mounted tests cover media, media-info, thumbnails and both preview sizes,
  CSV and subtitle delivery through a two-hop directory alias. Each must deny
  the requested alias, intermediate hop or target-prefix policy independently.
  Leaf-alias media and metadata are also checked; successful metadata preserves
  alias identity and dimensions, and streamed image bytes are exact.
- Service-data assessment: host `/fs` listings require an authenticated, live,
  active non-plugin admin before filesystem existence/canonicalization/listing.
  The mounted regression covers all four route prefixes, a private
  `streaming-backup-*` directory, its parent, a link and an absent path. It
  verifies uniform non-admin rejection without backup names or entries, permits
  an active admin and rejects suspension. Ordinary McBrowser browsing remains
  under the user's descriptor-confined root. No Streaming module changes were
  needed for this boundary; this is not a promise to hide service paths from
  authorized administrators.
- Verification: **126 McBrowser tests passed, 1 ignored**
  (`/tmp/mcbrowser-alias-media-integrated.log`); media unit suite **7 passed**
  (`/tmp/mcbrowser-media-regression-final.log`); full frontend **40 suites,
  358 tests passed** (`/tmp/mcbrowser-alias-media-frontend-all.log`). Targeted
  TypeScript and ESLint pass (`/tmp/mcbrowser-alias-media-tsc.log`,
  `/tmp/mcbrowser-alias-media-lint.log`). Browser acceptance and independent
  media re-review remain open, as do upload publication-identity recovery and
  alias copy/archive/share. No production/deployment changes were performed.
- The independent confined-editor review verified every-hop authorization,
  pinned ETag/target handling and link preservation, but found blocking quota
  accounting/audit defects: failed compensation after an unpublished commit can
  still produce a failed zero-delta audit while reservation remains charged;
  failed shrink release after successful publication can be silently completed.
  These findings affect shared create/copy/raw-upload helpers too and require
  repair plus injected quota-release-failure regressions. The passing gates
  above do not cover or clear these findings.

## November 2 confined alias editor and cleanup integration

- UTF-8 content GET/PUT now support confined internal file aliases. Reads and
  writes authorize the requested alias, every resolution hop and the final
  target. PUT reads the ETag and old size from one pinned file, atomically
  replaces that bound target and preserves the alias. FileSaved audit paths
  retain the requested alias. Mounted single-connection tests cover policy,
  ETag, quota, hardlink/escape rejection and target/alias replacement races.
- List, grid, gallery and mosaic workspace controls expose alias editing,
  preserve drafts on read/save errors, enforce Read/Modify controls and explain
  that saving updates the confined target. Alias copy/archive/share remain
  incomplete; editor implementation is not a full symlink-parity claim.
- Post-commit upload staging initialization cleanup now uses the atomic
  session/audit/quota discard helper. A quota-release failure retains the
  session and pending audit for retry instead of deleting the recovery record.
  Extraction tracks reserved bytes before no-clobber commit and only subtracts
  successful compensation; incomplete quota/filesystem cleanup retains pending
  audit state. Regression tests exercise both failed and successful compensation.
- ZIP admission rejects duplicate ZIP64 extra fields while allowing incidental
  locator magic inside an ordinary comment. Exact-directory decoder binding,
  entry/metadata ceilings and valid ZIP64 support remain tested.
- Current integrated McBrowser gate: **125 passed, 0 failed, 1 ignored**
  (`/tmp/mcbrowser-alias-editor-recovery-integrated.log`). Full frontend:
  **40 suites, 347 tests passed**
  (`/tmp/mcbrowser-alias-editor-frontend-all.log`). TypeScript and production
  Next build pass after repairing the preferences fixture
  (`/tmp/mcbrowser-alias-editor-tsc-final.log`,
  `/tmp/mcbrowser-alias-editor-build-final.log`). Serial af-files gate:
  **29 passed** (`/tmp/mcbrowser-af-files-serial-final.log`). An earlier parallel
  af-files run returned EAGAIN from a confined open; serial success does not
  establish the cause or resolve parallel-run reliability.
- **Open correctness blocker:** publication-error recovery still needs durable
  proof distinguishing an upload's published inode from a competing identical
  file. Transient cleanup DB failures can leave public HEAD/PATCH/DELETE/expiry
  recovery ambiguous or falsely completed. A focused repair is in progress;
  existing green tests do not establish that this race is safe. Independent
  confined-editor review and broader browser acceptance also remain open.
- No Streaming modules or production/deployment state were changed. This gate
  does not supersede the separately documented whole-API Streaming failures or
  establish full source-pinned parity.

## November 2 confined alias inspection and ZIP decoder identity repair

- Info/checksums now support confined file aliases, and metadata/counts support
  confined directory aliases. The collector authorizes the requested path,
  every resolution-trace path and the final target. Checksums use the returned
  pinned file and its metadata; directory counts filter children through every
  alias hop and the target namespace. Responses retain the requested alias
  path/name instead of revealing the resolved path. Mounted tests verify alias,
  intermediate-hop and target denials, live suspension and unchanged quota.
- Workspace Info controls are available for known file/directory aliases in
  list, grid, gallery and mosaic views. Directory requests explicitly omit the
  checksum parameter and display visible child counts. Unresolved aliases and
  special files remain blocked; alias editor/copy/archive/share workflows remain
  incomplete. These changes do not establish full upstream information parity.
- A deterministic regression proved that `zip` 9.2.1's automatic offset
  detection selected an unadmitted duplicate central directory: decoding
  returned archive offset 54 instead of 0. Admission now returns the exact
  directory offset, size and count. `AdmittedZipReader` presents the unchanged
  payload and admitted directory followed by a fixed 98-byte canonical ZIP64
  footer and virtual EOF. It does not rewrite the archive on disk or buffer its
  payload/directory. `Known(0)` prevents offset redetection; the footer abuts the
  admitted directory, preventing the decoder's invalid-directory fallback from
  choosing earlier end records. Returned offset and directory identity are
  checked as defense in depth. Original comments and alternate end records are
  not passed to the decoder; member bytes and offsets remain unchanged.
- The expanded regression covers duplicate directories, an embedded EOCD in
  an outer comment (including an unadmitted 4097-entry claim), duplicate ZIP64
  end records, and a valid ZIP64 archive with the maximum 65535-byte comment.
  Payload roundtrips remain byte-exact. The raw admission tail now includes the
  additional 20-byte locator needed for that maximum comment. Existing 4096
  entry / 8 MiB metadata / extraction resource ceilings remain in force.
- Verification: **117 McBrowser tests passed**, one subprocess fixture ignored
  in enumeration but exercised by its passing parent transport test
  (`/tmp/mcbrowser-alias-zip-integrated.log`); API build passed
  (`/tmp/mcbrowser-alias-zip-build.log`). Full frontend: **40 suites, 340 tests
  passed**, TypeScript and targeted ESLint passed
  (`/tmp/mcbrowser-alias-zip-frontend-all.log`,
  `/tmp/mcbrowser-alias-zip-tsc.log`, `/tmp/mcbrowser-alias-zip-lint.log`). This
  does not supersede the independently reproduced whole-API Streaming failure
  below. No Streaming files or production state were changed.
- Independent alias review is pending. ZIP decoder identity repair requires a
  fresh independent re-check. Remaining follow-ups include non-regular
  zero-byte Skip failure cleanup, nonzero final-publication Skip collisions,
  and ExtractArchive audit finalization after confirmed complete cleanup.
  Full feature parity, browser acceptance and deployment remain unclaimed.

## November 2 bounded ZIP admission and unpublished-failure audit repair

- ZIP extraction now scans ordinary and ZIP64 end records and central-directory
  records before constructing `zip::ZipArchive`. It admits at most 4096 actual
  records and 8 MiB of central-directory metadata, validates declared counts,
  offsets, single-disk structure and ZIP64 extra fields, rejects encryption flags
  and AES methods, and enforces deadlines/read budgets through both preflight
  and replay library construction. Valid small ZIP64 archives are tested, not
  rejected categorically. These are explicit extraction resource ceilings, not
  a claim of unrestricted upstream archive parity.
- Zero-byte skip publication now handles a regular destination appearing between
  preflight and atomic no-clobber commit without replacing it. The publication
  helper has a deterministic collision regression. Late skip completion uses a
  savepoint to release only its reservation, retain a failed zero-delta
  `SKIPPED_CONFLICT` audit, clear the session's mutation-audit binding, and persist
  its skipped marker for subsequent HEAD requests. An injected audit-write
  failure rolls back session/quota changes; retry and repeated HEAD do not
  double-release quota or enqueue completed mutation events.
- Known-unpublished failures from single-directory creation, single-entry
  deletion, and raw upload reservation/atomic publication now become failed
  audits rather than indefinitely pending records. CreateArchive staging,
  bounded-writing, policy, quota and commit failures also become failed when
  created ancestor cleanup succeeds. Recursive/partial mutations and failed
  cleanup retain pending evidence; successful publication is never reported as
  rolled back because later audit persistence fails.
- The integrated McBrowser gate passes **114 tests**, with its subprocess-only
  server ignored in direct enumeration but exercised by the real HTTP parent
  test (`/tmp/mcbrowser-audit-skip-zip-integrated.log`). This includes **20 upload
  tests**, **13 native-action tests**, the actual socket/process restart test,
  and the mounted unpublished-failure audit regression. A fresh independent
  review of ZIP64 admission and skip recovery is in progress; full-parity,
  browser/resource acceptance and deployment remain unclaimed.
- A broader API test attempt does **not** pass: **217 passed, 9 failed, 2
  ignored** (`/tmp/mcbrowser-audit-skip-full-api.log`). Its first failure is
  `streaming_ext::tests::test_monitor_identity_cold_start_and_stale_source_refuse_writes`
  with `QueryReturnedNoRows`; eight subsequent Streaming tests encounter a
  poisoned test lock. These results supersede earlier whole-API green counts
  for this checkout. Running that first test alone, without executing McBrowser
  tests, reproduces `QueryReturnedNoRows` after 60 seconds
  (`/tmp/mcbrowser-unrelated-streaming-isolation.log`). Streaming files were not
  changed in this repair.

## November 2 real HTTP process-crash recovery acceptance

- Added `real_http_upload_survives_process_crash` in
  `backend-rs/crates/af-api/src/mcbrowser_http_tests.rs`. It starts the actual
  Axum router on an ephemeral loopback socket in a disposable test subprocess,
  uses a temporary SQLite database and storage root, and kills/restarts that
  process twice. It never boots production workers or changes deployed state.
- A patterned 2 MiB payload is partially acknowledged, then interrupted during
  another PATCH body. A second same-user upload completes while that body is
  stalled, exercising single-connection pool and mutation-stripe availability.
  After process death, exact-fingerprint discovery and HEAD resume from the
  durable SQLite offset; HEAD deliberately truncates any uncommitted staging
  tail, rather than treating bytes from an unfinished request as acknowledged.
  The unfinished target returns HTTP 404 and is absent from the published root.
- Completion is sent over a raw TCP connection without reading its response.
  A test-only middleware marker confirms the handler returned 204; the process
  is killed and restarted again. Repeated HEAD, full download, Range download,
  final quota, and exactly one completed audit/outbox record are verified.
- The disposable server test is marked ignored for direct test enumeration but
  is explicitly invoked three times by the automatically executed parent test.
  This is real socket/process acceptance with preauthenticated fixture identity,
  not login/cookie, browser picker, large-file, disk-exhaustion, power-loss, or
  production-server certification. Those broader acceptance gates remain open.
- The independent publication/resource review confirmed that ZIP metadata was
  parsed by the ZIP library before the 4096-entry admission limit, and the raw
  encryption scan skipped ZIP64/large central directories. Bounded ZIP/ZIP64
  admission is assigned to a Gemini 4 Argon High implementation teammate; it is
  not yet certified repaired. Lower-severity audit-state consistency on proven
  unpublished failures and zero-byte skip collision behavior also need follow-up.
- Verification: `cargo test -p af-api mcbrowser:: --offline --manifest-path
  backend-rs/Cargo.toml -- --test-threads=1` passes **110 tests**, with **1
  subprocess-only fixture ignored in direct enumeration and exercised by its
  passing parent**. Output: `/tmp/mcbrowser-real-transport-suite.log`. The fresh
  frontend follow-up remains **40 suites, 335 passing tests** and a clean
  TypeScript check (`/tmp/mcbrowser-workspace-followup-all.log` and
  `/tmp/mcbrowser-workspace-followup-tsc.log`); this transport change edits no UI.

## November 2 keyboard/clipboard parity and mounted audit recovery

- Source-pinned `FileListing.vue:554` shortcuts now operate within the native
  workspace: selection/clear, range selection, copy/cut/paste, search focus,
  archive download, delete confirmation and mounted F2 rename. Inputs, editable
  content and dialogs do not dispatch explorer shortcuts. Permissions gate both
  shortcut admission and batch submission. Internal clipboard source snapshots
  survive folder navigation; paste uses the existing conflict/confirmation UI,
  and only successfully moved items leave the cut clipboard.
- Same-folder keep-both requests were incorrectly rejected as identical paths
  before suffix allocation. Client and backend now allow equal requested paths
  exclusively for keep-both, retain strict checks on the allocated destination,
  and still reject same-path overwrite/error and descendant destinations.
  Component, helper and mounted HTTP tests cover exact quota/audit destinations.
- The delivered upload/share audit integration now compiles and passes mounted
  recovery tests. Uploads persist their audit UUID across lost acknowledgments;
  completion plus queue insertion is idempotent, and share writes plus completion
  are transactional. The previous compilation failure below is superseded.
- Follow-up action review was checked against live code rather than accepted as
  broad certification. Subtitle discovery now checks both Read and Execute for
  every traced path. Extraction checks replayed entry byte counts before file
  publication, checks TAR replay entry count, and admits the full preflighted
  expanded size against quota before creating destination directories. Cleanup
  of created ancestor directories was already present; ambiguous/partial
  mutation failures deliberately retain pending audit evidence.
- Fresh full Rust API validation passes **204 tests**, including **109
  McBrowser tests**; **1 unrelated manual Streaming browser fixture is ignored**.
  The new archive-focused suite passes **12 tests**, and workspace/tab/client
  keyboard integration passes **55 tests**. The final full frontend validation
  with all three supplied Rust Streaming fixtures passes **40 suites, 335 tests,
  no skips**. TypeScript and targeted lint pass with no errors or warnings.
  Production static export passes, including `/share`; the existing static-export
  rewrites warning remains expected. Logs are `/tmp/mcbrowser-current-full-api-v3.log`
  and `/tmp/mcbrowser-keyboard-final-{all,typecheck,lint,build}.log`.
- This remains partial native parity. Real-browser transport/restart/resource
  acceptance, localization/mobile equivalence and remaining inventory gates
  are not waived. No Streaming code or production/deployment state was changed.

## November 2 resumed integration verification

- The delivered standalone native-action and admin audit/queue interfaces are
  mounted in the workspace/tab. A fresh TypeScript check passes, and all
  **18 focused McBrowser/public-share suites, 213 tests** pass.
- The fresh mounted backend gate currently fails compilation in the concurrent
  upload/share audit integration: persisted audit IDs must be strings extracted
  from `PendingAuditIntent.event.event_id`, not the intent object itself. The
  responsible owner is repairing these APIs; the earlier 103-test checkpoint
  does not certify the current backend tree. No Streaming files were changed.

## November 2 native actions, audit hooks and rich editor integration

- Mounted locally bundled Ace (46 modes, 17 themes), isolated Markdown/KaTeX
  rendering and HTML/MathML sanitization in the real workspace. Removed the
  production-global sanitizer test override; tests mock the imported renderer.
  Dirty-close/reload confirmation, unload protection, ETags and duplicate-save
  protection use the mounted editor.
- Mounted the closed native action dispatcher and typed audit-event router.
  Execute is a separate default-off policy flag; host commands, processes and
  arbitrary outbound hooks remain unavailable. The workspace exposes all four
  actions, and admins can open audit/settings/queue UI. Both persistent archive
  creation and attachment download offer nine codecs.
- Pending audit intents precede folder creation, raw upload publication, file
  creation/save, copy/move, recursive/nonrecursive deletion and archive actions.
  Completion records allocated destinations and byte deltas. Post-publication
  audit failure retains pending evidence rather than pretending rollback.
  Upload/share durable-recovery wiring is being completed independently and is
  not certified by these handler changes.
- Independent action review identified ZIP preflight and rollback issues.
  ZIP preflight now decompresses and CRC-checks every entry under byte/ratio/time
  bounds before creating destination directories. Cleanup releases at most
  confirmed removed reserved bytes. Failed parent creation cleans successfully
  created ancestors. Metadata opens enforce Execute on the actual descriptor
  trace; action errors are no-store, and TAR replay rechecks count/raw paths.
- A parent mounted McBrowser run passed **103 tests**, including corrupt-ZIP
  preflight, rollback accounting and action/audit publication regressions.
  Subsequent backend reruns encountered concurrent Streaming portability test
  and upload audit compilation changes; 103 is a checkpoint, not certification
  of later edits. `af-files` independently passes **29 tests**.
- Frontend production static export passes, including `/share`. Workspace/tab
  integration suites pass **39 tests**. The full integrated frontend gate passes
  **40 suites, 327 tests**, with **2 skipped tests** (not accepted as passing).
  Media delivery, follow-up audits and real-browser/restart/resource-exhaustion
  acceptance remain open. No deployment, service, commit or branch was changed.

## November 2 safe-action policy prerequisite

- The mandatory safe native action design requires an explicit `execute` gate;
  rejecting the field entirely is not an implementation of that workflow.
  Policy persistence and admin controls now accept a boolean `execute`, default
  it to false for new and legacy policies, and migrate existing SQLite rows with
  `perm_execute INTEGER NOT NULL DEFAULT 0` without changing existing flags or scope.
- This flag authorizes only the forthcoming closed enum of in-process file
  actions. It does not enable shell commands, arbitrary binaries, or the
  upstream WebSocket command runner. Action-specific Read/Create/Download checks
  remain required in addition to Execute. The handlers and event integration
  are still open gates, not certified by this policy prerequisite.
- Admin quick presets leave safe actions disabled; enabling them requires
  explicit selection. Unknown permission keys (including `shell`) remain rejected
  by the backend. Added regressions cover legacy JSON/schema migration, default
  denial, admin-only opt-in, denied paths, plugin identities, and suspended users.
- TypeScript checking and the two policy frontend suites pass (10 tests).
  Current Rust test execution is blocked by concurrent unresolved `r2d2` and
  `r2d2_sqlite` references in `streaming_import.rs`; streaming files were not modified.

## November 2 host-listing metadata disclosure repair

- Confirmed the legacy host filesystem picker was authenticated but not
  admin-scoped: its broad host allowlist let ordinary users enumerate private
  service/backup directory metadata readable by the API process. Directory mode
  `0700` does not separate remote tenants sharing that process identity.
- All four versioned/compatibility picker routes now require an active live-DB
  human admin before filesystem probing. DB failures deny access, and blocking
  authorization/listing runs off the async runtime with the connection released
  before filesystem work. Ordinary McBrowser tenant listings are unchanged.
- A mounted regression passes for unauthenticated/non-admin requests to parent,
  private backup, symlink alias and nonexistent paths through every route alias;
  it also checks admin compatibility, suspended-admin denial, tenant listing
  availability and unchanged private backup bytes. No streaming module or
  production/deployment state was modified.

## November 2 editor bounds and lifecycle review

- Verified pinned `files/file.go:265` permits 10 MiB text files. The native
  editor now uses this decoded limit rather than 2 MiB; its JSON bound allows
  six bytes per decoded byte. Focused tests pass for the exact multibyte UTF-8
  boundary, mounted 10 MiB content with sixfold JSON escaping, and rejection
  above the decoded limit without changing quota or published data.
- Independent lifecycle review confirmed the transaction/stripe/storage design.
  Follow-up fixes normalize quota status, prevent a suspended/plugin admin row
  from defeating last-usable-admin protection, and require live owners for
  OIDC access-token introspection and WebSocket ticket consumption. Nine focused
  lifecycle-related tests pass, including new deleted-owner and DB-error checks.
- Syntax editor/Markdown/KaTeX UI work is delegated separately; installing its
  local dependencies does not certify UI parity. Offline OIDC relying parties,
  already-established sockets, physical storage purge, and browser/restart
  acceptance remain explicit gates.

## November 2 account lifecycle continuation

- Account deletion now holds the target user's owned mutation stripe throughout
  a blocking worker and one immediate SQLite transaction. It verifies the caller's
  live admin role and lifecycle, protects the last admin, and atomically removes
  account credentials, McBrowser metadata, quota and identity. Cleanup errors
  roll back earlier deletions instead of reporting success after ignored errors.
- Four focused lifecycle tests pass, covering optional-table absence, user
  isolation, AUTOINCREMENT identities, live authorization and trigger-induced
  rollback. A mounted DELETE route test passes with the single-connection pool,
  verifies serialization against a held mutation stripe, then checks old JWT,
  public share and resumable session rejection.
- Disk files and private upload staging deliberately remain, matching the pinned
  upstream account-delete behavior. The mounted test checks this retention;
  operational retention/purge and reconciliation remain release gates.
- Live copy/move conflict controls were delivered with four frontend suites
  (70 tests) and a passing TypeScript check, as reported by the implementation
  teammate. Independent lifecycle and intermediate-hop reviews remain ongoing.

## November 2 mounted continuation

This checkpoint supersedes earlier unmounted-code and three-request observations,
not the outstanding full-parity acceptance gates.

- Reproduced an authorization bypass: `folder-link -> docs`,
  `docs/secret-link -> ../secret-public.txt`, and a deny on `docs/secret-link`
  still allowed direct alias preview (HTTP 200). Final-target-only policy checks
  were insufficient even though the kernel filesystem capability stayed confined.
- Resolved capabilities now carry the normalized full remaining path at each
  symlink expansion. File reads, directory listing, link metadata enrichment and
  rename target checks authorize this trace plus the final target. Directory
  listing retains ancestor traversal for explicitly allowed descendant carveouts.
  Mounted regressions now deny the chained alias, a hop through a denied directory,
  and a directory-target hop while preserving allowed descendant access.
- Mounted the copy/move implementation through the existing rename route using
  one SQLite connection and one scoped filesystem. Error/overwrite/keep-both
  requests return the actual destination; mounted tests verify default refusal,
  versioned names and exact overwritten-byte quota release. Live workspace
  conflict controls are a separate integration task, not inferred from this test.
- Search now follows pinned `conditions.go`/`search.go`: case modifiers,
  MIME/extension types, OR terms/types, quoted phrase and filename-only matching.
  Removed a previous test expectation that incorrectly matched parent directory
  names. `case:exact` and special `type:doc`/`type:archive` categories were not
  present upstream; the acceptance specification now states the actual semantics.
- Upload concurrency now defaults to and caps at five. Confirmed-byte aggregate
  progress, active speed and ETA exclude skipped uploads. Directory links sort
  with folders and display no file byte size; rename/delete dialogs say Link.
- Verification: **75 mounted Rust McBrowser tests pass**, including the new
  hop/copy/move/search regressions (`/tmp/mcbrowser-hops-conflicts-mounted.log`).
  **150 tests across ten stable frontend suites pass**
  (`/tmp/mcbrowser-hops-stable-client.log`). Full TypeScript checking and the four
  parent-edited upload/tab files' ESLint pass. A subsequent full frontend run with
  Streaming's exported fixture passes **30 suites / 255 tests**
  (`/tmp/af-full-frontend-mcbrowser-fixed.log`); filesystem tests pass **29 tests**
  (`/tmp/mcbrowser-trace-files-parent.log`). These are not full build/browser
  acceptance or proof that all media workflows are equivalent.
- A fresh independent hop-trace review is running. Remaining release gates still
  include rich media acceptance, broader alias operations, safe actions/hooks,
  account/storage cleanup, localization/a11y, production build and real
  network-loss/restart/large-file browser exercises.

Date: November 1, 2026. This checkpoint does **not** certify feature parity or production readiness.

Baseline: upstream McBrowser commit `833d908884d5c801f30f5c098d7977177eb3a36b`.
The parity inventory and acceptance specification remain the requirements, not the current test count.

## Confirmed integration defects and repairs

| Area | Evidence and cause | Repair | Verification |
| --- | --- | --- | --- |
| PATCH CSRF | `auth::csrf_middleware` only checked POST, PUT and DELETE, leaving TUS PATCH outside double-submit validation. | Include PATCH in the protected methods. Extend both-version route-authentication and mutation-CSRF coverage. | Rust execution pending the concurrent backend modules compiling. |
| Single-connection SQLite pool | `af_db::init_db` configures `max_size(1)`. Scoped filesystem opening previously acquired another connection even when the caller already held one. Legacy upload publication also called global policy/quota helpers while retaining its initial connection. | Add `open_configured_user_browser_fs_with_conn`; reuse the caller connection for delete and initial upload scope checks. Release the connection before receiving network bytes; reacquire one for same-connection publication authorization and quota updates. | New mounted HTTP regressions cover upload/delete, scoped copy/editor/recursive delete, and cancelled-body cleanup. Their execution is pending backend compilation. Operations and policy sibling handlers also need the same-connection contract. |
| Explicit raw-upload failure cleanup | A stream error returned before the blocking worker finished dropping its staging capability and mutation lock. | Close the channel and await worker termination before returning an observed stream error. Request-future cancellation still relies on channel closure and worker-owned cleanup. | Cancelled-body regression added; Rust execution pending. |
| Queue lifecycle | Starting another attempt before the old controller settled could corrupt the same queue entry. A shared directory request could also keep an individually cancelled entry waiting. | Keep transitional states, block retry/reselection until cancellation is confirmed, preserve resume intent until the old transport settles, and interrupt only the item's shared-directory wait rather than the underlying shared request. | Focused queue and tab suites pass. |
| Public file downloads | `downloadPublicShareFile` called `Response.blob()`, buffering the complete shared file before saving. | Plain-fetch HEAD preflight with the same scoped cookie used by native anchor GET. No Blob/object URL and no unlock secret in a query string. | Public client/page and AuthGuard suites pass; native large-file browser acceptance remains pending. |

## Audit claims requiring correction

Independent findings are leads, not automatically accepted facts. Source inspection rejected these portions of the latest review:

- The share password implementation is bcrypt, not Argon2id. Password unlock already has failed-attempt throttling, and public handlers reject secret query parameters. Do not add a duplicate password transport based on the review's obsolete description.
- Thumbnail lookup is keyed by user/path/size **and** validates device, inode, byte length and nanosecond modification time against the currently opened file. A missing textual scope in the key alone does not demonstrate a stale cross-scope hit.
- The live rename endpoint is `POST /mcbrowser/rename`, not the review's `PATCH /mcbrowser/entry`. The PATCH CSRF finding is nevertheless real for resumable uploads.
- Retrying an entry while its controller remains live is already guarded. The remaining shared-directory wait and resume-intent problems were repaired separately rather than reverting those guards.

## Actual verification at this checkpoint

The following five suites passed together, **75 tests total**:

- `frontend/src/lib/mcbrowser-uploads.test.ts`
- `frontend/src/components/tabs/McBrowserTab.test.tsx`
- `frontend/src/lib/mcbrowser-share.test.ts`
- `frontend/src/app/share/page.test.tsx`
- `frontend/src/components/layout/AuthGuard.test.tsx`

Runner: cached Node 22.20.0 and the temporary CJS Jest configuration at `/tmp/jest.network.cjs`.
This validates the tested client contracts and state transitions, not the live Rust routes or browser-native download completion.

The attempted mounted Rust HTTP test build encountered in-progress compile errors in sibling upload and archive modules. It is **not** a passing backend test run. Full TypeScript, production build/static export, all mounted backend tests, and end-to-end acceptance still require reruns after integration stabilizes.

## Remaining release gates

- Complete and test durable TUS publication, scope/inode binding, and original upload conflict workflows.
- Compile every mounted sub-router and prove no nested SQLite checkout remains.
- Complete archive codec/ZIP64 support, native archive tickets, copy/move conflict handling, and media UI integration.
- Finish persisted preferences and admin policy management; ensure the primary tab does not present unauthorized actions as available.
- Finish safe internal-symlink workflows and account/storage lifecycle handling without weakening confinement.
- Reconcile the complete source-pinned inventory, including safe command/action behavior, against executable acceptance evidence.
- Run a fresh independent review after repairs land; do not count a completed agent without a result as an audit.

## November 1 integration continuation

- The primary tab now receives loaded permissions from the workspace through a stable callback. Both views default to denied permissions while policy is unavailable; primary upload, folder creation, rename, delete, preview, and download actions honor those flags. Handler guards also reject disabled mutations and dropped uploads.
- Supported image, video, audio, PDF, CSV, and EPUB entries now open the rich media component from the primary tab; unsupported entries retain the bounded UTF-8 reader. The tab passes permissions and closes media state on session reset. This establishes mounting, not a claim that every media format has passed end-to-end acceptance.
- Added regressions for denied-policy controls, failed policy loads, blocked drag-and-drop, and routing image previews away from the text reader. The nine stable frontend suites pass together: **136 tests**. Full frontend TypeScript checking passes. The three edited tab/workspace files pass ESLint without errors or warnings. The capability filesystem suite passes **21 tests**.
- Added mature image and ZIP libraries and streaming archive codec dependencies to the Rust workspace and API crate. Registry resolution and fetching succeeded. Real image pixels and archive round trips must still be verified in the owning modules; adding dependencies alone does not satisfy these gates.
- The latest attempted mounted HTTP build still fails on four in-progress archive-module errors: missing ticket handlers, incomplete info response fields, and an incomplete archive-format match. Consequently the mounted HTTP regressions remain **unverified**, not passing.
- The preferences teammate disconnected after partial edits. Admin policy management is assigned separately; its eventual result must be mounted and verified before claiming that workflow complete.

## November 1 mounted validation update

This newer checkpoint supersedes the earlier compilation-blocked observations above, without certifying full parity.

- The mounted Rust McBrowser suite now passes: **63 passed, 0 failed**, including HTTP authentication/CSRF, scoped single-connection operations, archive codecs/tickets, shares, policy, and 16 upload tests. Command: `cargo test -p af-api mcbrowser:: --offline --manifest-path backend-rs/Cargo.toml -- --test-threads=1`; output: `/tmp/mcbrowser-mounted-current-rust.log`.
- Upload replacement reserves net growth, preserves existing files on cancellation, and atomically combines shrink quota release with the completed-row transition. Crash recovery tests prove repeated HEAD reconciliation cannot release shrink quota twice. Explicit overwrite/skip/resume client choices are bound to session conflict metadata; skipped files are not counted as uploaded.
- Upload response paths now prefer base64 metadata over whitespace-trimmed HTTP path headers. Regressions cover filenames with significant leading/trailing spaces and rejection of unknown server conflict modes.
- Admin policy management is mounted only after activation for authenticated admins. Saving the current user's policy disposes uploads, clears directory/preview state, and remounts the workspace so an old scope is not reused. The UI regression covers admin/member gating and self-policy reload.
- Ten stable frontend suites pass together: **146 tests**, output `/tmp/mcbrowser-stable-current-client-tests.log`. Full frontend TypeScript checking passes, and the four parent-edited upload/tab files pass ESLint. A combined run including the two in-progress media suites was terminated after over 110 seconds of high CPU with no output; those suites are not certified by the stable result, and their owner was notified.
- Capability filesystem tests pass: **26 tests**. Independent review identified inaccurate symlink metadata classification for redundant separators and an inconsistent strict-parent opener; both were repaired and regression-tested. Review assertions about hardlink bypass were not demonstrated: existing hardlink checks remain enforced. Opening host-created device nodes before type rejection remains a follow-up defense-in-depth concern; host filesystem writers are trusted, and no client device-creation endpoint exists.
- Internal-link APIs still require careful alias-and-resolved-target policy authorization when mounted. Copy/move conflict modes, media completion, account/storage lifecycle, safe action/hook parity, production build, and real browser/restart acceptance remain open gates.

## Confined link integration checkpoint

- Primary directory listing, bounded text preview, and downloads now use confined internal-link capabilities when strict opening encounters a link. File reads authorize both the user-requested alias and the proven root-relative target on the same SQLite connection. Listing authorizes both directory paths, filters children against alias and canonical rules, and returns alias-relative paths so navigation stays consistent.
- Entries retain `kind: symlink`. Optional `target_kind` is emitted only for an allowed, successfully confined file/directory target. Broken, looping, out-of-scope, and policy-denied targets receive no openable target kind. Client activation and preview/download controls use that field; unresolved links remain non-openable.
- Rename and delete now use leaf-link primitives: the link itself is changed/unlinked, strict parent confinement is preserved, and quota release is zero for symlink entries. The UI explicitly states link-only mutation semantics. Mutations through symlinked parent directories, copy/archive/share/editor/media alias parity, and host-device metadata hardening are still follow-up work, not implicitly certified by this checkpoint.
- A new mounted HTTP regression covers allowed alias navigation, hidden canonical descendants, independently denied aliases and targets, external/broken/loop rejection, safe external-link rename/unlink, unchanged file quota, and `..` escape rejection after remapping the user's effective scope. The full mounted McBrowser suite now passes **64 tests** (`/tmp/mcbrowser-symlink-mounted-rust.log`). Focused utility/tab tests pass **47 tests** (`/tmp/mcbrowser-symlink-client.log`).
