# McBrowser feature-parity release gate

## Baseline and verdict

The reference is `McEveritts/McBrowser` commit
`833d908884d5c801f30f5c098d7977177eb3a36b`. The local source audit used
`/tmp/McBrowser-rust-assessment`; `git ls-remote ... HEAD` matched that commit on
November 1, 2026. Original evidence paths below are relative to that repository;
native paths refer to this AetherFlow checkout.

**Full feature parity is NOT achieved.** This inventory is an acceptance backlog,
not a parity certification. Passing the current implementation tests proves only
the covered subset. Do not advertise this release as a complete replacement yet.

The user-selected architecture is a Rust backend baked into AetherFlow, using its
existing React dashboard and account system. Go/Vue translation, an external
iframe/service, standalone login/database duplication, and Docker packaging are
not the target. Replacing those mechanisms does not waive user-facing features.

## Feature inventory

`Covered` means implemented and tested in the current subset, not an assertion
that every upstream edge case has been reproduced. `Partial` and `Missing` both
block full parity. `Replacement` requires equivalence acceptance, not merely a
similarly named platform feature.

| Capability | Native state | Original evidence | Remaining acceptance requirement |
| --- | --- | --- | --- |
| Private user-scoped filesystem | Partial | `users/users.go`, `rules/`, `http/resource.go` | Descriptor-confined SQLite-ID roots, relative admin scopes and ordered prefix/regex rules are mounted. Scope migration/lifecycle and alias edge cases remain release gates. |
| Login/session/account administration | Replacement | `auth/`, `http/auth.go`, `http/users.go`, `cmd/users.go` | Reuse AetherFlow identities; verify role/lifecycle and access revocation across file operations. |
| Per-operation file permissions | Partial | `users/permissions.go` | Seven file-operation flags plus a separate default-off Execute gate for closed native actions and live-DB admin editing are mounted. Continue descendant, alias, lifecycle and UI enforcement acceptance. |
| Browse, breadcrumbs, sorting, metadata | Partial | `http/resource.go`, `frontend/src/views/files/FileListing.vue`, `frontend/src/components/Breadcrumbs.vue` | Current table works; listing scale limit, metadata, and preference equivalence need acceptance. |
| Grid/gallery and persisted preferences | Partial | `users/users.go`, `frontend/src/views/files/FileListing.vue` | Persisted list/grid/gallery, hidden-file, click, sorting/date, locale and editor-theme settings are mounted. Workspace selection/range and copy/cut/paste/search/download/rename/delete shortcuts have component coverage; broader keyboard/mobile/browser equivalence needs acceptance. |
| Recursive listing and search | Partial | `http/http.go`, `http/search.go`, `search/` | Bounded subtree search is mounted. Source-exact case/type/OR-term modifiers are integrated but full mounted acceptance is pending. |
| Multiple-file upload selection | Covered | `frontend/src/components/prompts/UploadFiles.vue`, `frontend/src/stores/upload.ts` | Current appendable queue is tested; broader upload parity remains partial below. |
| Batch queue, cancellation and retry | Partial | `frontend/src/stores/upload.ts`, `frontend/src/api/tus.ts` | Five-request client ceiling, pause/resume, confirmed progress, per-file results and conservative publication uncertainty handling exist. Real HTTP subprocess tests cover stalled-body concurrency and two crash/restart cycles; browser queue/reload acceptance remains pending. |
| Folder picker preserving hierarchy | Partial | `frontend/src/components/prompts/UploadFiles.vue`, `http/resource.go` | Picker paths and confined parent creation work; browser pickers expose no empty-directory objects. Empty folders are handled by recursive drop instead. |
| Folder drag-and-drop traversal | Partial | `frontend/src/utils/upload.ts` | Recursive webkitGetAsEntry traversal, repeated readEntries batches and empty-directory queueing are tested; real-browser acceptance remains. |
| Large/chunked/resumable uploads | Partial | `http/tus_handlers.go`, `frontend/src/api/tus.ts` | Durable TUS-style sessions, offsets, scope/inode binding and nonce-bound publication journals are mounted; identical content is not publication evidence. Actual HTTP tests cover a 2 MiB upload, partial-body process crash, fingerprint discovery, durable-offset resume, lost completion ACK, restart, exact download/Range, quota and audit idempotency. Missing proof and unsupported-xattr prepared crashes retain session/quota pending operator recovery. Independent proof review, large-file/browser and disk-exhaustion acceptance remain open. |
| Upload byte progress and speed | Partial | `frontend/src/stores/upload.ts`, `frontend/src/api/tus.ts` | Confirmed-byte per-item/aggregate progress, speed and ETA are implemented; skipped items are excluded. Real transport/UI acceptance remains. |
| Conflict resolution | Partial | `frontend/src/components/prompts/ResolveConflict.vue`, `http/resource.go` | Upload overwrite/skip/resume and copy/move overwrite/keep-both are distinct workflows. Backend quota-aware policies and live copy/move conflict controls are mounted; directory/partial-failure and real-browser acceptance remain. |
| New folder | Covered | `frontend/src/components/prompts/NewDir.vue`, `http/resource.go` | Single-folder creation plus opt-in idempotent parent creation are implemented. |
| Rename and move | Partial | `frontend/src/components/prompts/Rename.vue`, `frontend/src/components/prompts/Move.vue`, `http/resource.go` | Batch move and single-connection conflict-aware rename are mounted. Destination conflict controls and alias-parent mutations need acceptance. |
| Copy | Partial / implementation review in progress | `frontend/src/components/prompts/Copy.vue`, `fileutils/copy.go`, `fileutils/copy_test.go:99` (`TestCopyAllowsInScopeSymlink`), `http/resource.go` | Source-pinned confined alias and recursive-directory copy implementation is in the working tree with quota-aware conflict policies and every-hop permission checks. Current combined tests pass, but the replacement implementation teammate's final verification and independent review are outstanding. Directory merge/partial failure semantics and real-browser controls still need acceptance. |
| Recursive delete and bulk selection | Partial | `frontend/src/components/prompts/Delete.vue`, `frontend/src/views/files/FileListing.vue`, `http/resource.go` | Multi-select and bounded recursive removal release actual removed bytes, including partial errors; link/workspace and lifecycle acceptance remain. |
| New file and text/code editing | Partial | `frontend/src/components/prompts/NewFile.vue`, `frontend/src/views/files/Editor.vue`, `http/resource.go` | File creation, bounded UTF-8 ETag editing (including confined file aliases with pinned-target replacement), local Ace modes/themes and sanitized Markdown/KaTeX are mounted. Alias controls cover list/grid/gallery/mosaic; tests and production build pass. Independent alias-editor review and broader editor/browser equivalence remain. |
| Single-file download | Partial | `http/raw.go`, `frontend/src/api/files.ts` | Rust Range streams and browser-native attachment navigation are implemented. Large-download/browser acceptance remains. |
| Folder/selection archive download | Partial | `http/raw.go`, `frontend/src/components/prompts/Download.vue` | Streaming production, nine formats, ticket navigation and confined file/directory alias sources are mounted. Source descriptors remain pinned after every-hop authorization, preserving alias names. Ticket creation and downloads share admission through blocking planning and encoding; planning has cooperative cancellation, a 30-second deadline and 10,000-entry bound. All-codec alias/ticket/action HTTP and planner regressions pass; independent resource-admission/race re-review and large actual browser downloads remain required. |
| Text preview | Partial | `frontend/src/views/files/Editor.vue`, `frontend/src/views/files/Preview.vue` | Current read-only UTF-8 modal stops at 256 KiB; it is not editor/viewer parity. |
| Media/document previews | Partial | `frontend/src/views/files/Preview.vue`, `frontend/src/components/files/CsvViewer.vue`, `http/preview.go`, `http/subtitle.go` | Rich preview endpoints/UI are mounted with bounded image/subtitle/document handling. Confined file aliases dispatch to rich viewers; mounted two-hop media tests enforce alias/intermediate/final policy and alias-preserving metadata. Independent re-review and browser acceptance are outstanding. |
| File checksums/info | Partial | `files/file.go` (`Checksum`), `frontend/src/components/prompts/Info.vue` | Streaming MD5/SHA1/SHA256/SHA512 and directory counts support confined aliases with every-hop policy filtering and alias-preserving responses; workspace inspection covers list/grid/gallery/mosaic. Dimensions and detailed info equivalence still need verification. |
| Public sharing | Partial / independent review pending | `http/share.go:158-168`, `http/public.go:58-76`, `share/`, `frontend/src/components/prompts/Share.vue` | Owner create/list/revoke and password/expiry-controlled public file/folder UI support confined alias roots and descendants, pinned root identity, every-hop owner policy revalidation and alias-preserving public paths. Descendant aliases cannot escape the public share's own subtree, matching upstream filesystem rebasing. Eleven backend share tests and four workspace-view alias-sharing regressions pass. Independent re-review and real-browser/abuse acceptance remain. |
| Storage usage display | Partial | `http/resource.go` (`diskUsage`), `frontend/src/components/Sidebar.vue` | Live usage display, fail-closed quota lifecycle and transactional account metadata cleanup are mounted. Retained storage/staging needs operator retention/purge and reconciliation acceptance. |
| Branding/localization/accessibility | Partial | `branding/`, `frontend/src/i18n/`, `frontend/src/components/settings/` | AetherFlow branding replaces standalone styling; feature UI localization and a11y/keyboard equivalence still need verification. |
| Shell/command actions and event hooks | Replacement / acceptance pending | `http/commands.go`, `runner/runner.go`, `cmd/root.go` | Closed in-process checksum/archive/media actions, default-off Execute, durable typed mutation intents and an optional internal queue are mounted with workspace/admin UI. Finish publication/recovery hooks and independent/browser acceptance; arbitrary host execution is not reproduced. |
| Symlink behavior | Partial / independent review pending | `users/users.go`, `settings/`, `http/resource.go` | Confined internal reads and leaf-link mutations are mounted. The reproduced intermediate-hop policy bypass is repaired with resolution trace checks and mounted regressions; independent re-review and broader alias workflows remain incomplete. Scope escape is never acceptable. |

Source path names must be checked against the pinned source when implementing a
row. This inventory groups related workflows; it is not a line-by-line Go API
compatibility promise. Existing generic AetherFlow File Share, user management,
or settings tabs do not automatically satisfy McBrowser-specific workflows.

## What the batch implementation guarantees now

Native evidence: `frontend/src/lib/mcbrowser-uploads.ts`,
`frontend/src/components/tabs/McBrowserTab.tsx`, `frontend/src/lib/mcbrowser.ts`,
`backend-rs/crates/af-api/src/mcbrowser.rs`, and `backend-rs/crates/af-files/src/lib.rs`.

- Append files while running; at most five client requests are active. Server
  mutations for the same user remain serialized for filesystem/quota safety.
- Preserve folder-picker relative paths; validate the whole destination before
  creating parents. Parent creation is capability-relative, idempotent and refuses
  symlink/file ancestors. The picker does not represent empty directories.
- Keep per-file states, stable IDs, explicit confirmed outcomes, and fixed target
  paths. Completed files are never re-sent by Retry. Queue admission is bounded to
  1,000 retained results / 16 GiB aggregate. The resumable server defaults to a
  configurable 64 GiB per-file cap; legacy raw requests remain capped at 64 MiB.
- Cancel queued work before sending. Interrupted in-flight requests are explicitly
  uncertain because the server may have committed; never promise rollback based
  on AbortSignal. Uncertain requests are not automatically retried.
- Continue across AetherFlow sidebar tab switches. Full-page navigation, refresh,
  logout or account changes dispose the in-memory queue. Durable session discovery
  can resume a reselected matching file; File handles themselves are not persisted.
  A before-unload warning guards active transfers.
- Recursive drag-and-drop records empty folders; standard folder-picker APIs do
  not expose them. Confirmed-byte progress, combined speed and ETA are shown;
  skipped uploads are not miscounted as transferred bytes.
- Batches are independent file requests, not an atomic all-or-nothing filesystem
  transaction. Successful files and created parent folders survive other failures.

Tests: `mcbrowser-uploads.test.ts`, `McBrowserTab.test.tsx`, `mcbrowser.test.ts`,
`af-files` tests and `mcbrowser` API tests. They cover the implementation, not all
unchecked upstream acceptance requirements.

## Full-parity acceptance gate

A full-parity release must satisfy every applicable inventory row and the
following conditions. Nothing below is waived merely because an MVP exists.

- [ ] Record each original workflow as executable acceptance cases against this
      pinned baseline, including empty directories, zero-byte files, Unicode,
      large files, conflicts, interrupted requests and account changes.
- [ ] Implement and test every Partial/Missing row, or obtain explicit approval
      for each user-facing behavior difference. Native replacements need review.
- [ ] Resolve command-hook/symlink security-sensitive behaviors with an approved
      native design rather than copying vulnerabilities or silently omitting them.
- [ ] Test cross-user isolation, per-operation permissions, shared-link access,
      quota admission/release, partial failures, crashes and disk exhaustion.
- [ ] Exercise batch/folder uploads and resume against the real Rust API in a
      browser, including network loss, reload/restart, cancellation, and races.
- [ ] Validate large downloads/archives and media previews without unbounded
      server/client buffering or executing untrusted HTML.
- [ ] Pass frontend production build, Rust tests, integration tests and relevant
      accessibility/mobile/browser checks; retain results with the release.
- [ ] Verify deployment configuration, backups, monitoring, quota/staging
      reconciliation and migration of existing McBrowser data/scopes.

Until these gates pass, release notes must say **partial native implementation**,
not **full McBrowser feature parity**.

## Validation snapshot — November 1, 2026

- Frontend focused Jest suites: **52 passed** across API helpers, the upload queue,
  and McBrowser component interactions.
- Rust `af-files` tests: **15 passed**, including nested parent creation,
  confinement, upload publication, hardlinks and concurrent root listings.
- Rust `af-api` McBrowser-filtered tests: **13 passed**, including authentication,
  CSRF, quota helpers, upload bounds, preview boundaries and cancellation locks.
- Frontend TypeScript and production `next build`: **passed**.
- No deployment or real-browser end-to-end/resume certification was performed.

These are subset checks, not completion of the full-parity acceptance gate above.
