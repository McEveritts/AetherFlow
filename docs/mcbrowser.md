# Native McBrowser

McBrowser is a core AetherFlow dashboard tab in the left sidebar, backed by the
Rust API and the `af-files` crate. It is a new implementation, not a translation
of the legacy Go/Vue application. It needs no iframe, separate daemon, container,
extra login, or Marketplace installation. The dashboard uses its existing React
frontend; the filesystem and HTTP backend are Rust.

## Parity target

Full upstream feature parity is the acceptance target, not the current status.
See [the pinned feature inventory and release gate](./mcbrowser-parity.md) for
remaining requirements. The current implementation must not be advertised as full
parity until those gates pass or differences are explicitly approved.

## Implemented workflows — November 2, 2026

- Private browsing, breadcrumbs, search, sorting, list/grid views, persisted owner
  preferences, quota usage, and admin-managed operation permissions/path rules.
- Recursive copy/delete, move/rename, file creation, and bounded UTF-8 editing
  with ETag conflict detection. Copy/move accept explicit error, overwrite, and
  keep-both policies; allocated names are returned by the API. Workspace conflict
  controls are mounted. Same-folder keep-both copy/move allocates a distinct
  versioned destination without permitting same-path overwrite.
- Focused workspace shortcuts support Ctrl/Command A/C/X/V/S, Shift-F search,
  Escape, Delete confirmation and F2 rename. Shift-click checkbox selection
  extends the displayed range. Internal clipboard snapshots survive folder
  navigation, paste opens the conflict/confirmation dialog, and successful cut
  items are removed from the clipboard. Inputs, editable content and open dialogs
  do not trigger explorer shortcuts. These are not system-clipboard operations.
- An appendable resumable upload queue with a five-request client concurrency
  ceiling, confirmed-byte progress, aggregate speed/ETA, pause/resume, explicit
  cancellation verification, and overwrite/skip/resume choices. Queue retention
  is bounded to 1,000 entries / 16 GiB; the resumable server default per-file limit
  is 64 GiB, configurable with `AF_MCBROWSER_MAX_UPLOAD_BYTES`. PATCH chunks are
  bounded to 4 MiB. The legacy raw upload remains capped at 64 MiB.
- Recursive directory drag-and-drop preserves empty folders. Standard browser
  folder pickers expose files only and cannot represent empty folders. Batches
  are not atomic: published files and created parents survive other failures.
- Uploads continue across sidebar switches. Reload loses browser File handles;
  reselecting the same file can recover a matching durable session. Logout/account
  changes abort and dispose local state. Uncertain publication is never blindly
  retried, and cancelling a request does not promise rollback.
- Native attachment navigation for individual downloads and ticket-authorized
  streamed archives, avoiding full-file JavaScript Blob buffering. Public shares
  support password unlock, expiry, revocation, scoped folder browsing and downloads.
- Text previews are literal UTF-8, capped at 256 KiB. Rich media and document
  previews have separate bounded endpoints/components and remain under acceptance.
- Directory listing and recursive traversal are bounded to 10,000 entries.
- UTF-8 content editing accepts up to 10 MiB of decoded text, matching the pinned
  source. Its JSON body bound allows sixfold escaping without shrinking that
  decoded limit. Four editor requests may parse/process concurrently; additional
  requests receive `429 EDITOR_BUSY` with `Retry-After: 1` before body parsing.
- The mounted editor bundles Ace locally with syntax modes, themes, search,
  undo/redo and safe Markdown/KaTeX preview. Dirty-close/reload confirmation and
  an unload warning protect unsaved content; ETags protect concurrent saves.
- Safe Built-In Actions expose checksums, bounded archive extraction, persistent
  archive creation in nine formats, and media metadata inspection. They require
  explicit admin opt-in to default-off Execute plus corresponding file
  permissions. Execute never enables host shells or arbitrary programs.
- Admins can inspect typed mutation audit records and control/acknowledge the
  optional internal event queue. Audit recording is mandatory regardless of
  queue enablement. No outbound webhook or command runner is provided.

This remains a **partial native implementation**, not a full-parity certification.
Outstanding gates include intermediate-link policy verification, broader alias
workflows, media/browser acceptance, completion of all audit recovery hooks, lifecycle
acceptance, localization/accessibility, production build and restart/crash exercises.
See the integration audit for checkpoint-specific evidence rather than inferring
that a mounted module satisfies every upstream edge case.

### Account deletion and storage retention

Admin account deletion serializes with the target user's McBrowser mutations and
uses one immediate SQLite transaction for live admin/lifecycle checks, last-admin
protection, session/OIDC credential removal, McBrowser policy/preferences/share/
upload metadata cleanup, and quota/user removal. A database error rolls back the
entire deletion; a missing optional McBrowser table does not prevent deletion.
Existing audit history is retained.

Last-admin protection counts remaining usable non-plugin admin accounts rather
than allowing a suspended/plugin admin row to strand administration. Existing
OIDC access-token introspection and new WebSocket upgrades also check that the
token/ticket owner still exists. This does not recall offline-validated OIDC
tokens at third-party services or terminate already-established WebSocket
connections; those platform-wide revocation semantics need separate acceptance.

As in the pinned upstream account deletion workflow, deleting an account does
**not** delete its filesystem data. Published files and private resumable-upload
staging files remain for operator-managed retention, backup and eventual purge.
They become inaccessible through the deleted identity; old public shares and
upload sessions no longer resolve. AUTOINCREMENT IDs must not be manually reused
or reset, and an operator purge must target the verified retired user's storage,
never a path supplied by a client. Physical purge and retention automation remain
separate operational acceptance gates.

### Host filesystem path-picker policy

The legacy absolute-host-path picker (`/api/v1/auth/fs`, `/api/auth/fs`,
`/api/v1/fs` and `/api/fs`) is restricted to active, live-database admin
accounts. Ordinary users and plugin identities are rejected before filesystem
existence checks, canonicalization or directory enumeration. An allowed-root
configuration does not grant ordinary users access to host listings.

This prevents service-data and private backup names, sizes, timestamps and
directory structure from leaking through a process that can read those paths,
even when the on-disk directory is mode `0700`. Admin host-path selection still
uses `AF_ALLOWED_FS_ROOTS`; ordinary user file browsing uses the separate,
tenant- and policy-confined McBrowser API. No service or backup files are moved
or modified by this policy change.

## Storage and deployment

`AF_MCBROWSER_ROOT` defaults to `/var/lib/aetherflow/mcbrowser`. Use a dedicated
absolute directory owned by the API service UID. The API provisions and enforces
mode `0700` on this directory and its `user-{application_user_id}` children.
Application IDs are SQLite identities, not POSIX usernames. Do not point this
setting at an existing general-purpose directory: its permissions will be changed.
The filesystem root `/` is rejected. Ancestors of the configured root are trusted
administrator-controlled deployment configuration and must not be writable or
replaceable by untrusted users. Existing base and child directories must be owned
by the effective API UID; symlink roots are rejected.

The default location sits inside the existing systemd StateDirectory. A custom
location additionally needs writable access under the API unit sandbox and any
applicable host security policy. Keep using the existing native systemd and
Apache deployment; no additional listening service is introduced. Rebuild the
frontend and Rust API using the existing release process to ship the tab.

The filesystem implementation currently requires Linux and a filesystem supporting
atomic `renameat2(RENAME_NOREPLACE)`. Upload publication and rename fail closed if
that operation is unsupported; no unsafe check-then-overwrite fallback is used.

## Security and accounting

Authenticated endpoints inherit AetherFlow authentication and cookie CSRF protection.
Public share endpoints instead enforce the share's own access controls and owner lifecycle.
Plugin-scoped tokens are explicitly denied, including wildcard plugin tokens.
Each user receives a directory capability; operations resolve relative paths
using descriptor-confined capabilities. Absolute paths, traversal segments, NULs, backslashes,
and reserved `.af-upload-tmp.*` names are rejected. Paths are bounded to 4,096
bytes, 64 components, and 255 bytes per component. Opt-in reads resolve internal
symlinks with Linux `openat2` confinement and target identity verification;
strict mutation parents still reject symlinks. Leaf-link rename/delete affect
the link itself, not its target, with zero released regular-file bytes. Full
alias-policy acceptance remains a release blocker. Special files are unsupported.
Reading and deleting multiply hardlinked
files is denied. Private directories must not be modified by other processes.

Mutations serialize per lock stripe, and blocking mutation work retains its lock
even if the HTTP request is cancelled. Uploads stage into exclusive mode-0600
temporary files, enforce the existing database quota, reserve the exact byte count
atomically before publication, and preserve a 1 GiB free-space floor at admission
(using the maximum upload size when Content-Length is absent). This is an admission
check, not a global disk-space reservation across simultaneous users or services.

Quota reads fail closed on database errors and suspended accounts. A missing
quota record follows existing unlimited-quota semantics. Successful deletion
releases the recorded bytes. A crash between quota reservation and publication,
or a failed post-delete accounting update, can leave conservative over-accounting.
After atomic publication, a directory-fsync failure is logged rather than reported
as an unpublished upload; crash durability may be reduced in that case.

Resumable sessions persist scope/root identity and publication state. Expiry and
explicit cancellation reconcile durable sessions conservatively, releasing quota
only when unpublished staging is proven intact. This is not a general storage
reconciliation daemon: crashes can still leave conservative accounting, and raw
upload staging has no equivalent durable session recovery. Operators
must stop active writers before investigating staging files or reconciling usage;
never delete temporary files based solely on their age while uploads are active.
Back up user storage together with SQLite quota records. Out-of-band file copies
and deletes bypass accounting and require operator reconciliation.

## API contract

The canonical prefix is `/api/v1/auth/mcbrowser`; `/api/auth/mcbrowser` remains
available through the existing legacy router. Root is the empty relative path.

| Method | Suffix | Request | Result |
| --- | --- | --- | --- |
| GET | `/entries?path=...` | Relative directory | `{ path, entries, max_upload_bytes }` |
| POST | `/directory` | JSON `{ path, parents?: boolean }` | 201 `{ success: true }` |
| POST | `/rename` | JSON `{ from, to, conflict?: "error"\|"overwrite"\|"keep-both" }` | 200 `{ success, path, from, to }` |
| DELETE | `/entry?path=...` | Relative entry | 200 `{ success: true }` |
| PUT | `/upload?path=...` | Raw file body | 201 `{ success: true }` |
| GET | `/download?path=...` | Optional single Range header | Attachment stream, 200 or 206 |
| GET | `/preview?path=...` | Relative file | `{ path, content, truncated }` |
| POST/GET | `/uploads` | TUS-style metadata / discovery | Durable scoped upload sessions |
| HEAD/PATCH/DELETE | `/uploads/:id` | Offset / bounded chunk / cancellation | Confirmed offset or terminal state |
| POST | `/copy` | Same conflict fields as rename | Actual published destination |
| POST | `/delete-recursive` | JSON `{ path }` | Removed tree with quota accounting |
| POST | `/file` | JSON `{ path, content? }` | New file |
| GET/PUT | `/content?path=...` | UTF-8 content / ETag | Bounded editor read/save |
| GET | `/info?path=...&checksum=...` | Relative path, optional algorithms | Metadata, counts and checksums |
| POST | `/archive-ticket` | Selection and format | Ticket for native archive navigation |
| GET | `/policy`, `/preferences`, `/usage` | Owner metadata | Permissions/preferences/quota |
| GET/PUT | `/policy/:user_id` | Live-DB admin target policy | Validated target policy |
| GET/POST/DELETE | `/shares`, `/shares/:id` | Owner link management | Scoped share creation/list/revocation |

Each entry contains `name`, `path`, `kind`, `size`, and nullable RFC3339 `modified`.
Errors use `{ code, message }` without exposing host paths. The client uses the
existing authenticated fetch helper and never adds authentication tokens to URLs.

`parents` defaults to false, preserving normal single-folder create/conflict
behavior. The batch helper opts into `parents: true` for idempotent nested
creation. Both forms use the same authentication, CSRF, quota-status checks and
owned mutation lock. Parent directories can remain after cancelled/failed uploads.
