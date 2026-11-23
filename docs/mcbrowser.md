# Native McBrowser

McBrowser is a core AetherFlow dashboard tab backed by the Rust API (`backend-rs/crates/af-api/src/mcbrowser/`) and the capability-scoped filesystem crate (`backend-rs/crates/af-files/`), rendered in the Leptos Rust WebAssembly frontend (`frontend-rs`). It requires no iframe, separate daemon, container, extra login, or Marketplace package.

## Implemented Workflows

- **Browsing, Search & Preferences**: Private per-user browsing, breadcrumbs, search scanning up to 50,000 entries and returning up to 10,000 results while skipping `.git`, `node_modules`, and similar heavy directories — note two distinct search modes:
  - **WASM UI Smart Search (`ai=true`)**: The McBrowser UI unconditionally appends `&ai=true` to `GET /search`, running FlowAI smart search (`build_deterministic_nl_plan` + optional LLM enrichment), which strips `case:sensitive`/`case:insensitive` modifiers (always case-insensitive), parses natural-language filler/size/category/season hints, requires **all** significant tokens across full path or name (**AND** semantics), ranks matches by score, and falls back to deterministic search only if FlowAI yields 0 matches.
  - **Deterministic API Filename Search (omitting `ai=true`, or 0-match fallback)**: Supports `case:sensitive` / `case:insensitive` [default], `type:image`, `type:audio` / `type:music`, `type:video`, and exact-extension `type:<ext>` modifiers combined with OR, plus quoted `"phrase"` or space-separated OR filename terms.
  - Directory listings are bounded to 10,000 entries with sorting, list/grid views, persisted owner preferences (`GET/PUT /preferences`), quota usage, and admin-managed operation permissions/path rules.
- **File & Folder Mutations**: Recursive copy/delete, move/rename, file creation, and bounded UTF-8 editing with ETag conflict detection. The HTTP API for `/copy` and `/rename` accepts `conflict` policies (`error`, `overwrite`, `keep-both`) and returns allocated names; in the current WASM workspace UI, copy/move/rename actions send `"conflict": "error"` (UI conflict choices apply to resumable TUS uploads over 64 MiB).
- **Selection & Keyboard Shortcuts**: The workspace provides individual row checkboxes and a **Select visible** toggle (no Shift-click range selection, explorer-wide clipboard across folder navigation, or workspace-level keyboard shortcuts). Editor-scoped shortcuts (`Ctrl/Cmd+S`, find/replace, undo/redo) are active inside `McBrowserCodeEditor`.
- **Upload Queue & Resumable TUS Uploads**:
  - Files `<= 64 MiB` upload directly via `PUT /api/v1/auth/mcbrowser/upload` (bypassing TUS conflict modes).
  - Files `> 64 MiB` use the appendable resumable TUS upload queue with a **3-request** client concurrency cap, confirmed-byte progress, per-row transfer rates (no aggregate speed/ETA), pause/resume, cancellation verification, and overwrite/skip/resume choices. Queue history retains up to **1,000 entries** (no 16 GiB client byte cap); server per-file resumable limit defaults to 64 GiB (`AF_MCBROWSER_MAX_UPLOAD_BYTES`) with 4 MiB `PATCH` chunks.
  - Drag-and-drop currently reads the flat browser `FileList` (recursive directory drops preserving empty folders are not implemented in the UI, and the UI does not send `parents: true` on `/directory`). Uploads continue across sidebar switches; page reload drops browser `File` handles (reselecting the same file can recover a matching durable session); logout/account switch aborts local state.
- **Downloads, Archives & Public Shares**: Native attachment downloads (`GET /download` with single `Range` support), streamed archives (`POST /archive`, `POST /archive-ticket` + `GET /archive/:ticket`), and persistent on-disk archive creation via Safe Built-In Actions (`POST /actions` with `create_archive` — used by the UI archive button). Public shares (`/api/v1/public/mcbrowser/shares/:token{,/unlock,/entries,/download}`) support optional password unlock, expiry, revocation, scoped folder browsing, and downloads.
- **Previews & Code Editor**: Text previews are literal UTF-8 capped at 256 KiB; separate bounded endpoints serve media streaming/metadata, thumbnails, subtitles, CSV, and EPUB previews. UTF-8 editing accepts up to 10 MiB of decoded text (with a JSON body bound allowing sixfold escaping) and caps concurrent editor parses at 4 (`429 EDITOR_BUSY`, `Retry-After: 1`). The native Rust/Leptos code editor (`af-web-ui::editor`) supports **45** syntax modes, 17 built-in themes (**8** exposed in `EDITOR_THEME_OPTIONS`, accepting legacy `ace/theme/*` names), search/replace, undo/redo, dirty-close/unload warnings, and sanitized Markdown/MathML preview (`pulldown-cmark`, `pulldown-latex`, `ammonia` in `af-web-worker`).
- **Safe Built-In Actions & Audit Queue**: Checksums, bounded archive extraction, persistent archive creation across nine formats (`zip`, `tar`, `tar.gz`, `tar.bz2`, `tar.xz`, `tar.lz4`, `tar.sz`, `tar.br`, `tar.zst`), and media metadata inspection require explicit admin opt-in to default-off `permissions.execute` (`PUT /api/v1/auth/mcbrowser/policy/:user_id`) plus matching McBrowser policy permissions (`read`/`create`/`modify`/etc., never exposing host shells or arbitrary programs). Mandatory audit recording persists typed mutation records (`GET /events`, `GET /audit-events`) alongside an optional internal admin event queue (`GET/PUT /events/settings`, `GET /events/queue`, `POST /events/queue/:event_id/ack`).

## Current Scope and Limitations

McBrowser is an active partial native implementation rather than a certified drop-in replacement for every legacy FileBrowser edge case. Current limitations include:

- Workspace copy/move/rename UI hardcodes `"conflict": "error"` (no overwrite/keep-both prompt in workspace mutations yet).
- No explorer-wide keyboard shortcuts, Shift-click range selection, internal clipboard, or recursive directory drag-and-drop preserving empty folders in the WASM UI.
- Full symlink alias-policy acceptance, media/document browser acceptance, crash/restart recovery exercises, and accessibility/localization audits remain ongoing release gates.

## Account Deletion and Storage Cleanup

Admin account deletion serializes with the target user's McBrowser mutations and executes an immediate SQLite transaction covering live admin checks, last-usable-admin protection (ignoring suspended/plugin admin rows), session/OIDC revocation, McBrowser policy/preference/share/upload metadata removal, `sqlite_sequence` monotonic advancement (preventing user ID reuse), quota/user deletion, and insertion of durable cleanup rows in `account_storage_cleanup`.

During `finish_account_deletion()`, in-memory cached media thumbnails (`invalidate_thumbnail_cache`) and active **FileShare** uploads (`discard_fileshare_uploads` — FileShare is AetherFlow's built-in upload store under `/var/lib/aetherflow/uploads` / `AETHERFLOW_UPLOAD_DIR`, separate from McBrowser public share links) are cleared synchronously. When durable storage cleanup cannot complete synchronously, the deletion endpoint returns `202 Accepted` and background recovery (`account_cleanup::recover()`, running every 15 minutes) retries only durable rows recorded in `account_storage_cleanup`: the retired user's `user-<id>` directory, `.af-upload-staging/user-<id>` chunks, and unreferenced `fileshare_objects`. OIDC access-token introspection and WebSocket sessions/upgrades also verify live owner existence.

> [!CAUTION]
> **Do Not Bind-Mount Shared Storage Under `user-*`**: `account_cleanup.rs` recursively deletes `/var/lib/aetherflow/mcbrowser/user-<id>` without a `st_dev` mount-boundary guard. Never bind-mount shared host media directories (such as `/mnt/storage/media`) inside a user's McBrowser directory—deleting that account would recursively delete files across the bind mount.

## Host Filesystem Path-Picker Policy

The host path picker (`/api/v1/auth/fs`, `/api/auth/fs`, `/api/v1/fs`, `/api/fs`) is restricted strictly to active, live-database administrator accounts. Non-admin users and plugin tokens are rejected before path existence checks, canonicalization, or directory enumeration. Admin host browsing honors `AF_ALLOWED_FS_ROOTS` (defaulting to `/mnt,/media,/srv,/data,/home` plus `env::temp_dir()` and non-service `env::current_dir()`).

## Storage and Deployment

`AF_MCBROWSER_ROOT` defaults to `/var/lib/aetherflow/mcbrowser`. Use a dedicated absolute directory owned by the `aetherflow` service UID; the API enforces mode `0700` on the root and every `user-<application_user_id>` child (application IDs are SQLite IDs, not POSIX usernames). `/` and symlink roots are rejected, and all ancestors must be administrator-owned and non-writable by untrusted users.

The default path resides under `StateDirectory=aetherflow`. Custom roots outside the unit's pre-configured `ReadWritePaths` (`/var/lib/aetherflow`, `/var/log/aetherflow`, `/run/aetherflow`, `-/srv`, `-/mnt`, `-/media`, `-/data`, `-/opt/AetherFlow/backend/data`) require a `systemd` drop-in. McBrowser requires Linux with atomic `renameat2(RENAME_NOREPLACE)` and fails closed if unsupported.

> [!NOTE]
> `af backup create` backs up `/var/lib/aetherflow/aetherflow.sqlite` and system configs, **not** `/var/lib/aetherflow/mcbrowser`. Back up tenant storage alongside SQLite quota records to keep disk usage and quota accounting aligned.

## Security and Accounting

Authenticated endpoints inherit AetherFlow session auth and double-submit CSRF protection; public share endpoints enforce share-specific unlock/expiry/owner rules. Plugin-scoped tokens are unconditionally denied.

Each user receives a descriptor-confined capability directory rejecting absolute paths, `..`, NULs, backslashes, reserved `.af-upload-tmp.*` names, special files, multiply hardlinked files, and paths exceeding 4,096 bytes / 64 components / 255 bytes per component. Default low-level `af-files` primitives reject symlinks; McBrowser read/browse handlers invoke `af-files`'s opt-in internal-link APIs (`*_resolving_internal_links`) with Linux `openat2` confinement, target `(st_dev, st_ino)` identity verification, and policy checks on both alias and resolved target. Mutation parents always reject symlinks, and leaf-link rename/delete affect only the link itself.

- **Concurrency & Lock Retention**: Mutations serialize per lock stripe and retain their lock even if the HTTP request disconnects.
- **Upload Staging & Quota Enforcement**: Uploads stage in mode `0600` temp files under `/var/lib/aetherflow/mcbrowser/.af-upload-staging/user-<id>`, reserve exact byte quotas atomically, and require a 1 GiB free-space floor at admission. Storage quotas are managed in **Storage Quotas** (`GET /api/v1/admin/quotas`, `PUT /api/v1/admin/quotas/:id`, and `POST /api/v1/admin/quotas/:id/refresh`), which coordinates SQLite `user_quotas` with AetherFlow's `setdisk` quota wrapper (invoking Linux `setquota`) via `af-runner` and scans both `/home/<username>` and `<AF_MCBROWSER_ROOT>/user-<id>` (running `sudo af quota set` directly via CLI modifies only Linux POSIX quotas). Quota reads fail closed on DB errors or suspended accounts; missing quota rows allow unlimited usage.
- **Over-Accounting Recovery (`accounting_pending`)**: Crashes between reservation and publication or failed post-delete accounting can leave conservative over-accounting (flagged via `accounting_pending`). Stop active writers, inspect `/var/lib/aetherflow/mcbrowser/.af-upload-staging/user-<id>`, and trigger reconciliation via `POST /api/v1/admin/quotas/:id/refresh`, **Storage Quotas → Scan Disk** (per user), or **Sync / reconcile quotas** (fleet-wide; the toolbar **Refresh** button only reloads `GET /api/v1/admin/quotas`).

## API Contract

Authenticated routes live under `/api/v1/auth/mcbrowser` (with `/api/auth/mcbrowser` legacy aliases); public share routes live under `/api/v1/public/mcbrowser`. Root is the empty relative path.

| Method | Path Suffix | Request | Result |
| :--- | :--- | :--- | :--- |
| `GET` | `/entries?path=...` | Relative directory | `{ path, entries, max_upload_bytes }` |
| `GET` | `/search?q=...&ai=true` | Search query, optional `path`/`type`, optional `ai=true` (sent by WASM UI for FlowAI smart search; omit for deterministic OR filename search) | Bounded matches (up to 50k scanned / 10k returned) |
| `POST` | `/directory` | JSON `{ path, parents?: boolean }` | `201` `{ success: true }` |
| `POST` | `/file` | JSON `{ path, content? }` | New file (`201`) |
| `POST` | `/rename` | JSON `{ from, to, conflict?: "error"\|"overwrite"\|"keep-both" }` | `200` `{ success, path, from, to, accounting_pending }` |
| `POST` | `/copy` | Same conflict fields as rename | Published destination & accounting metadata |
| `DELETE` | `/entry?path=...` | Relative entry | `200` `{ success: true, accounting_pending? }` |
| `POST` | `/delete-recursive` | JSON `{ path }` | Removed tree with quota accounting |
| `PUT` | `/upload?path=...` | Raw file body (`<= 64 MiB`) | `201` `{ success: true }` |
| `POST`, `GET` | `/uploads` | TUS metadata / session discovery | Durable scoped upload sessions |
| `HEAD`, `PATCH`, `DELETE` | `/uploads/:id` | Offset / 4 MiB chunk / cancel | Confirmed offset or terminal state |
| `GET` | `/download?path=...` | Optional single `Range` header | Attachment stream (`200` or `206`) |
| `GET` | `/preview?path=...` | Relative text file | `{ path, content, truncated }` |
| `GET`, `PUT` | `/content?path=...` | UTF-8 content / `ETag` | Bounded editor read/save (up to 10 MiB decoded) |
| `GET` | `/info?path=...&checksum=...` | Relative path, optional algorithms | Metadata, counts, and checksums |
| `POST` | `/archive` | Selection and archive format | Streamed archive download |
| `POST` | `/archive-ticket` | Selection and archive format | One-time ticket for native download |
| `GET` | `/archive/:ticket` | Archive download ticket | Streamed archive attachment |
| `POST` | `/actions` | Safe built-in action payload (`create_archive`, extract, checksum, media info) | Action result (requires `execute` permission) |
| `GET` | `/media`, `/media-info`, `/thumbnail`, `/preview/thumb`, `/preview/big`, `/subtitle`, `/subtitles`, `/csv`, `/epub` | Relative media/document path | Bounded media stream, thumbnail, subtitle, or document preview |
| `GET` | `/policy`, `/usage` | Authenticated owner | Effective permissions / quota usage |
| `GET`, `PUT` | `/preferences` | Owner UI preferences | Persisted preferences |
| `GET`, `PUT` | `/policy/:user_id` | Live-DB admin target policy (`{ permissions: { read, create, rename, modify, delete, share, download, execute }, rules, scope }`) | Validated target user policy |
| `GET`, `POST` | `/shares` | Owner link list / creation | Scoped share list or created token |
| `DELETE` | `/shares/:id` | Owner share ID | Share revocation |
| `GET` | `/events`, `/audit-events`, `/events/queue` | Live-DB admin audit & queue inspection | Typed mutation audit records / queue items |
| `GET`, `PUT` | `/events/settings` | Live-DB admin event queue settings | Queue configuration |
| `POST` | `/events/queue/:event_id/ack` | Live-DB admin queue acknowledgment | Acknowledged queue task |
| `GET` | `public: /shares/:token` | Public share token | Share metadata |
| `POST` | `public: /shares/:token/unlock` | Share password | Unlock cookie/session |
| `GET` | `public: /shares/:token/entries` | Public folder listing | Scoped directory entries |
| `GET` | `public: /shares/:token/download` | Public file download | Scoped attachment stream |

Each directory entry (`BrowserEntry` from `GET /entries`) includes `name`, `path`, `kind`, `size`, nullable RFC3339 `modified`, and optional `target_kind` for symlinks. Errors return `{ code, message }` without leaking host filesystem paths. `parents` defaults to `false` on `/directory`; when callers opt into `parents: true`, parent directories created during a failed or cancelled batch are not automatically rolled back.
