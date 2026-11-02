# McBrowser Parity Audit & Executable Acceptance Specification

Status note — November 2, 2026: the matrix and unmounted-code observations below
record the initial audit, not the current checkout. Backend subrouters and the
React workspace are now mounted. Use `mcbrowser-parity.md` and the chronological
`mcbrowser-integration-audit.md` for current implementation status. Acceptance
requirements remain blocking until exercised; historical statuses are not test
certificates. Search semantics below have been corrected against the pinned source.

## 1. Audit Scope, Baseline, and Ground-Truth Rules

- **Pinned Upstream Baseline**: `/tmp/McBrowser-rust-assessment` at commit `833d908884d5c801f30f5c098d7977177eb3a36b` (`McEveritts/McBrowser`).
- **Native Target**: AetherFlow Rust (`backend-rs/crates/af-files`, `backend-rs/crates/af-api/src/mcbrowser.rs`, `backend-rs/crates/af-api/src/mcbrowser/*`) and Next.js (`frontend/src/components/tabs/McBrowserTab.tsx`, `frontend/src/components/mcbrowser/*`, `frontend/src/lib/mcbrowser*.ts`).
- **Audit Integrity Rules**:
  1. **No Credit for Unmounted or Unwired Code**: Concurrent work has created unmounted backend submodules (`backend-rs/crates/af-api/src/mcbrowser/{uploads,operations,media}.rs`) and unmounted frontend modules (`frontend/src/components/mcbrowser/McBrowserWorkspace.tsx`, `frontend/src/lib/mcbrowser-{resumable,workspace,uploads}.ts`). Because `backend-rs/crates/af-api/src/mcbrowser.rs:142-154` currently mounts only 7 routes (`/mcbrowser/{upload,entries,directory,rename,entry,download,preview}`) and `frontend/src/components/tabs/McBrowserTab.tsx` does not render `McBrowserWorkspace.tsx`, **none of those unmounted modules are counted as Passing**.
  2. **Strict Separation of Categories**:
     - **Original Capability (Must-Pass Parity)**: Proven by `file:line` in `/tmp/McBrowser-rust-assessment` (`833d908884d5c801f30f5c098d7977177eb3a36b`).
     - **Wishlist / Scope Inflation (Non-Parity Enhancement)**: Capabilities not present in upstream `833d908884d5c801f30f5c098d7977177eb3a36b` (or explicitly blocked upstream) that must not inflate parity scope unless intentionally added as safe enhancements.
     - **Unsafe Upstream Behavior (Must Redesign Safely)**: Upstream features that violate AetherFlow's multi-tenant sandbox (`openat2` confinement, no arbitrary host shell execution, no partial-overwrite corruption) and require a safe native architecture rather than a raw port or silent waiver.

---

## 2. Verified Capability & Parity Matrix

Status legend:
- **PASS**: Mounted, wired end-to-end in live `mcbrowser.rs` + `McBrowserTab.tsx`, and verified.
- **PARTIAL (Unmounted WIP)**: Present in unmounted `mcbrowser/{uploads,operations,media}.rs` or `McBrowserWorkspace.tsx`, or missing subset of upstream contract.
- **MISSING**: Not implemented in backend or frontend.
- **UNSAFE UPSTREAM -> SAFE REDESIGN**: Upstream implementation is unsafe; requires safe native replacement.

| Domain | Capability | Upstream Evidence (`833d9088...`) | Category | Live Native Status | Key Gap / Audit Finding |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Upload: Empty Dirs** | Drag-and-drop folder upload preserves empty directories | `frontend/src/utils/upload.ts:144-234,264-276`, `stores/upload.ts:116-120`, `http/resource.go:139-145` | **Original Capability** | **PARTIAL (Unmounted WIP)** | Live `McBrowserTab.tsx:394-396` uses `e.dataTransfer.files` (drops empty dirs). `mcbrowser-uploads.ts` implements `webkitGetAsEntry` + `createEmptyDirectories`, but is not wired into `McBrowserTab.tsx`. |
| **Upload: Empty Dirs** | `<input webkitdirectory>` folder picker preserves empty directories | `frontend/src/components/prompts/Upload.vue:49-66,108-123`, `FileListing.vue:153-160,867-885` | **Wishlist (Browser Limitation)** | **N/A (Wishlist)** | Upstream `<input webkitdirectory>` iterates `input.files` with `isDir: false`; HTML `<input type="file" webkitdirectory>` never exposes empty directories. Do **not** inflate picker scope. |
| **Upload: TUS Resumable** | Chunked/resumable upload (`POST`/`HEAD`/`PATCH`/`DELETE`), offset verification, progress/speed/ETA, 5-way queue | `http/tus_handlers.go:59-344`, `frontend/src/api/tus.ts:1-122`, `stores/upload.ts:9-198`, `UploadFiles.vue:16-24,90-200` | **Original Capability** | **PARTIAL (Unmounted WIP)** | Live `mcbrowser.rs:144` is single-shot `PUT /mcbrowser/upload` capped at 64 MiB with no byte progress. `mcbrowser/uploads.rs` + `mcbrowser-resumable.ts` implement TUS with private `.af-upload-staging` and SQLite tracking, but are **not mounted** in `mcbrowser.rs` or `McBrowserTab.tsx`. |
| **Upload: TUS Staging** | Upstream TUS writes directly to live target file (`O_TRUNC` on override) before upload finishes | `http/tus_handlers.go:88-120,213-286` | **Unsafe Upstream Behavior** | **SAFE REDESIGN (Unmounted WIP)** | Upstream corrupts/truncates live file if an overwrite upload aborts mid-stream. Native `uploads.rs` stages in `.af-upload-staging/user-<uid>/<id>.part` and commits atomically on final byte. Must support safe replace on commit when `policy=replace`. |
| **Conflict Policies** | Preflight conflict detection (flat & recursive) + `Override`, `Skip`, `Resume Transfer` for uploads; `Override`, `Skip`, `Rename (base(1).ext)` for copy/move | `frontend/src/utils/upload.ts:90-142`, `ResolveConflict.vue:1-246`, `Copy.vue:126-158`, `Move.vue:126-158`, `http/resource.go:147-169,245-264,328-344` | **Original Capability** (`Keep Both` on upload is **Wishlist**) | **PARTIAL (Unmounted WIP)** | Upstream **forbids** `['origin','dest']` (Keep Both) on uploads (`ResolveConflict.vue:48-55`), allowing it only on Copy/Move (`rename=true` -> `base(1).ext`). Native `uploads.rs` supports `fail`/`replace`/`keep_both` (`name (1).ext`), which is a safe superset once mounted, but `copy_entry` / `rename_entry` still lack `override` and `rename` conflict modes. |
| **Download: Single File** | Streaming `GET` download with `Range`, `Content-Disposition` (`RFC 5987`), `nosniff`, `CSP` | `http/raw.go:20-39,185-232`, `frontend/src/api/files.ts:82-104` | **Original Capability** | **PARTIAL** | Backend `GET /mcbrowser/download` supports `Range`, `nosniff`, and RFC 5987 filename, **but** frontend `downloadMcBrowserFile` (`mcbrowser.ts:276-308`) buffers the entire response in RAM via `await res.blob()`, crashing tabs on multi-GB files. |
| **Download: Archives** | Multi-file & directory archive streaming across 9 formats: `zip`, `tar`, `targz`, `tarbz2`, `tarxz`, `tarlz4`, `tarsz`, `tarbr`, `tarzst` | `http/raw.go:41-64,93-183`, `frontend/src/components/prompts/Download.vue:1333-1343` | **Original Capability** | **PARTIAL (Unmounted & Incomplete)** | Live `mcbrowser.rs` has no archive endpoint. Unmounted `mcbrowser/operations.rs:144-169` (`POST /mcbrowser/archive`) implements only 3 formats (`zip`, `tar`, `tar.gz`) and rejects `targz`, `tarbz2`, `tarxz`, `tarlz4`, `tarsz`, `tarbr`, `tarzst`. Also `mcbrowser-workspace.ts` buffers archive response into `res.blob()`. |
| **Checksum Algorithms** | On-demand file checksums: `md5`, `sha1`, `sha256`, `sha512` (hex) + directory counts & image dimensions in Info modal | `files/file.go:170-207,253-260,289-309`, `http/resource.go:69-83`, `frontend/src/components/prompts/Info.vue:1345-1540` | **Original Capability** | **PARTIAL (Unmounted WIP)** | Live `mcbrowser.rs` has no `/info` route. Unmounted `operations.rs:129-141,620-695` implements `md5`, `sha1`, `sha256`, `sha512` on `GET /mcbrowser/info`, but omits directory `numFiles`/`numDirs` and image `resolution` (`width x height`). |
| **Public Sharing** | Create/list/revoke share links (`POST/GET /api/share/{path}`, `GET /api/shares`, `DELETE /api/share/{hash}`), expiry (`seconds`/`minutes`/`hours`/`days`), bcrypt password + `X-SHARE-PASSWORD` / constant-time `?token=`, public browse & archive/file download (`GET /api/public/{share,dl}/{hash}`) | `http/share.go:1-251`, `http/public.go:1-165`, `share/share.go:1-20`, `share/storage.go:1-125`, `Share.vue`, `views/Share.vue`, `views/settings/Shares.vue` | **Original Capability** | **MISSING** | Frontend `mcbrowser-workspace.ts` calls `/mcbrowser/shares` and `/public/mcbrowser/shares/{hash}`, but **no backend share storage, routes, or public share viewer exist** in `af-api`. |
| **Admin: Scopes, Rules & Permissions** | 8 granular permissions (`admin`, `execute`, `create`, `rename`, `modify`, `delete`, `share`, `download`), per-user `Scope`, global/user path & regex allow/deny `Rules` with recursive `checkDescendants` on delete/copy/rename | `users/permissions.go:4-13`, `users/users.go:25,92-96`, `rules/rules.go:14-72`, `http/data.go:36-85`, `http/resource.go:283-312`, `Permissions.vue:1-79`, `Rules.vue:1-130` | **Original Capability** | **MISSING** | `mcbrowser.rs:249-256` gates all routes on `user.id > 0` only. No `policy` module exists in `backend-rs/crates/af-api/src/mcbrowser/`, no per-operation permission flags, and no path/regex rule evaluation or `checkDescendants` enforcement. |
| **User Preferences & Views** | Persisted `viewMode` (`list`, `mosaic`, `mosaic gallery`), `sorting` (`name`/`size`/`modified`, `asc`, natural sort), `hideDotfiles`, `singleClick`, `redirectAfterCopyMove`, `dateFormat`, `locale`, `aceEditorTheme` | `users/users.go:13-39`, `settings/defaults.go:10-22`, `files/listing.go:18-105`, `FileListing.vue:168,365-430,934-962`, `Profile.vue:1-221` | **Original Capability** | **MISSING (Backend) / PARTIAL (Unmounted UI)** | Live `McBrowserTab.tsx` has only ephemeral client sort (`name`/`size`/`modified`) and table view. Unmounted `McBrowserWorkspace.tsx` calls `/mcbrowser/preferences`, which does not exist in `af-api`. |
| **Media, Docs & Subtitles** | Image `thumb` (256x256 JPEG, EXIF fast-path, 10000x10000 OOM guard) & `big` (1080x1080) with cache invalidation; Video with `.vtt`/`.srt`/`.ass`/`.ssa` -> WebVTT conversion (`GET /api/subtitle/{path}` + `sub`/`subs`/`subtitles` discovery); Audio; PDF; EPUB (`vue-reader`); CSV viewer (5 MiB cap, delimiter/encoding); Markdown (`DOMPurify` + KaTeX); Text editor (`Ctrl+S`, dirty guard, 10 MiB cap) | `http/preview.go:37-159`, `img/service.go:26-259`, `files/file.go:30-33,222-391`, `http/subtitle.go:17-92`, `Preview.vue`, `Editor.vue`, `CsvViewer.vue`, `VideoPlayer.vue` | **Original Capability** | **PARTIAL (Unmounted WIP)** | Live `mcbrowser.rs` only returns 256 KiB plain-text/base64 JSON via `GET /mcbrowser/preview`. Unmounted `media.rs` adds streaming `/mcbrowser/media` (MP4/WebM/MP3/WAV/OGG/FLAC/PDF/PNG/JPEG/GIF/WebP) and `/mcbrowser/subtitle` (`.vtt`/`.srt`), and `operations.rs` adds `/mcbrowser/content` (2 MiB editor with ETag), but misses `.ass`/`.ssa` subtitles, `sub/` folder auto-discovery, server-side 256x256/1080x1080 image thumbnails, and EPUB viewing. |
| **File/Folder Mutations & Search** | Recursive delete/copy, cycle-safe move/rename, file creation, filename-only subtree search with case/type/OR-term modifiers | `http/resource.go:88-276,441-506`, `http/search.go:1-60`, `search/search.go:1-120`, `search/conditions.go:1-95` | **Original Capability** | **PARTIAL (Mounted; acceptance pending)** | Native operations are mounted. Search uses source-exact `case:sensitive`/`case:insensitive`, image/audio/music/video categories and exact extension types; `type:doc` is an extension, not a document category. Full browser and alias acceptance remain. |
| **Command Actions & Hooks** | Interactive WebSocket shell (`GET /api/command/{path}`) and `before_*`/`after_*` shell hooks (`$FILE`, `$SCOPE`, `$TRIGGER`, `$USERNAME`, `$DESTINATION`) | `http/commands.go:40-120`, `runner/runner.go:19-118`, `frontend/src/components/Shell.vue` | **Unsafe Upstream Behavior** | **SAFE REDESIGN REQUIRED** | Upstream spawns raw host executables (`exec.Command`) inside user directories and interpolates filenames into command arguments/shells, escaping `openat2` confinement. Must be replaced by a safe in-process/allowlisted action & event architecture (Section 4.1). |
| **Symlink Handling** | `ScopedFs` userland `EvalSymlinks` allowing in-scope symlinks (`maxSymlinkHops=40`), `invalid_link` badge for broken links, and `FollowExternalSymlinks` escape flag | `files/scoped.go:43-157`, `files/file.go:414-431`, `settings/settings.go:65` | **Unsafe Upstream (`FollowExternalSymlinks` & userland TOCTOU) / Original Capability (In-Scope Links)** | **BLOCKED IN NATIVE (`RESOLVE_NO_SYMLINKS`)** | Native `af-files` blocks all symlink traversal (`RESOLVE_NO_SYMLINKS`) and cannot even delete or rename a symlink entry itself (`EntryKind::Symlink` rejected in `remove`/`rename`). Requires safe kernel-enforced internal symlink design (Section 4.2). |

---

## 3. Executable-Style Acceptance Cases by User-Facing Workflow

Every acceptance case below cites its upstream ground truth in `/tmp/McBrowser-rust-assessment` (`SHA 833d908884d5c801f30f5c098d7977177eb3a36b`) and defines deterministic **Given / When / Then** verification criteria for AetherFlow.

### 3.1 Authentication, Scopes, Rules, and Granular Permissions

- **Upstream Evidence**:
  - `users/permissions.go:4-13` (`Permissions` struct: `Admin`, `Execute`, `Create`, `Rename`, `Modify`, `Delete`, `Share`, `Download`).
  - `frontend/src/components/settings/Permissions.vue:20-26,65-75` (`admin` enables all; `share` automatically forces `download = true`).
  - `users/users.go:25,92-96`, `settings/dir.go:23-69`, `http/users.go:101-103` (per-user `Scope` confinement and non-admin scope immutability).
  - `rules/rules.go:14-72`, `http/data.go:36-85`, `http/resource.go:283-312` (sequential rule evaluation where last matching global/user path or regex rule wins; `checkDescendants` walks subtrees before `delete`, `copy`, or `rename`).

#### `ACC-PERM-01`: Per-Operation Permission Enforcement
- **Given** an authenticated non-admin user whose McBrowser policy has `create = false`, `rename = false`, `modify = false`, `delete = false`, `share = false`, `download = false` (read/list only):
- **When** the client calls:
  1. `GET /api/v1/mcbrowser/entries?path=`
  2. `POST /api/v1/mcbrowser/directory` or `POST /api/v1/mcbrowser/file` or `POST /api/v1/mcbrowser/uploads`
  3. `PUT /api/v1/mcbrowser/content` or `POST /api/v1/mcbrowser/uploads?policy=replace` on an existing file
  4. `POST /api/v1/mcbrowser/rename` or `POST /api/v1/mcbrowser/copy`
  5. `DELETE /api/v1/mcbrowser/entry` or `POST /api/v1/mcbrowser/delete-recursive`
  6. `GET /api/v1/mcbrowser/download` or `POST /api/v1/mcbrowser/archive` or `GET /api/v1/mcbrowser/info?checksum=sha256`
  7. `POST /api/v1/mcbrowser/shares`
- **Then**:
  - Request (1) succeeds with `200 OK`.
  - Requests (2)–(7) fail with `403 Forbidden` (`{"error":{"code":"FORBIDDEN",...}}`) and perform zero filesystem mutations. *(Note: Upstream quirk returning `202 Accepted` on missing `Perm.Download` in `http/raw.go:79` and `http/resource.go:46,71` is replaced by standard `403 Forbidden`.)*
  - Enabling `share = true` in policy configuration automatically enforces `download = true`.

#### `ACC-PERM-02`: Sequential Path/Regex Rules & Subtree Descendant Protection (`checkDescendants`)
- **Given** a user with rules:
  1. Rule 1: `{ allow: false, regex: false, path: "/secrets" }`
  2. Rule 2: `{ allow: false, regex: true, regexp: "\\.pem$" }`
  3. Directory `/projects/app/certs/prod.pem` exists inside `/projects/app`:
- **When** the user:
  1. Lists `/` (`GET /api/v1/mcbrowser/entries?path=`) or requests `/secrets` directly
  2. Attempts to delete, rename, or copy the parent directory `/projects/app` (`POST /api/v1/mcbrowser/delete-recursive`, `/rename`, or `/copy`)
- **Then**:
  - `/secrets` and any `*.pem` files are omitted from directory listings and search results, and direct access returns `403 Forbidden` (or `404 Not Found` to avoid existence leakage).
  - Attempting to delete, move, or copy `/projects/app` fails with `403 Forbidden` because `checkDescendants` (`http/resource.go:283-312`) detects the denied descendant `/projects/app/certs/prod.pem` before mutating the parent tree.

---

### 3.2 Browse, Sorting, View Modes, and Persisted User Preferences

- **Upstream Evidence**:
  - `users/users.go:13-39`, `settings/defaults.go:10-22` (`ViewMode`: `mosaic` | `list`, `Sorting`: `{By: "name"|"size"|"modified", Asc: bool}`, `HideDotfiles`, `SingleClick`, `RedirectAfterCopyMove`, `DateFormat`, `Locale`, `AceEditorTheme`).
  - `files/listing.go:18-105` (natural case-insensitive sort via `natural.Less(strings.ToLower(a), strings.ToLower(b))`, directories grouped separately from files).
  - `frontend/src/views/files/FileListing.vue:168,365-430,934-962` (`switchView` cycles `mosaic` -> `mosaic gallery` -> `list`; `Ctrl+A` selects all; `Escape` clears selection; range Shift-click and Ctrl-toggle multi-select).

#### `ACC-PREF-01`: Natural Sorting & Persisted User Preferences
- **Given** a directory containing folders `dir10`, `dir2` and files `file10.txt` (100 B), `file2.txt` (500 B), `.hidden`:
- **When** the user fetches entries with `hideDotfiles = true`, `sorting = { by: "name", asc: true }`, then updates preferences via `PUT /api/v1/mcbrowser/preferences` to `{ view_mode: "mosaic_gallery", hide_dotfiles: false, single_click: true, redirect_after_copy_move: true, date_format: true, sorting_by: "name", sorting_asc: true }` and reloads the browser:
- **Then**:
  - With `hideDotfiles = true`, `.hidden` is excluded from listing responses (while backend rule checks ignore `hideDotfiles` so deleting a parent directory containing `.hidden` still works, matching `http/data.go:53-55`).
  - Natural sorting orders directories first (`dir2`, then `dir10`) followed by files (`file2.txt`, then `file10.txt`).
  - Reloading the page restores `mosaic_gallery`, `hide_dotfiles: false`, `single_click: true`, `redirect_after_copy_move: true`, and `date_format: true` from `GET /api/v1/mcbrowser/preferences`.

---

### 3.3 Upload Workflows: Empty Directories, TUS Resumable Transfers, and Conflict Policies

- **Upstream Evidence**:
  - **Folder Picker vs Drag-and-Drop Empty Dirs**:
    - Picker (`frontend/src/components/prompts/Upload.vue:49-66,108-123`, `FileListing.vue:153-160,867-885`): reads `input.files` and pushes `{ file, name: file.name, size: file.size, isDir: false, fullPath: file.webkitRelativePath }`. Empty directories are **never** emitted by `<input type="file" webkitdirectory>`.
    - Drag-and-Drop (`frontend/src/utils/upload.ts:144-234,264-276`, `stores/upload.ts:116-120`, `http/resource.go:139-145`): `scanFiles(dt)` traverses `webkitGetAsEntry()`; when `item.isDirectory` is true, it pushes `{ isDir: true, size: 0, fullPath: "${directory}${item.name}", name: item.name }` BEFORE reading child entries, appends `"/"` in `handleFiles`, and `POST /api/resources/{dir}/` calls `Fs.MkdirAll`.
  - **TUS Resumable Upload Protocol**:
    - `http/tus_handlers.go:59-344`, `settings/tus.go:3-10`, `frontend/src/api/tus.ts:1-122`, `frontend/src/stores/upload.ts:9-198`, `frontend/src/components/prompts/UploadFiles.vue:16-24,90-200`.
  - **Conflict Policies**:
    - `frontend/src/utils/upload.ts:90-142`, `frontend/src/components/prompts/ResolveConflict.vue:1-246`, `http/resource.go:147-169,245-264,328-344`.
    - For uploads (`isUploadAction: true`), existing directories merge (`includeDirectories = false`), and file conflicts support `Override All`, `Skip All`, `Resume Transfer` (`file.size > server.size`), or per-file `origin` vs `dest` selection. Selecting both `['origin', 'dest']` (Keep Both) is **explicitly rejected with `prompts.forbiddenError` in `ResolveConflict.vue:48-55`**.

#### `ACC-UPL-01`: Drag-and-Drop Nested Tree with Empty Directories vs Folder Picker Scope
- **Given** a dropped `DataTransfer` tree containing:
  - `project/empty_subdir/` (0 files)
  - `project/docs/readme.md` (12 bytes)
  - `project/assets/empty_icons/` (0 files)
- **When** the user drops `project` onto the McBrowser dropzone:
- **Then**:
  - `scanTransferItems` traverses `webkitGetAsEntry()` recursively and creates `project`, `project/empty_subdir`, `project/docs`, and `project/assets/empty_icons` via `POST /api/v1/mcbrowser/directory` (in parent-before-child depth order) before uploading `project/docs/readme.md`.
  - Listing `project/empty_subdir` and `project/assets/empty_icons` returns `200 OK` with `entries: []`.
  - **Scope Boundary**: Standard `<input webkitdirectory>` folder picker is ** only** required to create parent directories of selected files (`project/docs` for `project/docs/readme.md`); preserving empty directories via `<input webkitdirectory>` is a browser-API impossibility and classified as **Wishlist**, not a parity defect.

#### `ACC-UPL-02`: TUS Resumable Upload Lifecycle, Chunk Offset Verification, and Atomic Staging
- **Given** a user with 10 GiB available quota uploading a 10 MiB file (`report.bin`) in 4 MiB chunks:
- **When**:
  1. Client sends `POST /api/v1/mcbrowser/uploads` with `Tus-Resumable: 1.0.0`, `Upload-Length: 10485760`, `Upload-Metadata: path <b64>,fingerprint <b64>`
  2. Client sends `PATCH /api/v1/mcbrowser/uploads/{id}` with `Content-Type: application/offset+octet-stream`, `Upload-Offset: 0`, and 4 MiB body
  3. Network drops during the second chunk after 1 MiB is written; client queries `GET /api/v1/mcbrowser/uploads?path=report.bin&length=10485760&fingerprint=...` and `HEAD /api/v1/mcbrowser/uploads/{id}`
  4. Client sends `PATCH` with a wrong `Upload-Offset: 0`
  5. Client sends `PATCH` with the server's reported `Upload-Offset` for the remaining bytes through `10485760`
- **Then**:
  - Step (1) reserves `10485760` bytes in SQLite `user_quotas`, creates `.af-upload-staging/user-{uid}/{id}.part` outside the browsable user root, and returns `201 Created` with `Location: /api/v1/mcbrowser/uploads/{id}` and `Upload-Offset: 0`. During steps (1)–(4), `report.bin` does **not** appear in `GET /api/v1/mcbrowser/entries`.
  - Step (3) `HEAD` reconciles SQLite offset with staging disk size and returns `200 OK` with the exact committed `Upload-Offset` and `Cache-Control: no-store`.
  - Step (4) returns `409 Conflict` (`OFFSET_MISMATCH`) without corrupting the staging file.
  - Step (5) returns `204 No Content` with `Upload-Offset: 10485760`, atomically publishes `report.bin` into the user root, deletes the `.part` file, and keeps the `10485760` quota charge.
  - Calling `DELETE /api/v1/mcbrowser/uploads/{id}` on an in-progress upload removes the `.part` file, marks the session cancelled, and releases the full reserved `Upload-Length` from `user_quotas`.
  - UI displays live byte progress (`sentMbytes / totalMbytes`), percentage, transfer speed (`KB/s` or `MB/s`), and ETA (`HH:MM:SS`) across up to 5 concurrent uploads (`UploadFiles.vue:16-24,90-200`, `stores/upload.ts:11`).

#### `ACC-UPL-03`: Upload & Copy/Move Conflict Resolution Policies
- **Given** `/docs/spec.md` (size 500 B, content `"v1"`) already exists on the server:
- **When** the user uploads a new `spec.md` (size 800 B, content `"v2"`):
  1. Preflight check (`GET /api/v1/mcbrowser/entries` for flat upload, or recursive listing for nested folder upload) detects the collision on `/docs/spec.md` (existing directories are merged without conflict).
  2. If the user selects **Skip**: `spec.md` is removed from the upload queue and `/docs/spec.md` remains `"v1"`.
  3. If the user selects **Override / Replace** (requires `Perm.Modify`): the new upload stages in `.af-upload-staging` and, only upon receiving the final byte, atomically replaces `/docs/spec.md` with `"v2"` and adjusts `user_quotas.used_bytes` by `+300` bytes (`new_size - old_size`). If the replace upload is cancelled mid-stream, `/docs/spec.md` remains intact with `"v1"` (fixing upstream `tus_handlers.go:96` partial-truncation bug).
  4. If the user selects **Resume Transfer** (`ResolveConflict.vue:115-124,207-216`): if an active TUS session matches `(path, length, fingerprint)`, resume from `Upload-Offset`; otherwise if `local.size > server.size`, replace `/docs/spec.md`.
- **And When** the user copies or moves `/staging/spec.md` to `/docs/spec.md`:
  - Selecting **Rename / Keep Both** (`rename=true` in `http/resource.go:250-256,328-344`) writes `/docs/spec(1).md` while preserving `/docs/spec.md`. Upload keep-both is a native enhancement, not a substitute for original upload overwrite/skip/resume. Copy/move conflict flags are `override` and `rename`; a separate copy/move skip mode is not established by those source lines.

---

### 3.4 File & Directory Mutations and Subtree Search

- **Upstream Evidence**:
  - `http/resource.go:88-276,328-344,441-506` (`DELETE`, `POST`, `PUT`, `PATCH ?action=copy|rename`, `checkParent` self-descendant prevention, recursive listing).
  - `http/search.go:1-60`, `search/search.go:1-120`, `search/conditions.go:1-95` (`case:sensitive`, `case:insensitive`, MIME categories `type:image|audio|music|video`, otherwise exact `type:<extension>`).
  - `frontend/src/components/prompts/{NewFile,NewDir,Rename,Copy,Move,Delete}.vue`, `views/files/Editor.vue:1-327`.

#### `ACC-MUT-01`: Create File, Text Editor with ETag Concurrency, and Dirty-State Protection
- **Given** a user with `Perm.Create` and `Perm.Modify`:
- **When** the user creates `notes/todo.md` via `POST /api/v1/mcbrowser/file`, opens it in the editor (`GET /api/v1/mcbrowser/content?path=notes/todo.md`), edits the content, and saves via `PUT /api/v1/mcbrowser/content` (or `Ctrl+S`):
- **Then**:
  - `GET /content` returns `{ path, content, etag }`.
  - `PUT /content` with matching `etag` atomically writes the updated content, updates `user_quotas.used_bytes` by the exact byte delta, and returns the new `etag`.
  - `PUT /content` with a stale `etag` returns `409 Conflict` (`ETAG_MISMATCH`) without overwriting concurrent changes.
  - Navigating away or closing the editor with unsaved changes prompts a confirmation dialog (`DiscardEditorChanges.vue` / `beforeunload`).
  - Files ending in `.md` or `.markdown` offer a sanitized HTML/KaTeX preview toggle (`Editor.vue:30-42,163-175`).

#### `ACC-MUT-02`: Recursive Copy, Move/Rename Cycle Guard, and Recursive Delete with Quota Accounting
- **Given** directory `src` containing `a.txt` (1000 B) and `sub/b.txt` (2000 B), with `user_quotas.used_bytes = 3000`:
- **When**:
  1. User copies `src` to `src/sub/copy` (`POST /api/v1/mcbrowser/copy`) or moves `src` to `src/sub/moved` (`POST /api/v1/mcbrowser/rename`)
  2. User copies `src` to `dst` (`POST /api/v1/mcbrowser/copy`)
  3. User recursively deletes `src` (`POST /api/v1/mcbrowser/delete-recursive`)
- **Then**:
  - Step (1) fails with `400 Bad Request` (`Cannot copy/move directory into itself or a descendant`, matching `http/resource.go:278-281` `checkParent`).
  - Step (2) deep-copies `src` to `dst` using descriptor-confined traversal (`openat2`) and increments `user_quotas.used_bytes` from `3000` to `6000`. If `redirectAfterCopyMove` preference is enabled, the UI navigates to the destination directory (`Copy.vue:150`, `Move.vue:146`).
  - Step (3) deletes `src/sub/b.txt`, `src/sub`, `src/a.txt`, and `src` in bottom-up order and decrements `user_quotas.used_bytes` from `6000` back to `3000` (clamped at 0).

#### `ACC-SEARCH-01`: Subtree Search with Query Modifiers
- **Given** a directory tree under `/media` containing `Holiday.JPG`, `song.mp3`, `clip.mp4`, `report.pdf`, and folder `Holiday_Photos`:
- **When** the user searches under `/media`:
  1. `q=holiday` (default case-insensitive)
  2. `q=case:sensitive Holiday`
  3. `q=type:image holiday` or the native API filter `type=directory&q=holiday`
- **Then**:
  - Query (1) returns both `Holiday.JPG` and `Holiday_Photos` with relative paths from the user root.
  - Query (2) matches `Holiday.JPG` and `Holiday_Photos` but excludes `holiday_notes.txt`.
  - Query (3) filters image MIME types or native directory kind respectively. Upstream `type:dir`, `type:file`, `type:doc` and `type:archive` mean exact extensions, not special categories. Multiple types are OR conditions; unquoted space-separated terms are OR filename substrings, and a wholly quoted query is one phrase. Parent path names do not match leaf-only queries. Results enforce user path/regex rules; hidden-file presentation and traversal limits require separate acceptance.

---

### 3.5 Single-File Streaming Download & Multi-Format Archive Download

- **Upstream Evidence**:
  - `http/raw.go:20-64,93-232`, `frontend/src/components/prompts/Download.vue:1333-1343`, `frontend/src/api/files.ts:82-104`.
  - Supported `algo` values in `parseQueryAlgorithm` (`http/raw.go:41-64`): `zip` (default), `tar`, `targz` (`.tar.gz`), `tarbz2` (`.tar.bz2`), `tarxz` (`.tar.xz`), `tarlz4` (`.tar.lz4`), `tarsz` (`.tar.sz`), `tarbr` (`.tar.br`), `tarzst` (`.tar.zst`).

#### `ACC-DL-01`: Zero-Blob Browser-Native Streaming Download for Large Single Files
- **Given** a 4 GiB file `backups/node.img`:
- **When** the user clicks **Download** on `backups/node.img`:
- **Then**:
  - The download streams directly to the browser's native download manager (e.g., via a short-lived signed download ticket or streaming endpoint navigation) **without** calling `await fetch(...).then(r => r.blob())` in JavaScript memory.
  - Response headers include `Accept-Ranges: bytes`, `Content-Disposition: attachment; filename="node.img"; filename*=UTF-8''node.img`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy: default-src 'none'; sandbox`.

#### `ACC-DL-02`: Multi-File & Folder Archive Streaming Across All 9 Upstream Formats
- **Given** a folder `logs` (or multi-file selection `["a.txt", "sub/b.txt"]`):
- **When** the user triggers archive download and selects each format in the Download modal (`zip`, `tar`, `targz`/`.tar.gz`, `tarbz2`/`.tar.bz2`, `tarxz`/`.tar.xz`, `tarlz4`/`.tar.lz4`, `tarsz`/`.tar.sz`, `tarbr`/`.tar.br`, `tarzst`/`.tar.zst`):
- **Then**:
  - The server streams a valid archive in the requested format with matching extension (`.zip`, `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.lz4`, `.tar.sz`, `.tar.br`, `.tar.zst`).
  - Entry paths inside the archive are normalized relative paths (no leading `/`, no `..` traversal, backslashes neutralized per `http/raw.go:128-135`), and denied descendants (`checkRules`) are excluded.

---

### 3.6 File Info, Directory Counts, Image Dimensions, and Checksums

- **Upstream Evidence**:
  - `files/file.go:170-207` (`Checksum(algo)`: `md5`, `sha1`, `sha256`, `sha512`; returns `errors.ErrInvalidOption` -> `400` on unknown algorithm).
  - `files/file.go:253-260,289-309` (`Resolution`: `{Width, Height}` via `image.DecodeConfig` on image files).
  - `frontend/src/components/prompts/Info.vue:1345-1540` (displays name, human/exact byte size, modified timestamp, image `width x height`, directory `numFiles`/`numDirs`, and on-demand `Show` buttons for `MD5`, `SHA1`, `SHA256`, `SHA512` with click-to-copy).

#### `ACC-INFO-01`: On-Demand MD5, SHA1, SHA256, SHA512 Verification & Metadata
- **Given** a file `hello.txt` containing `"hello world\n"` (12 bytes) and a PNG image `banner.png` (800x600):
- **When** the user opens the **Info** modal and clicks **Show** for `md5`, `sha1`, `sha256`, and `sha512` on `hello.txt`, and opens **Info** on `banner.png` and on a folder `docs`:
- **Then**:
  - `GET /api/v1/mcbrowser/info?path=hello.txt&checksum=md5` returns `checksums.md5 = "6f5902ac237024bdd0c176cb93063dc4"`.
  - `checksum=sha1` returns `"22596363b3de40b06f981fb85d82312e8c0ed511"`.
  - `checksum=sha256` returns `"a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"`.
  - `checksum=sha512` returns `"db3974a97f2407b7cae1ae637c0030687a11913274d578492558e39c16c017de84eacdc8c62fe34ee4e12b4b1428817f09b6a2760c3f8a664ceae94d2434a593"`.
  - Requesting `checksum=crc32` or requesting a checksum on a directory returns `400 Bad Request`.
  - `Info` on `banner.png` returns `resolution: { width: 800, height: 600 }`; `Info` on `docs` returns child `num_files` and `num_dirs`.

---

### 3.7 Media Previews, Thumbnails, Documents, CSV, and Subtitles

- **Upstream Evidence**:
  - `http/preview.go:37-159`, `img/service.go:26-259` (`GET /api/preview/{thumb|big}/{path}?inline=true`: `thumb` = 256x256 JPEG fill, EXIF thumbnail fast-path, `big` = 1080x1080 JPEG fit, `MaxImageWidth = 10000` / `MaxImageHeight = 10000` OOM guard, cache invalidation on overwrite/rename/delete).
  - `files/file.go:30-33,331-391`, `http/subtitle.go:17-92`, `frontend/src/components/files/VideoPlayer.vue` (auto-detects `.vtt`, `.srt`, `.ass`, `.ssa` matching video stem in same folder or `sub`/`subs`/`subtitles` child folders and converts to `text/vtt`).
  - `frontend/src/views/files/Preview.vue:76-153,204-250,309-318`, `frontend/src/components/files/CsvViewer.vue:1-120` (Audio, Video, PDF `<object>`, EPUB reader with saved location/zoom, CSV table viewer up to 5 MiB with delimiter `,`/`;`/both and encoding selector, Prev/Next media navigation).

#### `ACC-MEDIA-01`: Rich Media Streaming, Image Thumbnails, Subtitle Discovery, and Structured Viewers
- **Given** a folder containing `photo.jpg` (4000x3000), `huge_bomb.png` (20000x20000 header), `movie.mp4`, `sub/movie.en.srt`, `track.flac`, `manual.pdf`, `book.epub`, and `data.csv` (with `;` delimiter):
- **When** the user views the folder in Mosaic/Gallery mode and opens each file in the Preview viewer:
- **Then**:
  - `photo.jpg` renders a 256x256 thumbnail in Mosaic view and a 1080x1080 (or full pan/zoom `ExtendedImage`) preview, while `huge_bomb.png` (> 10000x10000) is rejected by the resizer before allocating pixel buffers (`ErrImageTooLarge`).
  - `movie.mp4` streams with HTTP `206 Partial Content` byte-range seeking and automatically loads `sub/movie.en.srt` converted to `text/vtt; charset=utf-8` via `/api/v1/mcbrowser/subtitle` (supporting `.vtt`, `.srt`, `.ass`, `.ssa`).
  - `track.flac` streams in `<audio controls>` with `206 Partial Content`.
  - `manual.pdf` renders inline with `Content-Type: application/pdf` and `Content-Security-Policy: default-src 'none'; frame-ancestors 'self'; sandbox`.
  - `book.epub` renders in a sandboxed EPUB reader (persisting reading position and zoom level in `localStorage`).
  - `data.csv` (< 5 MiB) renders in the interactive CSV table viewer with selectable delimiter (`,`, `;`, or both) and character encoding.
  - Prev/Next buttons and `ArrowLeft`/`ArrowRight` keys navigate across previewable items in the current sorted directory listing.

---

### 3.8 Public Sharing (Passwords, Expiry, Token Auth, and Subtree Confinement)

- **Upstream Evidence**:
  - `http/share.go:1-251`, `http/public.go:1-165`, `share/share.go:1-20`, `share/storage.go:1-125`.
  - `frontend/src/components/prompts/Share.vue`, `frontend/src/views/Share.vue`, `frontend/src/views/settings/Shares.vue`.

#### `ACC-SHARE-01`: Public Share Creation, Expiry, Bcrypt Password & Token Auth, and Subtree Confinement
- **Given** a user with `Perm.Share && Perm.Download` and directory `/releases/v1` containing `app.tar.gz` and `notes.txt`:
- **When**:
  1. User creates a share via `POST /api/v1/mcbrowser/shares` with `{ path: "releases/v1", expires: "2", unit: "hours", password: "correct-horse-battery" }`
  2. Anonymous visitor requests `GET /api/v1/public/mcbrowser/shares/{hash}` without `X-SHARE-PASSWORD`
  3. Anonymous visitor requests `GET /api/v1/public/mcbrowser/shares/{hash}` with `X-SHARE-PASSWORD: wrong`
  4. Anonymous visitor requests `GET /api/v1/public/mcbrowser/shares/{hash}` with `X-SHARE-PASSWORD: correct-horse-battery`
  5. Anonymous visitor downloads `GET /api/v1/public/mcbrowser/dl/{hash}/app.tar.gz?token={token}` and `GET /api/v1/public/mcbrowser/dl/{hash}?algo=targz&token={token}`
  6. Anonymous visitor attempts path escape `GET /api/v1/public/mcbrowser/shares/{hash}/../secret.txt`
  7. Owner deletes `/releases/v1` (or revokes the share via `DELETE /api/v1/mcbrowser/shares/{hash}`, or expiry timestamp passes)
- **Then**:
  - Step (1) stores a bcrypt password hash (never returning `password_hash` or `token` in the management response) and returns `{ hash, path, expire, has_password: true }`.
  - Steps (2) and (3) return `401 Unauthorized`.
  - Step (4) verifies the bcrypt password and returns `200 OK` with directory entries inside `releases/v1` plus the share's random 96-byte base64 `token`.
  - Step (5) verifies `?token=` using constant-time comparison (`subtle.ConstantTimeCompare` equivalent) and streams the single file or archive.
  - Step (6) is confined to the shared subtree (`releases/v1`) plus the owner's `checkerPrefix` rules (`http/public.go:39-44`) and fails with `400`/`404`.
  - Step (7) automatically removes or invalidates the share so subsequent public requests return `404 Not Found`.

---

## 4. Safe Native Designs for Unsafe Upstream Capabilities (No Silent Waivers)

### 4.1 Safe Native Replacement for Shell, Command Actions, and Event Hooks

#### Upstream Unsafe Evidence
1. **Interactive WebSocket Shell (`http/commands.go:40-120`, `frontend/src/components/Shell.vue`)**:
   - `GET /api/command/{path}` upgrades to a WebSocket, reads a command line, parses it with ` runner.ParseCommand(d.settings, raw)`, checks only whether `slices.Contains(d.user.Commands, name)` (or passes `raw` directly to `d.settings.Shell` if configured in `runner/parser.go:12-27`), sets `cmd.Dir = d.user.FullPath(r.URL.Path)`, and spawns `exec.Command(command[0], command[1:]...)` on the host OS.
2. **Lifecycle Event Hooks (`runner/runner.go:19-118`, `http/resource.go:63,119,179,239`, `http/tus_handlers.go:269`)**:
   - Executes arbitrary blocking/non-blocking host commands on `before_*` / `after_*` (`upload`, `delete`, `save`, `copy`, `rename`), interpolating user-controlled paths into `$FILE`, `$SCOPE`, `$TRIGGER`, `$USERNAME`, and `$DESTINATION` via `os.ExpandEnv` and `cmd.Env`.
3. **Why This Violates AetherFlow Security Invariants**:
   - Spawning host processes with `cmd.Dir` inside user storage bypasses `af-files` `openat2(RESOLVE_BENEATH)` descriptor confinement, enables symlink/TOCTOU root escapes, exposes host environment/network/filesystem state to web users, and creates command/argument injection vectors when filenames start with `-` or contain shell metacharacters.

#### Safe Native Architecture (Mandatory Design)
1. **No Arbitrary Host Shell Execution**:
   - `GET /api/command` (arbitrary WebSocket shell) is **permanently prohibited** in `af-api`. `Perm.Execute` must never spawn `sh`, `bash`, or arbitrary binaries from `$PATH`.
2. **Typed, Sandboxed Built-In File Actions (Replacing User Command Runner)**:
   - Instead of raw shell commands, `Perm.Execute` gates a **closed enum of in-process Rust file actions** operating strictly on file descriptors opened via `BrowserFs` (`openat2(RESOLVE_BENEATH)`):
     - `Action::ComputeChecksums { path, algorithms }`
     - `Action::ExtractArchive { archive_path, destination_dir }` (bounded decompression ratio, entry count cap, and `BrowserFs` descriptor writes so zip-slip is structurally impossible)
     - `Action::CreateArchive { source_paths, destination_path, format }`
     - `Action::InspectMediaMetadata { path }`
3. **Structured In-Process Event Bus & Audit Log (Replacing `before_*` / `after_*` Shell Hooks)**:
   - All filesystem mutations (`UploadCompleted`, `EntryDeleted`, `FileSaved`, `EntryCopied`, `EntryRenamed`, `ShareCreated`, `ShareRevoked`) emit a strongly-typed Rust struct `McBrowserAuditEvent { event_id, timestamp, user_id, username, trigger, relative_path, destination_path, byte_delta }` to:
     1. AetherFlow's SQLite audit log (`mcbrowser_audit_events`) for admin visibility.
     2. An optional, admin-configured **webhook / internal AetherFlow task queue** that serializes the event as JSON over HTTP/IPC—**never** interpolating filenames into shell strings or process arguments.

---

### 4.2 Safe Native Design for Internal Symlinks Without Root Escape or TOCTOU

#### Upstream vs Current Native Behavior
- **Upstream (`files/scoped.go:43-157`, `files/file.go:414-431`, `settings/settings.go:65`)**:
  - Upstream `ScopedFs.within()` resolves paths in userland using `filepath.EvalSymlinks` and a manual `os.Lstat` + `os.Readlink` loop (`maxSymlinkHops = 40`) to check whether a symlink's target stays inside the user's scope root, hiding out-of-scope symlinks (`os.ErrPermission`) and marking broken in-scope symlinks as `invalid_link`. Upstream also offers `FollowExternalSymlinks`, which intentionally allows escaping the scope root.
  - **Defect**: Userland `EvalSymlinks` followed by standard path-based `os.Open`/`os.Remove`/`os.Rename` has a classic **TOCTOU race window**, and `FollowExternalSymlinks` is a direct host-filesystem escape.
- **Current Native (`backend-rs/crates/af-files/src/lib.rs:20-23,128,430-467`)**:
  - `af-files` passes `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` to `openat2` and rejects `EntryKind::Symlink` in `remove()` and `rename()`. As a result, users cannot even delete or rename an existing symlink inside their own folder, nor can they use valid relative symlinks that stay strictly within their own root.

#### Safe Native Kernel-Enforced Internal Symlink Design
1. **`FollowExternalSymlinks` Is Permanently Prohibited**:
   - No symlink may ever resolve outside the user's `self.root_fd` (`user-{id}` root) or across procfs/magiclinks (`RESOLVE_NO_MAGICLINKS` is always set).
2. **Allow Safe Management (Delete, Rename, Inspect) of Symlink Entries Themselves (`O_NOFOLLOW`)**:
   - In `BrowserFs::list_dir_fd`: use `fstatat(dir_fd, name, AT_SYMLINK_NOFOLLOW)` and `readlinkat(dir_fd, name)`.
   - In `BrowserFs::remove` and `BrowserFs::rename`: resolve the **parent directory** from `self.root_fd` using `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` and execute `unlinkat(parent_fd, leaf, 0)` or `renameat2(old_parent_fd, old_leaf, new_parent_fd, new_leaf, RENAME_NOREPLACE)`. Both syscalls act on the symlink inode itself without dereferencing its target, allowing users to safely clean up or rename symlinks inside their tree.
3. **Zero-TOCTOU Kernel-Constrained Dereferencing for Internal Symlinks**:
   - When opening a file or directory for **read/stat/list/download** or resolving a parent directory from `self.root_fd`:
     - Invoke `openat2(self.root_fd, full_relative_path, &OpenHow { flags: O_RDONLY | O_CLOEXEC, mode: 0, resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS })` **anchored directly at `self.root_fd`** (rather than hop-by-hop with `RESOLVE_NO_SYMLINKS`).
     - **Why this is race-free**: When `openat2` is called on `self.root_fd` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` (without `RESOLVE_NO_SYMLINKS`), the Linux kernel resolves relative symlinks atomically in-kernel and guarantees that **every intermediate and final component remains strictly beneath `self.root_fd`**. Any symlink pointing to `/etc/passwd`, `../../other-user`, or a `/proc/self/fd/*` magiclink fails inside the kernel with `EXDEV` (`ErrorKind::PermissionDenied`) or `ELOOP`—with zero userland TOCTOU window!
     - If `openat2(self.root_fd, rel_path, RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` fails with `EXDEV` on a symlink entry during directory listing, classify the entry as `symlink_blocked` (or omit it per upstream `files/file.go:419`); if it fails with `ENOENT`, classify it as `invalid_link` (broken internal symlink, matching `files/file.go:426`); if it succeeds, populate `symlink_target` and target metadata (`file` vs `dir`).
4. **Safe Internal Symlink Creation (`symlinkat`) & Mutation Leaf Protection**:
   - If symlink creation is enabled (`POST /api/v1/mcbrowser/symlink`), validate `target` lexically: reject absolute paths (`target.starts_with('/')`), backslashes, and NUL bytes, and verify that normalizing `parent_rel_path.join(target)` does not ascend above root (`..` depth check) before calling `symlinkat(target, parent_fd, leaf_name)`.
   - All **write/overwrite/delete leaf operations** (`begin_upload`, `put_content`, `unlinkat`) must continue opening the final leaf with `O_NOFOLLOW` so uploading or deleting a symlink path never silently overwrites or deletes the target file.

---

## 5. Prioritized Must-Pass Release Blockers

To reach verified parity without relying on unmounted code or unsafe behaviors, the following blockers must be resolved in priority order:

1. **[BLOCKER-1] Mount and Wire Concurrent Backend & Frontend Modules End-to-End**:
   - `backend-rs/crates/af-api/src/mcbrowser.rs` currently mounts only 7 basic routes; `mcbrowser/{uploads,operations,media}.rs` are unmounted dead code, and `McBrowserWorkspace.tsx` is not rendered by `frontend/src/components/tabs/McBrowserTab.tsx`.
   - **Must-Pass Test**: `cargo test -p af-api` and `npm test` exercising all routes through `mcbrowser::router()` and `McBrowserTab.tsx`.
2. **[BLOCKER-2] Complete Missing Backend Modules (`shares`, `policy`, `preferences`, `usage`) Called by Frontend**:
   - `frontend/src/lib/mcbrowser-workspace.ts` calls `/mcbrowser/shares`, `/public/mcbrowser/shares/*`, `/mcbrowser/policy`, `/mcbrowser/preferences`, and `/mcbrowser/usage`, none of which exist in `backend-rs/crates/af-api/src/mcbrowser/`.
   - Furthermore, `uploads.rs:120` has `authorize_create_permission` stubbed to `Ok(())`, and `media.rs:51` calls an undefined `authorize(&user, Permission::Read, &path)`.
   - **Must-Pass Test**: `ACC-PERM-01`, `ACC-PERM-02`, `ACC-PREF-01`, `ACC-SHARE-01`.
3. **[BLOCKER-3] Eliminate Browser `res.blob()` Full-File RAM Buffering on Single-File and Archive Downloads**:
   - `frontend/src/lib/mcbrowser.ts:276-308` (`downloadMcBrowserFile`) and `frontend/src/lib/mcbrowser-workspace.ts:395-417` (`downloadMcBrowserArchive`) buffer entire downloads into browser RAM via `await res.blob()`.
   - **Must-Pass Test**: `ACC-DL-01` (browser-native streaming download without `res.blob()`).
4. **[BLOCKER-4] Expand Archive Formats from 3 (`zip`, `tar`, `tar.gz`) to All 9 Upstream Formats (or Document Explicit Codec Support)**:
   - Upstream `http/raw.go:41-64` and `Download.vue:1333-1343` support `zip`, `tar`, `targz`, `tarbz2`, `tarxz`, `tarlz4`, `tarsz`, `tarbr`, `tarzst`. Unmounted `operations.rs:154` only accepts `"zip"`, `"tar"`, `"tar.gz"`.
   - **Must-Pass Test**: `ACC-DL-02`.
5. **[BLOCKER-5] Wire Drag-and-Drop Empty-Directory Creation & Upload/Copy/Move Conflict Resolution**:
   - Wire `scanTransferItems` (`webkitGetAsEntry`) + `createEmptyDirectories` into the live dropzone (`ACC-UPL-01`) and ensure Copy/Move endpoints (`/copy`, `/rename`) support `override` and `rename` (`base(1).ext`) conflict modes (`ACC-UPL-03`).
6. **[BLOCKER-6] Complete Subtitle Discovery (`.ass`/`.ssa` + `sub`/`subs`/`subtitles` dirs), Server Image Thumbnails, and Info Directory Counts/Image Dimensions**:
   - Extend `media.rs` `/mcbrowser/subtitle` to convert `.ass`/`.ssa` and discover sidecars in `sub`/`subs`/`subtitles` subdirectories (`ACC-MEDIA-01`), add bounded thumbnail generation with `10000x10000` dimension guard, and include directory `num_files`/`num_dirs` + image `resolution` in `/mcbrowser/info` (`ACC-INFO-01`).
7. **[BLOCKER-7] Implement Safe Kernel-Enforced Internal Symlink Handling & Allow Unlinking/Renaming Symlink Entries**:
   - Allow `unlinkat`/`renameat2` on symlink entries (`O_NOFOLLOW` on leaf) and use `openat2(root_fd, rel_path, RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)` for safe in-root symlink traversal (`Section 4.2`).
