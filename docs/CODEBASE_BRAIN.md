# AetherFlow Codebase Brain

Audit date: 2026-03-09

## Scope
- Tracked files audited: 957
- Text files scanned line-by-line: 877
- Binary/archive files cataloged: 80
- Full per-file inventory: `docs/CODEBASE_BRAIN_INVENTORY.csv`

## Coverage model
- Manual deep read: `backend/`, `frontend/src/`, setup modules, system scripts, package manager, updater paths.
- Automated line scan across all tracked files for secrets, destructive ops, auth/cookie/CORS/WS patterns, legacy markers.
- Vendor payload (`setup/sources/xmlrpc-c_1-39-13`) treated as third-party code and cataloged separately.

## Architecture brain
- Runtime backend (Go):
  - Entry/CORS bind: `backend/main.go`
  - Routing/auth/session: `backend/api/routes.go`, `backend/api/auth.go`
  - Features: services, marketplace, fileshare, backup, updater, AI, websocket metrics
  - System control execution: `backend/services/systemctl.go`, `backend/services/installer.go`
- Runtime frontend (Next.js):
  - App shell/auth guard: `frontend/src/app/layout.tsx`, `frontend/src/components/layout/AuthGuard.tsx`
  - Dashboard orchestration: `frontend/src/app/page.tsx`
  - Metrics stream and history: `frontend/src/contexts/WebSocketContext.tsx`, `frontend/src/hooks/useMetrics.ts`
  - Domain tabs: `frontend/src/components/tabs/*`
- Provisioning and legacy ops:
  - Installer orchestrator: `setup/AetherFlow-Setup`
  - Setup modules: `setup/modules/*.sh`
  - Package lifecycle scripts: `packages/package/install/*`, `packages/package/remove/*`
  - System commands/utilities: `packages/system/*`

## High-severity findings

### Critical
1. Unauthenticated privileged endpoints exist outside `AdminOnly()` group.
   - `backend/api/routes.go:55`
   - `backend/api/routes.go:56`
   - `backend/api/routes.go:60`
   - `backend/api/routes.go:61`
   - `backend/api/routes.go:65`
   - `backend/api/routes.go:66`

2. Service control accepts caller-provided `action` and `process` with no allowlist.
   - `backend/api/routes.go:104`
   - `backend/api/routes.go:116`
   - `backend/api/routes.go:123`
   - `backend/services/systemctl.go:165`
   - `backend/services/systemctl.go:167`

3. JWT secret falls back to a hardcoded default when env is missing.
   - `backend/api/auth.go:29`

4. Session/OAuth cookies are issued with `secure=false`.
   - `backend/api/auth.go:78`
   - `backend/api/auth.go:135`
   - `backend/api/auth.go:161`
   - `backend/api/auth.go:312`
   - `backend/api/auth.go:374`

5. WebSocket origin check allows all origins.
   - `backend/api/websockets.go:19`
   - `backend/api/websockets.go:20`

6. File upload destination uses unsanitized client filename.
   - `backend/api/fileshare.go:80`

7. Hardcoded SSH credentials/host data committed in repo helpers.
   - `temp_ssh.go:16`
   - `temp_ssh.go:18`
   - `temp_ssh.go:21`
   - `temp_ssh.js:29`
   - `temp_ssh.js:71`
   - `temp_ssh.js:74`
   - `ssh_tool.py:35`
   - `ssh_pty.py:43`

8. Global shared user is hardcoded in common package shell library.
   - `packages/common.sh:5`

### High
1. Installer path includes default insecure credentials and root-level filebrowser scope.
   - `packages/package/install/installpackage-filebrowser:24`
   - `packages/package/install/installpackage-filebrowser:25`
   - `packages/package/install/installpackage-filebrowser:36`
   - `packages/package/install/installpackage-filebrowser:62`

2. Remote script piping to shell in install flows (supply-chain risk).
   - `packages/package/install/installpackage-filebrowser:19`
   - `packages/package/install/installpackage-flood:20`
   - `packages/package/install/installpackage-overseerr:20`
   - `packages/package/install/installpackage-uptimekuma:20`
   - `setup/modules/modern_stack.sh:17`

3. Update flows force-reset local code state.
   - `scripts/update.sh:18`
   - `scripts/update.sh:19`
   - `packages/system/af:125`
   - `packages/system/af:126`
   - `packages/system/updateAetherFlow:42`
   - `packages/system/updateAetherFlow:43`

4. Legacy scripts still target removed `/srv/rutorrent` layout and/or reference unset `rutorrent` variable.
   - `packages/system/set_interface:22`
   - `packages/system/set_interface:23`
   - `packages/system/set_interface:24`
   - `packages/system/set_interface:25`
   - `packages/system/theme/themeSelect-defaulted:22`
   - `packages/system/theme/themeSelect-defaulted:46`
   - `packages/system/theme/themeSelect-smoked:22`
   - `packages/system/theme/themeSelect-smoked:46`

### Medium
1. Panic risks from unchecked type assertions in auth/AI handlers.
   - `backend/api/auth.go:215`
   - `backend/api/auth.go:356`
   - `backend/api/auth.go:401`
   - `backend/api/auth.go:436`
   - `backend/api/ai.go:99`

2. Metrics loop polls every 100ms and executes expensive system calls per tick.
   - `backend/api/websockets.go:133`
   - `backend/api/websockets.go:148`
   - `backend/api/websockets.go:151`

3. Frontend onboarding model list is out of sync with backend defaults/runtime model set.
   - `frontend/src/components/layout/OnboardingWizard.tsx:16`
   - `frontend/src/components/layout/OnboardingWizard.tsx:112`
   - `backend/db/db.go:52`
   - `backend/api/ai.go:54`

4. Marketplace icon path expects `/img/brands/*` while assets are under `/public/img/*`.
   - `frontend/src/components/tabs/MarketplaceTab.tsx:16`

## File-map for fast navigation
- API auth/session stack: `backend/api/auth.go`, `backend/api/routes.go`
- System command execution: `backend/services/systemctl.go`
- Package execution pipeline: `backend/api/marketplace.go`, `backend/services/installer.go`
- Update pipeline: `backend/api/updater.go`, `scripts/update.sh`, `packages/system/updateAetherFlow`
- Setup orchestrator/state machine: `setup/AetherFlow-Setup`, `setup/modules/06-state.sh`
- Legacy compatibility hotspot: `packages/system/*`, `setup/templates/bashrc.template`
- Frontend dataflow root: `frontend/src/app/page.tsx`, `frontend/src/hooks/useMetrics.ts`, `frontend/src/contexts/WebSocketContext.tsx`

## Inventory schema (`CODEBASE_BRAIN_INVENTORY.csv`)
- `path`: tracked file path
- `category`: high-level bucket
- `extension`: extension or `[noext]`
- `size_bytes`: file size
- `line_count`: text line count when parsable
- `likely_binary`: heuristic binary/archive indicator
- `secret_hits`: keyword hit count (triage signal)
- `destructive_hits`: destructive/remote-exec hit count
- `network_hits`: external network/proxy/API hit count
- `auth_hits`: auth/cookie/jwt/cors/ws hit count
- `legacy_hits`: legacy/deprecated/mock/todo hit count
- `notes`: focused flags (`default-jwt-secret-fallback`, `websocket-all-origins`, etc.)

## Immediate hardening priority
1. Gate `/services/:name/control`, `/packages/:id/*`, and `/system/update/run` behind auth + admin middleware.
2. Remove JWT fallback secret; fail startup if `JWT_SECRET` missing.
3. Set secure cookies in production and define explicit same-site policy.
4. Lock down websocket origin checks to trusted hosts.
5. Sanitize upload filenames via `filepath.Base` and enforce allowlist/size limits.
6. Remove committed SSH helper credentials and rotate any reused secrets.
7. Replace `AETHERFLOW_USER` hardcoding with runtime/environment resolution.
8. Retire or quarantine legacy `/srv/rutorrent` scripts from active update paths.
