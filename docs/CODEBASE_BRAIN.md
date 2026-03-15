# AetherFlow Codebase Brain

Audit date: 2026-03-15

## Scope
- Go backend: `backend/` — Gin router, JWT auth, WebSocket, SQLite, service management
- Next.js frontend: `frontend/src/` — React 19, Zustand, SWR, Tailwind CSS
- Setup/provisioning: `setup/`, `packages/`, `scripts/`
- Configuration: `backend/config/packages.json`, `backend/config/package_automation.json`, embedded OpenAPI spec, env vars

## Architecture

### Backend (Go 1.25 / Gin)
| Layer | Files |
|-------|-------|
| Entry/CORS | `backend/main.go` |
| Routing/Auth | `backend/api/routes.go`, `backend/api/auth.go`, `backend/api/versioning.go` |
| WebSocket (authenticated) | `backend/api/websockets.go` |
| Features | `backend/api/` — services, marketplace, fileshare, backup, updater, AI, settings, quotas, billing |
| System execution | `backend/services/systemctl.go`, `backend/services/installer.go`, `backend/services/quota_manager.go` |
| Database | `backend/db/db.go` (SQLite, canonical path: `backend/data/`) |
| Config | `backend/config/packages.json`, `backend/config/package_automation.json`, `backend/api/spec/openapi-v1.yaml` |

### Frontend (Next.js 16 / React 19)
| Layer | Files |
|-------|-------|
| App shell | `frontend/src/app/layout.tsx` — ThemeProvider → LanguageProvider → ToastProvider → SWRProvider → AuthProvider → AuthGuard → WebSocketProvider |
| Dashboard | `frontend/src/app/page.tsx` — reads `useSystemStore` (Zustand), renders tabs |
| State (Zustand) | `frontend/src/store/useSystemStore.ts` — activeTab, sidebar, theme, language |
| Connection state | `frontend/src/store/useConnectionStore.ts` — WS connection state machine |
| Data fetching | `frontend/src/lib/fetcher.ts`, `frontend/src/components/layout/SWRProvider.tsx` |
| WebSocket lifecycle | `frontend/src/contexts/WebSocketContext.tsx` — exponential backoff, heartbeat, fallback polling |
| Metrics hook | `frontend/src/hooks/useMetrics.ts` — SWR + WebSocket fusion, globalMutate for services |
| Auth | `frontend/src/contexts/AuthContext.tsx` |
| E2E/Visual tests | `frontend/playwright.config.ts`, `frontend/tests/e2e/*` |
| Tabs | `frontend/src/components/tabs/*` — zero-prop components using Zustand |

### Provisioning
| Component | Files |
|-----------|-------|
| Installer | `setup/AetherFlow-Setup`, `setup/modules/*.sh` |
| Package lifecycle | `packages/package/install/*`, `packages/package/remove/*` |
| System CLI | `packages/system/*` |
| Plugin SDK | `plugins/sdk-template/`, `scripts/create-plugin-sdk.sh` |

## Security audit (v4.0)

### ✅ Resolved (since v3.x audit)
1. **JWT secret**: Now `log.Fatal` on missing `JWT_SECRET` — no fallback.
2. **Cookie security**: `Secure` flag configurable via `COOKIE_SECURE` env; `SameSite=Lax` on all cookies.
3. **WebSocket origin**: Proper `url.Parse` comparison instead of `strings.HasSuffix`.
4. **WebSocket auth**: JWT cookie validated on upgrade — unauthenticated clients rejected.
5. **File upload sanitization**: `filepath.Base`, double-extension blocking, null byte stripping.
6. **File upload limits**: 50 MB size limit via `MaxBytesReader`, content-type sniffing blocks executables.
7. **Service control**: Moved behind `AdminOnly()` middleware with action allowlist.
8. **JWT alg validation**: All `jwt.Parse` calls now verify HMAC signing method to prevent algorithm confusion.
9. **Password policy**: 8-char minimum enforced on local accounts.

### ⚠️ Remaining findings

#### High
1. **Hardcoded SSH credentials**: `temp_ssh.go`, `temp_ssh.js`, `ssh_tool.py`, `ssh_pty.py` still contain committed credentials.
   - **Action**: Delete these files and rotate any reused secrets.
2. **Global shared user hardcode**: `packages/common.sh:5` uses `AETHERFLOW_USER` variable.
   - **Action**: Resolve via runtime environment variable.
3. **Remote script piping**: Install scripts pipe `curl | bash` (supply-chain risk).
   - **Action**: Download, verify checksum, then execute.

#### Medium
1. **30-day JWT tokens**: No refresh mechanism. Long-lived tokens increase session hijacking window.
2. **Panic risks**: Unchecked type assertions in `auth.go` (GoogleCallback userInfo parsing).
3. **Metrics loop**: 3s tick + 15s service tick — acceptable, but `systemctl cat` per service is expensive.
4. **AI chat endpoint**: `/api/ai/chat` has no auth requirement.

### Legacy status
- `dashboard/config/` — **DELETED** (migrated to `backend/config/`)
- `dashboard/db/` — kept as legacy fallback; canonical is now `backend/data/`
- `dashboard/fileshare/uploads` — **REMOVED** from path lookups
- `docs/API.md` — **REWRITTEN** for Go Gin API (was PHP-only)
- `docs/BOOTSTRAP5_MIGRATION.md` — **DELETED** (frontend is Tailwind CSS)
- `docs/DEPENDENCIES.md` — **DELETED** (use `package.json` + `go.mod`)

## File-map
| Domain | Files |
|--------|-------|
| API auth | `backend/api/auth.go`, `backend/api/routes.go` |
| WebSocket | `backend/api/websockets.go` |
| Service control | `backend/services/systemctl.go` |
| Package pipeline | `backend/api/marketplace.go`, `backend/services/installer.go`, `backend/config/packages.json`, `backend/config/package_automation.json` |
| API versioning | `backend/api/versioning.go`, `backend/api/spec/openapi-v1.yaml`, `backend/api/openapi.go` |
| Quotas & billing | `backend/api/quota_handlers.go`, `backend/services/quota_manager.go`, `packages/system/setdisk`, `packages/system/showspace` |
| Update pipeline | `backend/api/updater.go`, `scripts/update.sh` |
| Database | `backend/db/db.go` |
| File uploads | `backend/api/fileshare.go` |
| Backups | `backend/api/backup.go` |
| Frontend state | `frontend/src/store/useSystemStore.ts`, `frontend/src/store/useConnectionStore.ts` |
| Frontend data | `frontend/src/hooks/useMetrics.ts`, `frontend/src/hooks/useMarketplace.ts`, `frontend/src/lib/fetcher.ts` |
| Frontend WS | `frontend/src/contexts/WebSocketContext.tsx` |
| Frontend layout | `frontend/src/app/layout.tsx`, `frontend/src/app/page.tsx` |
| Frontend tests | `frontend/tests/e2e/login.spec.ts`, `frontend/tests/e2e/navigation.spec.ts`, `frontend/tests/e2e/marketplace.install.spec.ts`, `frontend/tests/e2e/visual.spec.ts` |
