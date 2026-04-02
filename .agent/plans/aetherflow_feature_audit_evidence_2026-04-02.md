# AetherFlow Feature Audit Evidence

Date: 2026-04-02

## Audit Metadata
- Branch: `audit/feature-matrix-2026-04-02`
- Base branch: `master`
- Base commit: `73cb79a378cefddf4a25bc6d9b65c20db1af8473`
- Branch creation method: raw `.git` ref update, because `git.exe` was not available in the shell environment
- Deliverables:
  - `.agent/plans/aetherflow_feature_audit_evidence_2026-04-02.md`
  - `.agent/plans/aetherflow_feature_audit_matrix_2026-04-02.md`

## Search Profile
- Included roots: `backend/`, `frontend/src/`, `.agent/plans/`
- Excluded from scans: `.git/`, `node_modules/`, `frontend/.next/`, compiled binaries such as `backend/aetherflow-api.exe`, generated swagger artifacts unless directly referenced, runtime upload/data directories unless a phase required them
- Primary command engine: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

## Repeatable Commands
```powershell
# branch setup, because git.exe was unavailable
C:\Windows\System32\cmd.exe /c mkdir .git\refs\heads\audit 2>nul & > .git\refs\heads\audit\feature-matrix-2026-04-02 echo 73cb79a378cefddf4a25bc6d9b65c20db1af8473 & > .git\HEAD echo ref: refs/heads/audit/feature-matrix-2026-04-02

# backend marker scan
Get-ChildItem backend -Recurse -Include *.go | Select-String -Pattern TODO,FIXME,XXX,HACK,stub,pending,mock,'not implemented' -SimpleMatch -Context 1,2

# backend status-code scan
Select-String -Path backend\api\*.go,backend\services\*.go -Pattern StatusNotImplemented,501 -SimpleMatch

# frontend marker and hardcoded-data scan
Select-String -Path frontend\src\app\*.tsx,frontend\src\components\*\*.tsx,frontend\src\contexts\*.tsx,frontend\src\hooks\*.ts,frontend\src\lib\*.ts,frontend\src\store\*.ts -Pattern TODO,'disabled={true}','const mock','mockData' -SimpleMatch

# route tree source of truth
Get-Content backend\api\routes.go

# fetcher inventory source of truth
Select-String -Path frontend\src\app\*.tsx,frontend\src\components\*\*.tsx,frontend\src\contexts\*.tsx,frontend\src\hooks\*.ts,frontend\src\lib\*.ts -Pattern '/api/' -SimpleMatch

# schema coverage source of truth
Select-String -Path backend\api\*.go,backend\services\*.go,backend\cluster\*.go -Pattern 'settings','users','login_history','cluster_nodes','oidc_clients','oidc_auth_codes','oidc_refresh_tokens','log_bookmarks','notifications','notification_rules','notification_channels','user_quotas','billing_webhook_events','vpn_configs','app_updates','media_metadata','metrics_history','schema_versions' -SimpleMatch
```

## Phase Group 1: Automated Codebase Scan

### Negative Results
- No backend `TODO`, `FIXME`, `XXX`, or `HACK` markers were found in runtime Go files.
- No explicit `http.StatusNotImplemented` or literal `501` responses were found in backend handlers or services.
- No frontend `TODO` markers, `disabled={true}` markers, or `const mockData = [...]` declarations were found in runtime `frontend/src` code.

### Explicit Marker Inventory
| finding_id | file | line | marker_type | context | probable feature |
| --- | --- | ---: | --- | --- | --- |
| `BE-MARKER-001` | `backend/api/bandwidth.go` | 32 | comment: `stub` | `HandleBandwidthApply is a stub that accepts recommended limits.` | Bandwidth apply daemon integration |
| `FE-UI-004` | `frontend/src/components/layout/Header.tsx` | 50 | comment: `Mock` | `User Profile Mock` comment above a button with no data wiring or action | Header account/profile controls |

### Test-Only Mock References Excluded From the Feature Matrix
- `backend/api/api_test.go:292`
- `backend/api/auth_security_test.go:201`
- `backend/api/routes_security_test.go:17`
- `backend/api/routes_security_test.go:58`
- `backend/api/routes_security_test.go:122`
- `frontend/src/components/layout/AuthGuard.test.tsx:12`
- `frontend/src/components/layout/AuthGuard.test.tsx:17`

### Backend HTTP Status Audit
- No explicit `501` or `StatusNotImplemented` handlers exist.
- Manual handler review still found placeholder or partial-success behavior:
  - `BE-MARKER-001`: [bandwidth.go](C:/Users/armyw/OneDrive/Documents/Antigravity/Projects/AetherFlow/backend/api/bandwidth.go) says `HandleBandwidthApply` is a stub, but the handler now attempts a live Transmission RPC call.
  - `ARCH-004`: [smart_backup.go](C:/Users/armyw/OneDrive/Documents/Antigravity/Projects/AetherFlow/backend/api/smart_backup.go) returns success when schedule mode changes even if no Gemini key is available and no fresh window is computed.
  - `BE-SERVICE-001`: package install and uninstall routes return `200 OK` immediately after queueing an async job; downstream script failure is only observable via job state/log output.

### Backend Mock Logging Sweep
- No production `fmt.Println` or `log.Println` calls with `not implemented` were found.
- Relevant partial-state logging found:
  - `backend/api/crypto.go:33` logs that encryption is disabled in dev/test when `AES_MASTER_KEY` is absent.
  - `backend/services/smart_backup.go:50` logs `disabled (mode=manual)`.
  - `backend/services/smart_backup.go:88` and `:93` log that window calculation is skipped when no Gemini key is available.

### Backend Null Return Sweep
| finding_id | file | lines | return pattern | contract risk | notes |
| --- | --- | --- | --- | --- | --- |
| `BE-SERVICE-001` | `backend/services/package_service.go` | `126`, `131` | `return nil` | High | `GetPackages()` returns `nil` when `packages.json` is missing or invalid. Marketplace and service views then degrade to empty state instead of surfacing configuration failure. |
| `BE-SERVICE-002` | `backend/services/package_service.go` | `67`, `72` | `return nil` | Medium | `loadPackageAutomation()` silently drops package automation metadata on read or unmarshal failure. Updates and sandbox metadata disappear without operator feedback. |

### Frontend Marker and Interaction Sweep
| finding_id | file | lines | element | observed behavior | implication |
| --- | --- | --- | --- | --- | --- |
| `FE-UI-001` | `frontend/src/components/tabs/SecurityTab.tsx` | `24`, `40`, `51` | Change password, token generation, revoke sessions buttons | Buttons render with no `fetch`, `useSWR`, or backend mutation path | Entire security feature set is placeholder UI |
| `FE-UI-004` | `frontend/src/components/layout/Header.tsx` | `50` | Header profile button | Marked as mock and not wired to auth state or navigation | Account surface is decorative only |
| `FE-UI-006` | `frontend/src/components/tabs/FileshareTab.tsx` | runtime review | Download icon button | Renders as a button with no `href` or click handler | Files can be listed but not downloaded from the UI |

### Frontend Hardcoded and Placeholder Sweep
- No direct `mockData` arrays were found in runtime code.
- Placeholder/static UI still exists:
  - `FE-UI-001`: [SecurityTab.tsx](C:/Users/armyw/OneDrive/Documents/Antigravity/Projects/AetherFlow/frontend/src/components/tabs/SecurityTab.tsx)
  - `FE-UI-004`: [Header.tsx](C:/Users/armyw/OneDrive/Documents/Antigravity/Projects/AetherFlow/frontend/src/components/layout/Header.tsx)
  - `frontend/src/components/tabs/ProfileTab.tsx:69` uses `https://via.placeholder.com/150` as an avatar fallback

## Phase Group 2: API and Contract Reconciliation

### Backend Route Tree
All non-root routes below are mounted twice:
- canonical versioned path under `/api/v1/...`
- legacy alias under `/api/...`

#### Public
| method | route | tier | handler | source |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/public/openapi.yaml` | `public` | `GetOpenAPISpec` | `backend/api/routes.go` |
| `GET` | `/api/v1/public/swagger/*any` | `public` | `ginSwagger.WrapHandler(...)` | `backend/api/routes.go` |
| `GET` | `/api/v1/public/csrf-token` | `public` | `issueCSRFToken` | `backend/api/routes.go` |
| `GET` | `/api/v1/public/auth/google/login` | `public` | `GoogleLogin` | `backend/api/routes.go` |
| `GET` | `/api/v1/public/auth/google/callback` | `public` | `GoogleCallback` | `backend/api/routes.go` |
| `POST` | `/api/v1/public/auth/login` | `public` | `LocalLogin` | `backend/api/routes.go` |
| `POST` | `/api/v1/public/auth/setup` | `public` | `SetupAdmin` | `backend/api/routes.go` |
| `GET` | `/api/v1/public/auth/setup/check` | `public` | `CheckSetupNeeded` | `backend/api/routes.go` |
| `POST` | `/api/v1/public/billing/webhooks/:provider` | `public` | `HandleBillingWebhook` | `backend/api/routes.go` |
| `GET` | `/api/v1/public/marketplace` | `public` | `GetMarketplaceApps` | `backend/api/routes.go` |
| `GET` | `/api/v1/public/oidc/jwks` | `public` | `OIDCJwks` | `backend/api/routes.go` |
| `GET` | `/api/v1/public/oidc/authorize` | `public` | `OIDCAuthorize` | `backend/api/routes.go` |
| `POST` | `/api/v1/public/oidc/token` | `public` | `OIDCToken` | `backend/api/routes.go` |
| `GET` | `/api/v1/public/oidc/userinfo` | `public` | `OIDCUserInfo` | `backend/api/routes.go` |
| `POST` | `/api/v1/public/oidc/revoke` | `public` | `OIDCRevoke` | `backend/api/routes.go` |

#### Auth
| method | route | tier | handler | source |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/auth/ws` | `auth` | `HandleWebSocket` | `backend/api/routes.go` |
| `GET` | `/api/v1/auth/ws/ticket` | `auth` | `IssueWSTicket` | `backend/api/routes.go` |
| `POST` | `/api/v1/auth/oidc/consent` | `auth` | `OIDCConsent` | `backend/api/routes.go` |
| `POST` | `/api/v1/auth/ai/chat` | `auth` | `handleAiChat` | `backend/api/routes.go` |
| `POST` | `/api/v1/auth/ai/support` | `auth` | `handleAiSupport` | `backend/api/routes.go` |
| `GET` | `/api/v1/auth/session` | `auth` | `GetSession` | `backend/api/routes.go` |
| `POST` | `/api/v1/auth/logout` | `auth` | `Logout` | `backend/api/routes.go` |
| `PUT` | `/api/v1/auth/profile` | `auth` | `UpdateProfile` | `backend/api/routes.go` |
| `GET` | `/api/v1/auth/user/quota` | `auth` | `GetOwnQuota` | `backend/api/routes.go` |
| `GET` | `/api/v1/auth/settings` | `auth` | `GetSettings` | `backend/api/routes.go` |
| `GET` | `/api/v1/auth/fileshare` | `auth` | `GetFilesList` | `backend/api/routes.go` |
| `GET` | `/api/v1/auth/services` | `auth` | `getServices` | `backend/api/routes.go` |
| `GET` | `/api/v1/auth/packages/:id/progress` | `auth` | `PackageProgress` | `backend/api/routes.go` |
| `GET` | `/api/v1/auth/system/update/check` | `auth` | `CheckUpdate` | `backend/api/routes.go` |
| `GET` | `/api/v1/auth/system/hardware` | `auth` | `GetHardwareInfo` | `backend/api/routes.go` |
| `GET` | `/api/v1/auth/notifications` | `auth` | `GetNotifications` | `backend/api/routes.go` |
| `PUT` | `/api/v1/auth/notifications/:id/read` | `auth` | `MarkNotificationRead` | `backend/api/routes.go` |
| `POST` | `/api/v1/auth/notifications/dismiss-all` | `auth` | `DismissAllNotifications` | `backend/api/routes.go` |
| `GET` | `/api/v1/auth/ws/logs` | `auth` | `HandleLogWebSocket` | `backend/api/routes.go` |

#### Admin
| method | route | tier | handler | source |
| --- | --- | --- | --- | --- |
| `POST` | `/api/v1/admin/backup/run` | `admin` | `RunBackup` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/backup/list` | `admin` | `GetBackupsList` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/backup/download/:filename` | `admin` | `DownloadBackup` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/backup/upload/:filename` | `admin` | `UploadBackupChunk` | `backend/api/routes.go` |
| `PUT` | `/api/v1/admin/settings` | `admin` | `updateSettings` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/settings/test-ai` | `admin` | `TestAiConnection` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/users` | `admin` | `GetUsers` | `backend/api/routes.go` |
| `PUT` | `/api/v1/admin/users/:id/role` | `admin` | `UpdateUserRole` | `backend/api/routes.go` |
| `DELETE` | `/api/v1/admin/users/:id` | `admin` | `DeleteUser` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/quotas` | `admin` | `ListUserQuotas` | `backend/api/routes.go` |
| `PUT` | `/api/v1/admin/quotas/:id` | `admin` | `UpdateUserQuota` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/quotas/:id/refresh` | `admin` | `RefreshUserQuota` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/billing/webhooks` | `admin` | `ListBillingWebhookEvents` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/services/:name/control` | `admin` | `controlService` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/packages/:id/install` | `admin` | `InstallPackage` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/packages/:id/uninstall` | `admin` | `UninstallPackage` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/system/update/run` | `admin` | `RunUpdate` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/fileshare/upload` | `admin` | `QuotaUploadGuard(), UploadFile` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/cluster/nodes` | `admin` | `GetClusterNodes` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/cluster/enroll` | `admin` | `EnrollWorker` | `backend/api/routes.go` |
| `DELETE` | `/api/v1/admin/cluster/nodes/:id` | `admin` | `RemoveWorker` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/cluster/nodes/:id/metrics` | `admin` | `GetWorkerMetrics` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/oidc/clients` | `admin` | `GetOIDCClients` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/oidc/clients` | `admin` | `CreateOIDCClient` | `backend/api/routes.go` |
| `DELETE` | `/api/v1/admin/oidc/clients/:id` | `admin` | `DeleteOIDCClient` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/ai/metadata/scan` | `admin` | `HandleMetadataScan` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/ai/metadata/status` | `admin` | `HandleMetadataStatus` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/ai/metadata/results` | `admin` | `HandleMetadataResults` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/ai/bandwidth/analyze` | `admin` | `HandleBandwidthAnalyze` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/ai/bandwidth/apply` | `admin` | `HandleBandwidthApply` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/ai/predictions` | `admin` | `HandleGetPredictions` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/ai/predictions/analyze` | `admin` | `HandleAnalyzePredictions` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/ai/predictions/history` | `admin` | `HandleGetMetricsHistory` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/ai/backup/optimal-window` | `admin` | `HandleGetOptimalWindow` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/ai/backup/schedule` | `admin` | `HandleSetBackupSchedule` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/logs` | `admin` | `GetLogs` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/logs/sources` | `admin` | `GetLogSources` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/logs/bookmarks` | `admin` | `BookmarkLog` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/notifications/rules` | `admin` | `GetNotificationRules` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/notifications/rules` | `admin` | `CreateNotificationRule` | `backend/api/routes.go` |
| `PUT` | `/api/v1/admin/notifications/rules/:id` | `admin` | `UpdateNotificationRule` | `backend/api/routes.go` |
| `DELETE` | `/api/v1/admin/notifications/rules/:id` | `admin` | `DeleteNotificationRule` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/notifications/channels` | `admin` | `GetNotificationChannels` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/notifications/channels` | `admin` | `CreateNotificationChannel` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/notifications/channels/:id/test` | `admin` | `TestNotificationChannel` | `backend/api/routes.go` |
| `DELETE` | `/api/v1/admin/notifications/channels/:id` | `admin` | `DeleteNotificationChannel` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/network/status` | `admin` | `GetNetworkStatus` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/network/wireguard/peers` | `admin` | `GetWireGuardPeers` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/network/wireguard/peers` | `admin` | `AddWireGuardPeer` | `backend/api/routes.go` |
| `DELETE` | `/api/v1/admin/network/wireguard/peers/:key` | `admin` | `RemoveWireGuardPeer` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/network/wireguard/keygen` | `admin` | `GenerateWireGuardKeys` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/network/tailscale/status` | `admin` | `GetTailscaleStatus` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/network/tailscale/peers` | `admin` | `GetTailscalePeers` | `backend/api/routes.go` |
| `POST` | `/api/v1/admin/network/tailscale/routes` | `admin` | `AdvertiseTailscaleRoutes` | `backend/api/routes.go` |
| `GET` | `/api/v1/admin/system/metrics` | `admin` | `getSystemMetrics` | `backend/api/routes.go` |

#### Root
| method | route | tier | handler | source |
| --- | --- | --- | --- | --- |
| `GET` | `/.well-known/openid-configuration` | `root/public` | `OIDCDiscovery` | `backend/api/routes.go` |

### Frontend Fetcher Catalog
Global note:
- `frontend/src/lib/fetcher.ts` adds `X-API-Version: v1` and `Accept: application/vnd.aetherflow.v1+json, application/json`.
- SWR consumers inherit those headers via `frontend/src/components/layout/SWRProvider.tsx`.
- Direct `fetch()` calls bypass that contract unless they set headers manually.
- No frontend runtime code stores or sends a Bearer token. Protected routes therefore depend on cookies, while backend `AuthMiddleware()` and `GetSession()` require `Authorization: Bearer ...`.

| caller | method | url | headers | auth transport | matched backend route | notes |
| --- | --- | --- | --- | --- | --- | --- |
| `LoginPage useEffect` | `GET` | `/api/v1/public/auth/setup/check` | `none` | `public` | `GET /api/v1/public/auth/setup/check` | Exact public route |
| `LoginPage handleLogin` | `POST` | `/api/v1/public/auth/setup` or `/api/v1/public/auth/login` | `Content-Type: application/json` | `cookie` | `POST /api/v1/public/auth/setup`, `POST /api/v1/public/auth/login` | Exact public routes; cookie session is set here |
| `Dashboard page` | `GET` | `/api/v1/auth/settings` | `fetcher default` | `no bearer` | `GET /api/v1/auth/settings` | Path exact; auth transport mismatched |
| `OnboardingWizard` | `PUT` | `/api/v1/auth/settings` | `Content-Type: application/json` | `no bearer` | `none` | Wrong tier; backend mutation route is `PUT /api/v1/admin/settings` |
| `AiChatTab` | `POST` | `/api/v1/admin/ai/chat` | `Content-Type: application/json` | `no bearer` | `none` | Wrong path; backend chat route is `/api/v1/auth/ai/chat` |
| `AiChatTab` | `POST` | `/api/v1/admin/ai/support` | `Content-Type: application/json` | `no bearer` | `none` | Wrong path; backend route is `/api/v1/auth/ai/support`, and handler still enforces admin role internally |
| `BackupTab` | `GET` | `/api/v1/admin/backup/list` | `none` | `cookie only` | `GET /api/v1/admin/backup/list` | Path exact; auth transport mismatched |
| `BackupTab` | `GET` | `/api/v1/admin/ai/backup/optimal-window` | `none` | `cookie only` | `GET /api/v1/admin/ai/backup/optimal-window` | Path exact; auth transport mismatched |
| `BackupTab` | `POST` | `/api/v1/admin/backup/run` | `none` | `cookie only` | `POST /api/v1/admin/backup/run` | Path exact; auth transport mismatched |
| `BackupTab` | `POST` | `/api/v1/admin/ai/backup/schedule` | `Content-Type: application/json` | `cookie only` | `POST /api/v1/admin/ai/backup/schedule` | Path exact; auth transport mismatched |
| `BackupTab download link` | `GET` | `/api/backup/download/:filename` | `browser link` | `cookie only` | `none` | `FE-FETCH-007`; stale path omits `/admin` and `/v1` |
| `FileshareTab` | `GET` | `/api/v1/auth/fileshare` | `fetcher default` | `no bearer` | `GET /api/v1/auth/fileshare` | Path exact; auth transport mismatched |
| `FileshareTab` | `POST` | `/api/v1/auth/fileshare/upload` | `multipart/form-data (browser)` | `cookie only` | `none` | `FE-FETCH-004`; backend route is `POST /api/v1/admin/fileshare/upload` |
| `MarketplaceTab via useMarketplace` | `GET` | `/api/v1/public/marketplace` | `fetcher default` | `public` | `GET /api/v1/public/marketplace` | Exact public route |
| `MarketplaceTab` | `POST` | `/api/packages/:id/install` | `none` | `cookie only` | `none` | `FE-FETCH-006`; rewrite sends this to backend `/api/packages/...`, but registered route is `/api/admin/packages/...` or `/api/v1/admin/packages/...` |
| `MarketplaceTab` | `POST` | `/api/packages/:id/uninstall` | `none` | `cookie only` | `none` | Same mismatch as install |
| `MetadataTab` | `POST` | `/api/v1/admin/ai/metadata/scan` | `Content-Type: application/json` | `cookie only` | `POST /api/v1/admin/ai/metadata/scan` | Path exact; auth transport mismatched |
| `MetadataTab` | `GET` | `/api/v1/admin/ai/metadata/status` | `none` | `cookie only` | `GET /api/v1/admin/ai/metadata/status` | Path exact; auth transport mismatched |
| `MetadataTab` | `GET` | `/api/v1/admin/ai/metadata/results` | `none` | `cookie only` | `GET /api/v1/admin/ai/metadata/results` | Path exact; auth transport mismatched |
| `ProfileTab` | `GET` | `/api/user/quota/:id` | `fetcher default` | `no bearer` | `none` | `FE-FETCH-005`; `GetUserQuota` exists but is not registered in `routes.go` |
| `ProfileTab` | `PUT` | `/api/v1/auth/profile` | `Content-Type: application/json` | `cookie only` | `PUT /api/v1/auth/profile` | Path exact; auth transport mismatched |
| `ServicesTab` | `GET` | `/api/v1/auth/services` | `fetcher default` | `no bearer` | `GET /api/v1/auth/services` | Path exact; auth transport mismatched |
| `ServicesTab` | `POST` | `/api/v1/auth/services/:name/control` | `Content-Type: application/json` | `cookie only` | `none` | `FE-FETCH-003`; backend control route is admin-tier |
| `SettingsTab` | `POST` | `/api/v1/auth/settings/test-ai` | `Content-Type: application/json` | `cookie only` | `none` | `FE-FETCH-002`; backend route is `POST /api/v1/admin/settings/test-ai` |
| `SettingsTab` | `GET` | `/api/v1/auth/system/update/check` | `fetcher default` | `no bearer` | `GET /api/v1/auth/system/update/check` | Path exact; auth transport mismatched |
| `SettingsTab` | `GET` | `/api/v1/auth/settings` | `fetcher default` | `no bearer` | `GET /api/v1/auth/settings` | Path exact; auth transport mismatched |
| `SettingsTab` | `PUT` | `/api/v1/auth/settings` | `Content-Type: application/json` | `cookie only` | `none` | `FE-FETCH-002`; backend route is `PUT /api/v1/admin/settings` |
| `SettingsTab` | `POST` | `/api/v1/admin/system/update/run` | `none` | `cookie only` | `POST /api/v1/admin/system/update/run` | Path exact; auth transport mismatched |
| `UsersTab` | `GET` | `/api/v1/admin/users` | `fetcher default` | `no bearer` | `GET /api/v1/admin/users` | Path exact; auth transport mismatched |
| `UsersTab` | `PUT` | `/api/v1/admin/users/:id/role` | `Content-Type: application/json` | `cookie only` | `PUT /api/v1/admin/users/:id/role` | Path exact; auth transport mismatched |
| `UsersTab` | `DELETE` | `/api/v1/admin/users/:id` | `none` | `cookie only` | `DELETE /api/v1/admin/users/:id` | Path exact; auth transport mismatched |
| `AuthContext.checkSession` | `GET` | `/api/v1/auth/session` | `none` | `cookie only via credentials: include` | `GET /api/v1/auth/session` | `ARCH-001`; backend `GetSession` requires Bearer token |
| `AuthContext.login` | `GET` | `/api/v1/public/auth/google/login` | `browser navigation` | `public` | `GET /api/v1/public/auth/google/login` | Exact public route |
| `AuthContext.logout` | `POST` | `/api/v1/auth/logout` | `none` | `cookie only via credentials: include` | `POST /api/v1/auth/logout` | `ARCH-001`; route sits behind bearer-only `AuthMiddleware()` |
| `WebSocketContext buildWsUrl` | `WS` | `/api/v1/auth/ws` when `NEXT_PUBLIC_API_URL` is set | `browser WS upgrade` | `no bearer, no ticket` | `GET /api/v1/auth/ws` | `ARCH-002`; path exact but frontend never requests `/api/v1/auth/ws/ticket` and cannot set Authorization header |
| `WebSocketContext buildWsUrl` | `WS` | `/api/ws` on same-origin fallback | `browser WS upgrade` | `no bearer, no ticket` | `none` | `ARCH-002`; local path does not match `/api/auth/ws` or `/api/v1/auth/ws` |
| `WebSocketContext polling fallback` | `GET` | `/api/v1/admin/system/metrics` | `none` | `cookie only` | `GET /api/v1/admin/system/metrics` | Path exact; auth transport mismatched |
| `useMetrics` | `GET` | `/api/v1/auth/system/hardware` | `fetcher default` | `no bearer` | `GET /api/v1/auth/system/hardware` | Path exact; auth transport mismatched |

### Contract Diff Summary
| bucket | entries | notes |
| --- | --- | --- |
| `Exact public route` | login bootstrap, Google login redirect, marketplace list | Public endpoints are path-aligned and do not depend on the auth transport bug |
| `Exact protected path, auth transport broken` | settings GET, profile PUT, users admin, backup admin, metadata admin, hardware/services/settings/auth session/logout | Frontend never sends Bearer tokens, but backend protected routes require them |
| `Path mismatch or stale route` | AI chat/support, settings save/test, services control, fileshare upload, profile quota, marketplace install/uninstall, backup download, same-origin WS path | These fail even before considering auth transport |
| `Intentional backend-only` | public billing webhooks, OIDC discovery/token/jwks/revoke, admin billing list | These are integration surfaces for external systems, not necessarily missing UI |

### Backend Orphan Isolation
| finding_id | backend surface | representative routes | frontend consumer found | classification |
| --- | --- | --- | --- | --- |
| `BE-ROUTE-001` | cluster management | `/api/v1/admin/cluster/nodes`, `/cluster/enroll`, `/cluster/nodes/:id/metrics` | none | backend orphan / admin-only surface |
| `BE-ROUTE-002` | network management | `/api/v1/admin/network/status`, `/network/wireguard/*`, `/network/tailscale/*` | none | backend orphan / admin-only surface |
| `BE-ROUTE-003` | log operations | `/api/v1/admin/logs`, `/logs/sources`, `/logs/bookmarks` | none | backend orphan / admin-only surface; bookmarks are write-only |
| `BE-ROUTE-004` | notification rule/channel administration | `/api/v1/admin/notifications/rules*`, `/notifications/channels*` | none | backend orphan / admin-only surface |
| `BE-ROUTE-005` | OIDC client administration | `/api/v1/admin/oidc/clients*` | none | backend orphan / admin-only surface |
| `BE-ROUTE-006` | AI auxiliary endpoints | `/api/v1/admin/ai/bandwidth/apply`, `/api/v1/admin/ai/predictions`, `/api/v1/admin/ai/predictions/history` | none | backend orphan |

### Frontend Orphan Isolation
| finding_id | frontend surface | observed request or UI | backend support | classification |
| --- | --- | --- | --- | --- |
| `FE-UI-001` | `SecurityTab` | static buttons only | none | rendered placeholder |
| `FE-UI-004` | header profile button | mock button, no navigation | none | rendered placeholder |
| `FE-FETCH-005` | `ProfileTab` quota load | `/api/user/quota/:id` | no registered route | broken fetch path |
| `FE-UI-006` | `FileshareTab` download action | download button with no action | no download route in `fileshare.go` | broken UI control |
| `ARCH-003` | OIDC consent page | backend redirects to `/oauth/consent` | no frontend route found | missing screen |

## Phase Group 3: Database Schema and State Audit

### Schema Coverage Map
| table | created_in | readers | writers | orphan_status | notes |
| --- | --- | --- | --- | --- | --- |
| `settings` | `backend/db/db.go` | `backend/api/settings.go`, `backend/api/ai_helpers.go`, `backend/api/ai.go`, `backend/services/smart_backup.go` | `backend/api/settings.go`, `backend/api/crypto.go`, `backend/api/smart_backup.go` | `active` | Migration 4 adds `backup_schedule_mode` and `backup_optimal_window`; both are used |
| `users` | `backend/db/db.go` | `backend/api/auth.go`, `backend/api/users.go`, `backend/api/oidc.go`, `backend/services/quota_manager.go` | `backend/api/auth.go`, `backend/api/users.go` | `active` | Core auth and RBAC table |
| `login_history` | `backend/db/db.go` | none found outside boot | `backend/api/auth.go` | `write-only` | Operationally used for audit logging, but not surfaced anywhere |
| `cluster_nodes` | `backend/db/db.go` | `backend/cluster/cluster.go`, `backend/api/cluster_handlers.go` | `backend/cluster/cluster.go` | `active backend-only` | No frontend consumer |
| `oidc_clients` | `backend/db/db.go` | `backend/api/oidc.go`, `backend/api/oidc_clients.go` | `backend/api/oidc_clients.go` | `active backend-only` | No frontend consumer |
| `oidc_auth_codes` | `backend/db/db.go` | `backend/api/oidc.go`, `backend/api/oidc_clients.go` | `backend/api/oidc.go`, `backend/api/oidc_clients.go` | `active backend-only` | Auth code flow state |
| `oidc_refresh_tokens` | `backend/db/db.go` | `backend/api/oidc.go` | `backend/api/oidc.go`, `backend/api/oidc_clients.go` | `active backend-only` | Refresh token state |
| `log_bookmarks` | `backend/db/db.go` | none found | `backend/api/log_handlers.go` | `partial / write-only` | `DB-TABLE-002`; bookmark creation exists, retrieval UI/API does not |
| `notifications` | `backend/db/db.go` | `backend/api/notification_handlers.go` | `backend/services/notifications.go`, `backend/api/notification_handlers.go` | `active` | User-facing notifications |
| `notification_rules` | `backend/db/db.go` | `backend/api/notification_handlers.go`, `backend/services/notifications.go` | `backend/api/notification_handlers.go` | `active backend-only` | No frontend consumer |
| `notification_channels` | `backend/db/db.go` | `backend/api/notification_handlers.go`, `backend/services/notifications.go` | `backend/api/notification_handlers.go` | `active backend-only` | No frontend consumer |
| `user_quotas` | `backend/db/db.go` | `backend/services/quota_manager.go`, `backend/api/quota_handlers.go` | `backend/services/quota_manager.go` | `active` | Fileshare quota guard depends on it |
| `billing_webhook_events` | `backend/db/db.go` | `backend/services/quota_manager.go`, `backend/api/quota_handlers.go` | `backend/services/quota_manager.go` | `active backend/external` | External billing integration surface |
| `vpn_configs` | `backend/db/db.go` | none found | none found | `orphaned` | `DB-TABLE-001`; table initializes but has zero operational queries |
| `app_updates` | `backend/db/db.go` | `backend/services/app_updates.go` | `backend/services/app_updates.go` | `active backend-only` | Merged into marketplace response, not directly queried from frontend |
| `media_metadata` | `backend/db/db.go` | `backend/services/metadata_enricher.go`, `backend/api/metadata.go` | `backend/services/metadata_enricher.go` | `active` | Admin AI feature |
| `metrics_history` | `backend/db/db.go` | `backend/services/metrics_recorder.go`, `backend/services/resource_predictor.go`, `backend/services/smart_backup.go`, `backend/api/predictions.go` | `backend/services/metrics_recorder.go` | `active` | Supports predictions and smart backup |
| `schema_versions` | `backend/db/db.go` | `backend/db/db.go` only | `backend/db/db.go` only | `internal` | Migration bookkeeping table, not a product feature |

### Zustand Store Audit
| store | persistence | active state | observed consumers | status |
| --- | --- | --- | --- | --- |
| `useSystemStore` | `persist` middleware for `theme`, `language`, `ambientColor1`, `ambientColor2` | `activeTab`, `isSidebarHovered`, `isMobileMenuOpen`, `activeTasks` | `Dashboard`, `Header`, `Sidebar`, `ThemeProvider`, `LanguageProvider`, `AiChatTab` | Mixed |
| `useConnectionStore` | no persistence | `connectionState`, `reconnectAttempt`, `lastMessageAt` | `Header`, `WebSocketContext` | Active |

### State Utilization Verification
| finding_id | state | evidence | status |
| --- | --- | --- | --- |
| `FE-UI-003` | `useSystemStore.activeTasks` | runtime search only found references in `frontend/src/store/useSystemStore.ts` and `frontend/src/store/useSystemStore.test.ts` | orphaned |

## Phase Group 4: Known Architectural Stub Review

### Architecture Verification
| feature | expected behavior | observed behavior | evidence | status |
| --- | --- | --- | --- | --- |
| `ARCH-001` auth transport | Frontend should authenticate protected routes in the same transport the backend expects | `LocalLogin` and OAuth callback set only `aetherflow_session` cookies, but `GetSession()` and `AuthMiddleware()` require `Authorization: Bearer ...`; frontend never stores or sends a Bearer token | `backend/api/auth.go:98,152,352,405,452,481`, `frontend/src/contexts/AuthContext.tsx`, `frontend/src/lib/fetcher.ts` | `disconnected` |
| `ARCH-002` WebSocket live metrics | Frontend should request a ticket or otherwise satisfy backend auth, then connect to the correct WS path | Frontend opens bare browser WebSocket connections, never calls `/api/v1/auth/ws/ticket`, and same-origin fallback uses `/api/ws`; backend WS route is under auth middleware and the handler's cookie fallback is effectively pre-empted | `backend/api/routes.go:66-67`, `backend/api/websockets.go`, `frontend/src/contexts/WebSocketContext.tsx` | `disconnected` |
| `ARCH-003` OIDC consent flow | Authorization endpoint should redirect to a real frontend consent screen that can submit consent successfully | Backend redirects to `/oauth/consent`, no frontend route exists, and consent POST route sits behind bearer-only auth middleware | `backend/api/oidc.go:205-206`, `backend/api/routes.go:68`, empty frontend search for `/oauth/consent` and `oidc/consent` | `missing` |
| `ARCH-004` smart backup execution | Smart mode should compute a window, schedule the next run, and execute `RunBackup()` in that window | Mode and cached window are stored, but `nextBackupAt` is only read, never set, and no code calls `RunBackup()` from the scheduler | `backend/api/smart_backup.go`, `backend/services/smart_backup.go`, `backend/api/backup.go` | `partial` |
| `ARCH-005` frontend header contract | All frontend API calls should consistently send `X-API-Version: v1` and vendor `Accept` headers | Only SWR users inherit the global fetcher contract; most direct `fetch()` calls send only `Content-Type` or no custom headers. Backend `/api/v1` routes do not enforce the request headers anyway because `ForceAPIVersion()` sets version server-side | `frontend/src/lib/fetcher.ts`, `frontend/src/components/layout/SWRProvider.tsx`, `backend/api/versioning.go` | `partial` |
| `ARCH-006` bandwidth engine | UI should expose both analyze and apply if daemon integration is meant to be live, and code comments should match runtime behavior | UI only calls `/api/v1/admin/ai/bandwidth/analyze`; no frontend consumer calls `/api/v1/admin/ai/bandwidth/apply`. Backend apply handler still says `stub` but now performs a live Transmission RPC request | `frontend/src/components/cards/BandwidthCard.tsx`, `backend/api/bandwidth.go` | `partial` |
| `ARCH-007` marketplace install/uninstall | Frontend should call the registered admin package routes and stream progress from the installer service | Backend install/uninstall handlers queue real bash scripts through `RunPackageAction()`, but frontend still posts to stale `/api/packages/:id/install|uninstall` paths | `frontend/src/components/tabs/MarketplaceTab.tsx`, `backend/api/marketplace.go`, `backend/services/installer.go` | `disconnected` |
| `ARCH-008` security console | Security tab actions should map to live backend mutations | `SecurityTab` contains no fetches or SWR calls; buttons are render-only | `frontend/src/components/tabs/SecurityTab.tsx` | `missing` |

## Phase Group 5: Completeness Pass

### Required Negative Findings Captured
- No backend `TODO`/`FIXME` markers in runtime Go code
- No backend explicit `501`/`StatusNotImplemented`
- No frontend `TODO` markers in runtime code
- No frontend `disabled={true}` markers in runtime code
- No frontend `mockData` declarations in runtime code

### Required Scenario Checks Captured
- Cookie auth vs bearer auth: `ARCH-001`
- Header contract enforcement and bypass: `ARCH-005`
- Rewrite behavior from `next.config.ts`: used in `FE-FETCH-006` and `FE-FETCH-007`
- OIDC consent frontend absence: `ARCH-003`
- Smart backup execution gap: `ARCH-004`
- Security tab render-without-backend gap: `FE-UI-001`, `ARCH-008`

### Final Coverage Notes
- Every audit phase produced either evidence-backed findings or an explicit zero-result note.
- The dominant root cause across the frontend/backend bridge is not only stale paths, but a systemic auth transport split:
  - frontend assumes cookie-authenticated same-origin requests
  - backend protected routes assume Bearer-token requests
- The second dominant gap is feature incompleteness after remediation:
  - route exists but no UI consumer
  - UI exists but no route
  - schema exists but no operational query path
