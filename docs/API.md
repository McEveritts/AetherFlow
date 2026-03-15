# AetherFlow REST & WebSocket API Reference

> **Backend**: Go 1.24 / Gin framework  
> **Auth**: JWT (HS256) via `aetherflow_session` HttpOnly cookie  
> **Base Path**: `/api`

---

## Authentication

### `POST /api/auth/setup`
Create the initial admin account (only works when 0 users exist).
- **Auth**: None
- **Rate Limited**: 5 req/min
- **Body**: `{ "username": "...", "password": "..." }` (password ≥ 8 chars)
- **Response**: `{ "message": "Admin account created", "username": "..." }`

### `POST /api/auth/login`
Authenticate with username + password.
- **Auth**: None
- **Rate Limited**: 5 req/min
- **Body**: `{ "username": "...", "password": "..." }`
- **Response**: `{ "message": "Login successful", "user": { id, username, email, avatar_url, role, is_oauth } }`
- **Cookie**: Sets `aetherflow_session` (30-day JWT, HttpOnly, SameSite=Lax)

### `GET /api/auth/session`
Get current authenticated user info.
- **Auth**: Required (JWT cookie)
- **Response**: `{ id, username, email, avatar_url, role, is_oauth }`

### `POST /api/auth/logout`
Clear the session cookie.
- **Auth**: None
- **Response**: `{ "message": "Logged out" }`

### `GET /api/auth/setup/check`
Check if initial setup is required.
- **Auth**: None
- **Response**: `{ "setupRequired": true|false }`

### `GET /api/auth/google/login`
Redirect to Google OAuth consent screen.
- **Auth**: None

### `GET /api/auth/google/callback`
Google OAuth callback — exchanges code, upserts user, sets JWT cookie.
- **Auth**: None (validates OAuth state)

### `PUT /api/auth/profile`
Update the authenticated user's email.
- **Auth**: Required (JWT cookie)
- **Body**: `{ "email": "..." }`
- **Response**: `{ "message": "Profile updated successfully" }`

---

## System Metrics

### `GET /api/system/metrics`
Get current system metrics snapshot (CPU, memory, network, disk I/O).
- **Auth**: None (read-only)
- **Response**: `SystemMetrics` object

### `GET /api/system/hardware`
Get hardware info (CPU model, GPU, NICs, storage).
- **Auth**: None (read-only)
- **Response**: `HardwareReport` object

### `GET /api/ws` (WebSocket)
Real-time metrics stream via WebSocket.
- **Auth**: Required (JWT cookie validated on upgrade)
- **Origin**: Same-origin only (strict URL comparison)
- **Messages**: Server pushes `{ "type": "METRICS_UPDATE", "data": { "system": SystemMetrics, "services": {...} } }` every 3s
- **Ping/Pong**: Server sends WebSocket PING every 54s, expects PONG within 70s

---

## Services

### `GET /api/services`
List active services with status.
- **Auth**: None (read-only)
- **Response**: `{ "service_name": { status, managed_by, process, ... }, ... }`

### `POST /api/services/:name/control` ⛔ Admin
Control a service (start/stop/restart).
- **Auth**: Admin only
- **Body**: `{ "action": "start|stop|restart", "managed_by": "systemd|pm2", "process": "..." }`
- **Response**: `{ "message": "...", "service": "...", "action": "..." }`

---

## Marketplace

### `GET /api/marketplace`
List available packages with installation status.
- **Auth**: None (read-only)
- **Response**: `[ { name, label, description, category, status, ... }, ... ]`

### `POST /api/packages/:id/install` ⛔ Admin
Install a marketplace package.
- **Auth**: Admin only

### `POST /api/packages/:id/uninstall` ⛔ Admin
Uninstall a marketplace package.
- **Auth**: Admin only

### `GET /api/packages/:id/progress`
Get package install/uninstall progress.
- **Auth**: None (read-only)

---

## Settings

### `GET /api/settings`
Get current system settings.
- **Auth**: None (read-only for UI configuration)
- **Response**: `{ aiModel, systemPrompt, language, timezone, updateChannel, defaultDashboard, setupCompleted, geminiApiKey }`

### `PUT /api/settings` ⛔ Admin
Update system settings.
- **Auth**: Admin only
- **Body**: Full settings object

### `POST /api/settings/test-ai` ⛔ Admin
Test the AI/Gemini API connection.
- **Auth**: Admin only

---

## File Share

### `GET /api/fileshare`
List uploaded files.
- **Auth**: None (read-only)
- **Response**: `[ { name, size, modTime, extension }, ... ]`

### `POST /api/fileshare/upload` ⛔ Admin
Upload a file (max 50 MB).
- **Auth**: Admin only
- **Validation**: Blocked extensions (exe, sh, bat, php, etc.), content-type sniffing rejects executables, double-extension prevention
- **Response**: `{ "message": "...", "filename": "..." }`

---

## Backups

### `POST /api/backup/run` ⛔ Admin
Create a new database backup via `VACUUM INTO`.
- **Auth**: Admin only
- **Response**: `{ message, filename, size, checksum, timestamp }`

### `GET /api/backup/list` ⛔ Admin
List available backups.
- **Auth**: Admin only
- **Response**: `[ { filename, size, timestamp, checksum }, ... ]`

### `GET /api/backup/download/:filename` ⛔ Admin
Download a backup (supports chunked and range requests).
- **Auth**: Admin only

### `POST /api/backup/upload/:filename` ⛔ Admin
Upload a backup in chunks with checksum verification.
- **Auth**: Admin only

---

## User Management

### `GET /api/users` ⛔ Admin
List all users.
- **Auth**: Admin only

### `PUT /api/users/:id/role` ⛔ Admin
Update a user's role.
- **Auth**: Admin only

### `DELETE /api/users/:id` ⛔ Admin
Delete a user.
- **Auth**: Admin only

### `GET /api/user/quota/:id`
Get a user's storage quota.
- **Auth**: Required

---

## AI Chat

### `POST /api/ai/chat`
Send a message to the FlowAI assistant.
- **Auth**: None
- **Body**: `{ "message": "...", "history": [...], "model": "gemini-2.5-pro" }`
- **Response**: `{ "reply": "..." }`

---

## System Update

### `GET /api/system/update/check`
Check for available updates.
- **Auth**: None (read-only)

### `POST /api/system/update/run` ⛔ Admin
Execute a system update.
- **Auth**: Admin only
