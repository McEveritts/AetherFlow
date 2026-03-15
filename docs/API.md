# AetherFlow REST & WebSocket API Reference

Backend:
- Go 1.25 + Gin
- Auth: `aetherflow_session` HttpOnly JWT cookie
- Canonical base path: `/api/v1`
- Legacy base path: `/api`
- Version header: `X-API-Version: v1`
- Vendor media type: `Accept: application/vnd.aetherflow.v1+json`
- Machine-readable schema: `/api/v1/openapi.yaml`

## Versioning

- `/api/v1` is the stable reseller-facing surface for v3.1.0.
- `/api` still routes to the same handlers for backwards compatibility.
- Legacy `/api` responses now include:
  - `X-API-Version: v1`
  - `Deprecation: true`
  - `Link: </api/v1/...>; rel="successor-version"`

## Auth

- `POST /api/v1/auth/setup`
  - Create the initial admin account when no users exist.
- `POST /api/v1/auth/login`
  - Local username/password authentication.
- `GET /api/v1/auth/session`
  - Resolve the current authenticated user.
- `POST /api/v1/auth/logout`
  - Clear the current session.
- `GET /api/v1/auth/setup/check`
  - Return `{ "setupRequired": boolean }`.
- `GET /api/v1/auth/google/login`
  - Start Google OAuth.
- `GET /api/v1/auth/google/callback`
  - Finish Google OAuth.
- `PUT /api/v1/auth/profile`
  - Update the current user profile.

## System

- `GET /api/v1/system/metrics`
  - Point-in-time metrics snapshot.
- `GET /api/v1/system/hardware`
  - Hardware inventory.
- `GET /api/v1/system/update/check`
  - Check for a newer AetherFlow release.
- `POST /api/v1/system/update/run`
  - Run the updater. Admin only.
- `GET /api/v1/openapi.yaml`
  - Embedded OpenAPI schema for the current API version.

## WebSocket

- `GET /api/v1/ws`
  - Real-time metrics and service updates.
- `GET /api/v1/ws/logs`
  - Real-time log streaming.
- Message types:
  - `METRICS_UPDATE`
  - `MARKETPLACE_UPDATE`
  - `NOTIFICATION`

## Services

- `GET /api/v1/services`
  - List active services and runtime metadata.
- `POST /api/v1/services/:name/control`
  - Start, stop, or restart a service. Admin only.

## Marketplace

- `GET /api/v1/marketplace`
  - List marketplace packages and live update badges.
- `POST /api/v1/packages/:id/install`
  - Start package installation. Admin only.
- `POST /api/v1/packages/:id/uninstall`
  - Start package removal. Admin only.
- `GET /api/v1/packages/:id/progress`
  - Read current install or uninstall progress.

## Files & Backup

- `GET /api/v1/fileshare`
  - List uploaded files.
- `POST /api/v1/fileshare/upload`
  - Upload a file. Admin only. Quota middleware now rejects uploads that exceed configured filesystem headroom.
- `POST /api/v1/backup/run`
  - Create a backup. Admin only.
- `GET /api/v1/backup/list`
  - List backups. Admin only.
- `GET /api/v1/backup/download/:filename`
  - Download a backup. Admin only.
- `POST /api/v1/backup/upload/:filename`
  - Upload backup chunks. Admin only.

## Users, Quotas & Billing

- `GET /api/v1/users`
  - List users. Admin only.
- `PUT /api/v1/users/:id/role`
  - Update user role. Admin only.
- `DELETE /api/v1/users/:id`
  - Delete a user. Admin only.
- `GET /api/v1/user/quota/:id`
  - Resolve the current quota record for a user.
- `GET /api/v1/quotas`
  - List quota records for all users. Admin only.
- `PUT /api/v1/quotas/:id`
  - Set or update a quota. Admin only.
- `POST /api/v1/quotas/:id/refresh`
  - Refresh quota usage from `showspace`. Admin only.
- `POST /api/v1/billing/webhooks/whmcs`
  - Secure WHMCS webhook listener.
- `POST /api/v1/billing/webhooks/blesta`
  - Secure Blesta webhook listener.
- `GET /api/v1/billing/webhooks`
  - Audit recent webhook deliveries. Admin only.

Billing listener security:
- Preferred:
  - `Authorization: Bearer <secret>`
- Supported HMAC headers:
  - `X-AetherFlow-Signature`
  - `X-WHMCS-Signature`
  - `X-BLESTA-Signature`
- Supported token headers:
  - `X-AetherFlow-Token`
  - `X-WHMCS-Token`
  - `X-BLESTA-Token`

Environment variables:
- `WHMCS_WEBHOOK_SECRET`
- `BLESTA_WEBHOOK_SECRET`
- `BILLING_WEBHOOK_SECRET`
- `BILLING_QUOTA_PLAN_MAP`

## Notifications

- `GET /api/v1/notifications`
- `PUT /api/v1/notifications/:id/read`
- `POST /api/v1/notifications/dismiss-all`
- `GET /api/v1/notifications/rules`
- `POST /api/v1/notifications/rules`
- `PUT /api/v1/notifications/rules/:id`
- `DELETE /api/v1/notifications/rules/:id`
- `GET /api/v1/notifications/channels`
- `POST /api/v1/notifications/channels`
- `POST /api/v1/notifications/channels/:id/test`
- `DELETE /api/v1/notifications/channels/:id`

## OIDC

- `GET /api/v1/oidc/jwks`
- `GET /api/v1/oidc/authorize`
- `POST /api/v1/oidc/token`
- `GET /api/v1/oidc/userinfo`
- `POST /api/v1/oidc/revoke`
- `GET /.well-known/openid-configuration`
  - Discovery now points clients at `/api/v1/oidc/*`.

## AI

- `POST /api/v1/ai/chat`
- `POST /api/v1/ai/support`
- `POST /api/v1/ai/metadata/scan`
- `GET /api/v1/ai/metadata/status`
- `GET /api/v1/ai/metadata/results`
- `POST /api/v1/ai/bandwidth/analyze`
- `POST /api/v1/ai/bandwidth/apply`
- `GET /api/v1/ai/predictions`
- `POST /api/v1/ai/predictions/analyze`
- `GET /api/v1/ai/predictions/history`
- `GET /api/v1/ai/backup/optimal-window`
- `POST /api/v1/ai/backup/schedule`

## Cluster & Network

- Cluster:
  - `GET /api/v1/cluster/nodes`
  - `POST /api/v1/cluster/enroll`
  - `DELETE /api/v1/cluster/nodes/:id`
  - `GET /api/v1/cluster/nodes/:id/metrics`
- Network:
  - `GET /api/v1/network/status`
  - `GET /api/v1/network/wireguard/peers`
  - `POST /api/v1/network/wireguard/peers`
  - `DELETE /api/v1/network/wireguard/peers/:key`
  - `POST /api/v1/network/wireguard/keygen`
  - `GET /api/v1/network/tailscale/status`
  - `GET /api/v1/network/tailscale/peers`
  - `POST /api/v1/network/tailscale/routes`
