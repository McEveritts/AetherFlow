# AetherFlow Backend Connectivity Outage Resolution

This document outlines the diagnosis and resolution of two cascading networking/authentication defects that prevented the AetherFlow backend from being accessible on the McStream production server.

## Incident Overview

Following a successful atomic deployment of AetherFlow, the Go API Gateway (backend) appeared to be completely offline when accessed via the McStream server's external IP address (`192.168.1.153`). The `aetherflow-api.service` was actively running and processing requests (verified via `systemctl status` and `journalctl`), but the client-side dashboard could not establish a connection — displaying "Connection to identity provider lost. Is the backend service active?"

## Root Cause Analysis & Identification

Two independent defects were identified:

### 1. HTTP Server Bind Address (Blocker #1)
The `main.go` source code for the backend had a hardcoded `http.Server` address configuration that bound the application exclusively to localhost:

```go
srv := &http.Server{
    Addr: "127.0.0.1:" + port,
}
```

This physically restricted the backend to loopback traffic only. External connections to port 8080 were refused at the OS level.

### 2. HostValidationMiddleware Rejection (Blocker #2)
After fixing the bind address, the backend was reachable on the network but still rejected browser requests with `400 Bad Request`. The `HostValidationMiddleware` in `api/auth.go` contained a hardcoded whitelist of allowed `Host` header values:

```go
allowedHosts := map[string]bool{
    "api.aetherflow.com": true,
    "localhost:8080":     true,
    "127.0.0.1:8080":    true,
}
```

AetherFlow's frontend uses a Next.js rewrite proxy — the browser sends requests to port `3000`, and the Next.js server forwards them to the backend on port `8080`. Critically, Next.js preserves the **original browser Host header** (e.g. `192.168.1.153:3000`) when proxying. Since the LAN IP was not in the hardcoded whitelist, the middleware silently rejected every proxied request.

## Remediations Executed

### 1. Bind Address Fix (`backend/main.go`)
Patched the HTTP server to bind to `0.0.0.0` (all interfaces):

```go
srv := &http.Server{
    Addr: "0.0.0.0:" + port,
}
```

### 2. HostValidationMiddleware Auto-Discovery (`backend/api/auth.go`)
Replaced the hardcoded host whitelist with dynamic auto-discovery using `net.Interfaces()`. When `ALLOWED_HOSTS` is not explicitly set in the environment, the middleware now:
- Includes default entries: `localhost`, `127.0.0.1` (with ports `3000` and `8080`)
- Auto-discovers all non-loopback IPs from the server's network interfaces
- Registers each discovered IP bare, and with `:8080` and `:3000` suffixes
- Logs the total number of allowed hosts at startup for observability

When `ALLOWED_HOSTS` **is** explicitly set, it overrides defaults entirely (production hardening).

This approach is **network-agnostic** — it works on any server regardless of IP address or network topology, since it discovers the machine's own IPs at runtime.

### 3. Deployment
Both fixes were committed and pushed to the `master` branch. A `nightly` atomic deployment was triggered on McStream via `deployment_engine.sh nightly`, which compiled the patched backend and restarted the systemd services.

## Validations Performed

Post-deployment end-to-end verification:

| Test | Method | Result |
|---|---|---|
| Backend via Next.js proxy | `curl http://192.168.1.153:3000/api/v1/public/auth/setup/check` | `200 OK` — `{"setupRequired":true}` |
| Setup check (localhost) | `curl http://127.0.0.1:8080/api/v1/public/auth/setup/check` | `200 OK` — `{"setupRequired":true}` |
| Host header rejection proof | `curl -H 'Host: 192.168.1.153:3000' http://127.0.0.1:8080/...` | Previously `400`, now `200` |

## Key Takeaway

The `HostValidationMiddleware` is a critical security control (CWE-601: Open Redirect prevention), but its hardcoded whitelist was incompatible with AetherFlow's proxy architecture. The auto-discovery pattern mirrors the existing `discoverOrigins()` function used for CORS in `main.go`, maintaining consistency across the codebase.
