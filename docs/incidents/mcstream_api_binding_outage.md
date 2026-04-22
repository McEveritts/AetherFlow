# AetherFlow Backend Binding Outage Resolution

This document outlines the diagnosis and resolution of a networking visibility issue that prevented the AetherFlow backend from being accessible on the McStream production server.

## Incident Overview

Following a successful atomic deployment of AetherFlow, the Go API Gateway (backend) appeared to be completely offline when accessed via the McStream server's external IP address (`192.168.1.153:8080`). The `aetherflow-api.service` was actively running and processing requests (verified via `systemctl status` and `journalctl`), but the client-side dashboard could not establish a connection to it.

## Root Cause Analysis & Identification

By securely connecting to the McStream node and testing the port locally (`curl 127.0.0.1:8080`), it was determined that the API was functioning properly. However, external requests to `192.168.1.153:8080` were returning connection refused or timeouts.

**The Root Cause:**
The `main.go` source code for the backend had a hardcoded `http.Server` address configuration that bound the application exclusively to localhost:

```go
// Old configuration
srv := &http.Server{
	Addr:    "127.0.0.1:" + port,
	Handler: r,
}
```

This caused the backend to be physically restricted to loopback traffic. Because of this, the server's networking layer and proxy components were unable to route external traffic to the API, creating the illusion of an offline backend.

## Remediations Executed

### 1. Source Code Patch
The `backend/main.go` file was patched to bind the HTTP server to `0.0.0.0`, ensuring that the API Gateway listens on all network interfaces instead of just the loopback interface.

```go
// New configuration
srv := &http.Server{
	Addr:    "0.0.0.0:" + port,
	Handler: r,
}
```
The startup logging statement was also updated to reflect the `0.0.0.0` address.

### 2. Deployment
The fix was committed to the `master` branch and a `nightly` atomic deployment was triggered on the McStream server using the `/opt/AetherFlow/scripts/deployment_engine.sh nightly` pipeline. This fetched the new source, compiled the Go backend, and executed the daemon reload.

## Validations Performed

Post-deployment, the API Gateway was successfully verified by issuing an external `curl` network request:

- **External Network Check**: `curl -v http://192.168.1.153:8080/api/v1/public/auth/setup/check`
- **Result**: Successfully connected and received HTTP headers from the API Gateway (including AetherFlow's custom `Content-Security-Policy` and `X-Api-Version` headers), confirming that the backend is now exposed and correctly accepting external connections.
