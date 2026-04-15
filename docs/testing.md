# Testing AetherFlow

AetherFlow testing encompasses both the **frontend operator experience** and the **backend control plane**.

This guide covers the core tooling, prerequisites, and standard commands used to validate the platform.

> [!NOTE]
> Testing should confirm more than “does it compile.” In AetherFlow, a useful test workflow checks UI behavior, backend correctness, and operational paths that matter in real deployments.

---

## Prerequisites

Before running tests, make sure the local environment has the required toolchain installed:

- **Node.js**: Required for Jest and Playwright.
- **Go**: Required for backend execution (`go test`).
- **Playwright browsers**: Must be downloaded locally via `npx playwright install`.
- **Python**: Required to execute the `test_api.py` manual diagnostic script.

---

## Frontend End-to-End Testing (Playwright)

AetherFlow uses **Playwright** for browser-driven testing of critical user flows, such as authentication, dashboard rendering, and marketplace interactions.

### Setup
```bash
npm install
npx playwright install
```

### Execution
Run the standard Playwright suite:
```bash
npx playwright test
```

### What E2E Tests Verify
- Critical routes load successfully.
- Navigation does not break under normal workflow conditions.
- Real-time dashboard components (e.g. Activity graph) mount without crashing.
- Authentication paths enforce redirect expectations.

---

## Backend Unit & Integration Testing (Go)

The backend is the operational core of AetherFlow. The project uses Go’s built-in testing model.

### Execution
Run tests across all Go module packages:
```bash
go test ./...
```

### What Backend Tests Verify
- Logic within individual REST / WS Route Handlers (`/api/v1/system`, etc.)
- FlowAI decision gating (verifying that proposed actions are actually intercepted).
- Struct Marshaling/Unmarshaling and configuration read capabilities.
- Marketplace manifest resolution logic.

> [!TIP]
> If a backend change affects auth, orchestration, status reporting, or realtime behavior, ensure you write a test verifying the state transitions under load.

---

## Manual Diagnostics (`test_api.py`)

AetherFlow includes `test_api.py` as a manual diagnostic script for remote and local API verification over SSH/Paramiko.

### Use Cases
- Bypassing the frontend to test raw WebSocket metrics telemetry.
- Testing auth flows if encountering CSRF desync issues in the browser.
- Simulating system resource loading logic without navigating the React UI.

**Usage**:
```bash
python3 test_api.py
```

> [!WARNING]
> `test_api.py` is a diagnostic tool, not a replacement for automated tests. Use it to quickly isolate whether an issue lies in the React state management or the core Go backend.
