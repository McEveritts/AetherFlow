// Package api defines the versioned HTTP and WebSocket surfaces for AetherFlow.
//
// Browser-facing routes live under authenticated and public groups, while
// selected admin endpoints are intentionally exposed as Headless Operator APIs
// for CLI and automation workflows such as cluster management, network
// orchestration, notification rule administration, OIDC client management, and
// AI-assisted metrics analysis.
package api
