# Implementation Plan - MediaNexus (Modernization & Windows Port)

This plan outlines the steps to modernize the MediaNexus (AetherFlow) codebase, optimize its performance, and migrate it to a Windows-compatible architecture while integrating Google Gemini capabilities.

## User Review Required

> [!IMPORTANT]
> The original project is a **Linux-exclusive** set of Bash scripts and PHP files relying on `systemd`, `/proc`, and `apt-get`. "Compiling" this directly to Windows is impossible.
> 
> **Proposed Strategy:**
> We will pivot to a **Containerized Architecture (Docker)**. This allows the application to run on Windows (via Docker Desktop/WSL2) *and* Linux without rewriting the entire logic. The dashboard will be decoupled: a modern Frontend (React/Next.js) talking to a Backend API (Go/Python) that manages these containers.

## Phase 1: Immediate Optimization (The "Deep Dive")
**Goal:** Fix critical performance bottlenecks and security risks in the existing PHP codebase before any major rewrite.

- [ ] **Optimize Process Monitoring**
    - **Current:** The dashboard executes `ps axo...` via `shell_exec` ~30 times per page load (once per service).
    - **Fix:** Refactor `processExists` in `dashboard/inc/config.php` to run `ps` *once*, cache the output, and perform in-memory checks.
- [ ] **Security Audit & Hardening**
    - **Current:** Heavy reliance on `shell_exec` with user input.
    - **Fix:** Implement a strict whitelist for `$_GET` actions (start/stop/restart) instead of passing variables directly to shell commands, even if escaped.
- [ ] **Modernize UI Assets**
    - Update the `dashboard/index.php` and widgets to use a consistent, modern variable system for colors (preparing for the "Glassmorphism" update).

## Phase 2: Google Gemini Integration
**Goal:** Add AI intelligence to the server dashboard.

- [ ] **Gemini API Integration**
    - create `dashboard/inc/gemini.php` to handle API requests.
- [ ] **Smart Assistant Widget**
    - Add a chat widget to usage `dashboard/widgets/gemini_chat.php`.
    - **Capabilities:**
        - "Summarize my server health" (reads CPU/RAM/Disk logs).
        - "Troubleshoot Plex" (scans specific log files for errors).
        - "Recommend cleanup" (identifies large/unused files).

## Phase 3: The Windows "Port" (Containerization)
**Goal:** Make MediaNexus run on Windows.

- [ ] **Dockerize Core Services**
    - Create a `docker-compose.yml` that defines the standard MediaNexus stack (rTorrent, Plex, Sonarr, Radarr).
    - This replaces the `/packages/install/` bash scripts.
- [ ] **Create Windows Launcher**
    - Build a small **Electron or Tauri app** (linking to your "LyricVault" experience) that:
        1. Checks for Docker Desktop.
        2. Pulls the MediaNexus images.
        3. serves as the "Tray Icon" for the server.

## Phase 4: Full Rewrite (Long Term)
**Goal:** Replace legacy PHP/Bash with a modern stack.

- [ ] **Backend Replacement:** Rewrite `dashboard/inc/config.php` logic into a **Go or Rust** API.
    - Why? Single binary, cross-platform, high performance, type-safe.
- [ ] **Frontend Replacement:** Rewrite the Dashboard in **React/Next.js**.
    - Enables the "Water-like" animations and high-end UI you requested.

---

## Detailed Task List - Phase 1 (Optimization)

### 1. Refactor Process Monitor
The current `processExists` function is the biggest lag source.
```php
// Current (Slow)
function processExists($processName) {
    exec("ps ... | grep $processName", $output); // Spawns shell 30x
}

// Proposed (Fast)
$processList = shell_exec("ps axo user,pid,comm,cmd"); // Spawns shell 1x
function processExists($processName) {
    // Search in $processList string
}
```

### 2. Strict Service Control
Replace dynamic `systemctl $c` calls with a switch/map to prevent any potential injection attacks and potential errors.

### 3. Abstraction Layer
Start creating a `SystemInterface` class.
- `SystemInterface->get_cpu_usage()`
- `SystemInterface->get_bandwidth()`
On Linux, it reads `/proc`. On Windows (dev mode), it can return mock data or read WMI (if running via PHP-for-Windows).
