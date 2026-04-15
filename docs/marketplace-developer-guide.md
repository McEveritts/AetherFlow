# Marketplace Developer Guide

This guide details the conventions and technical requirements for adding new applications to the AetherMarketplace. 

## Package Structure

Each marketplace application is located in the `/packages` directory, structured by its lifecycle role.

```bash
/packages
├── common.sh               # Root helper library (Mandatory)
├── package
│   ├── install
│   │   └── installpackage-<appname>  # Entry point for installation
│   └── remove
│       └── removepackage-<appname>   # Entry point for removal
```

---

## The `common.sh` Library

Every marketplace script **must** source the `common.sh` helper library. This ensures consistent logging, locking, and error handling across the ecosystem.

```bash
# Sourcing common.sh
source "$(dirname "$0")/../../common.sh"
```

### Essential Helper Functions

| Function | Purpose |
| :--- | :--- |
| `require_root` | Exits the script if not run with sudo/root privileges. |
| `print_info / print_error` | Logs and displays a message with a timestamp. |
| `write_lock / remove_lock` | Manages an installation lock to prevent race conditions. |
| `backup_file_once` | Creates a `.bak-af` snapshot before modifying a system file. |
| `fetch_and_run` | Safely downloads and executes a remote script with checksum validation. |

---

## Best Practices for Scripts

### 1. Idempotency is Mandatory
A script must be safe to run multiple times. If an app is already installed, the `installpackage` script should either skip or perform a safe repair/update. 

**Example Pattern:**
```bash
if [[ -f "/usr/bin/some-app" ]]; then
    print_info "App already detected. Skipping binary download."
else
    # Perform installation
fi
```

### 2. Service Naming Convention
To ensure the AetherFlow backend can manage your app, you must follow the service prefixing rule:
- **Service Name**: `af-<app_name>.service`
- **Location**: `/etc/systemd/system/af-<app_name>.service`

### 3. Sudoers Compliance
The AetherFlow backend executes scripts via `sudo`. Ensure any commands used in your script are likely to be covered by the `NOPASSWD` rules in `/etc/sudoers.d/aetherflow`.

### 4. Progress Feedback
The circular progress UI in the dashboard listens for exit codes and standard output. 
- **Success**: Exit `0`.
- **Failure**: Exit with a non-zero code and use `print_error` to describe the failure.

---

## Creating a New Package

1. **Clone the Template**: Start with `installpackage-template` in `/packages/package/install`.
2. **Define Variables**: Set unique paths for binary storage and configuration data.
3. **Use Helpers**:
   - Call `require_root` at the start.
   - Wrap the main logic in `write_lock` / `remove_lock`.
4. **Register with Backend**: Ensure the application metadata (icon, description) is added to the database's `Marketplace` table so it appears in the UI.

> [!IMPORTANT]
> **Always use absolute paths.** Scripts are executed from the backend directory, so relative paths within a script (like `./config.conf`) will fail. Use `$(dirname "$0")` or absolute `/opt/AetherFlow/` references.

---

## Validation Checklist

Before submitting a new package:
- [ ] Script sources `common.sh`.
- [ ] Script handles removal of its own systemd units.
- [ ] Script is safe to run twice (Idempotent).
- [ ] Error messages are descriptive for the end-user.
- [ ] Unit names are prefixed with `af-`.
