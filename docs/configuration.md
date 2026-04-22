# Configuration Reference

AetherFlow uses a standardized environment file (`.env`) for core application settings. This allows for clean separation between the immutable code and the host-specific configuration.

## Environment File (.env)

The `.env` file is located in the root of the AetherFlow installation. After any modification to this file, you must restart the services to apply changes.

```bash
sudo systemctl restart aetherflow-api aetherflow-frontend
```

---

## Core Variables

These variables are required for the platform to function correctly.

| Variable | Description | Default |
| :--- | :--- | :--- |
| `ADMIN_EMAIL` | The email address granted automatic administrative rights on first login. | `(Required)` |
| `JWT_SECRET` | A random string used to sign session tokens. | `(Required)` |
| `AES_MASTER_KEY` | A 32-byte base64 string for database encryption at rest. | `(Required)` |
| `PORT` | The network port for the Go API backend. | `8080` |
| `DB_PATH` | Absolute path to the SQLite terminal database. | `/opt/AetherFlow/backend/aetherflow.sqlite` |

---

## Security & Authentication

AetherFlow prioritizes secure defaults. Ensure these are configured for production environments.

### Google OAuth2 (SSO)
Required for the primary login flow. Create credentials at the [Google Cloud Console](https://console.cloud.google.com/apis/credentials).

| Variable | Description |
| :--- | :--- |
| `GOOGLE_CLIENT_ID` | Your OAuth 2.0 Client ID. |
| `GOOGLE_CLIENT_SECRET` | Your OAuth 2.0 Client Secret. |
| `GOOGLE_REDIRECT_URI` | Typically `https://YOUR_DOMAIN/api/auth/google/callback`. |

### Advanced Security
| Variable | Description | Default |
| :--- | :--- | :--- |
| `COOKIE_SECURE` | Set to `false` only for local HTTP development. | `true` |
| `CSRF_DISABLED` | Set to `true` to disable CSRF protection (Not recommended). | `false` |
| `REDIS_ADDR` | Address of the Redis instance for session invalidation. | `localhost:6379` |
| `ALLOWED_HOSTS` | Comma-separated list of Host headers (e.g., `api.aetherflow.com`). | `(All)` |

---

## AI & FlowAI

Configuration for the integrated multi-provider management assistant. Settings here act as defaults but can be overridden dynamically within the UI or via local endpoints.

| Variable | Description |
| :--- | :--- |
| `GEMINI_API_KEY` | Your Google AI Studio API key. |
| `ANTHROPIC_API_KEY` | (Optional) For Claude-based support. |
| `OPENAI_API_KEY` | (Optional) For GPT-4 based support. |
| `LM_STUDIO_ENDPOINT` | (Optional) Override for local LM Studio API. Defaults to `http://localhost:1234`. |
| `OLLAMA_ENDPOINT` | (Optional) Override for local Ollama API. Defaults to `http://localhost:11434`. |

> [!TIP]
> **FlowAI Support Mode** performs best when provided with a high-bandwidth model like Gemini 2.0 Flash or Claude 3.5 Sonnet. Advanced users can use **LocalAI** via LM Studio or Ollama for full data privacy.

---

## Cluster & Networking

For multi-node deployments or advanced networking.

| Variable | Description | Options |
| :--- | :--- | :--- |
| `CLUSTER_MODE` | Deployment topology. | `standalone`, `master`, `worker` |
| `GRPC_PORT` | Port for internal gRPC node communication. | `50051` |
| `ALLOWED_CORS_ORIGIN` | Explicit frontend origin URLs. | `(Auto-detected)` |

---

## Database Management

AetherFlow uses **SQLite** as its primary storage engine to keep infrastructure overhead low.

> [!WARNING]
> **Data Portability**: Since SQLite is a file-based database, ensure you have regular backups of the file specified in `DB_PATH`. Changing the `AES_MASTER_KEY` after data has been written will render the encrypted fields in the database unreadable.

To check database health:
```bash
# Check if the DB file exists and is readable
ls -lh /opt/AetherFlow/backend/aetherflow.sqlite
```
