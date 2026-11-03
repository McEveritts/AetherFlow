# FlowAI Assistant

FlowAI is AetherFlow's integrated AI operations layer, designed to help operators observe, diagnose, and manage their infrastructure with human-in-the-loop safety.

## Key Features

- **Context-Aware Assistance**: Automatically pulls recent logs and hardware metrics into the AI session context.
- **Support & Assistant Modes**: Distinct modes for learning versus execution.
- **Action Approval Gate**: A security boundary that intercepts AI-proposed system mutations for manual review.
- **Multi-Provider Support**: Route requests to Gemini, OpenAI, Anthropic, or local LLMs (LM Studio, Ollama) with a single abstraction layer.

---

## Architecture Overview

FlowAI uses a provider-agnostic routing layer in the Rust control plane (`backend-rs/crates/af-api/src/intelligence.rs`, with parity in `backend/providers/`) to decouple all AI logic from any specific vendor SDK.

```
┌─────────────────────────────────────────────────────┐
│  Frontend (Next.js 16 / Obsidian V2)                │
│  AiChatTab.tsx → sends { model, provider, ... }     │
│  SettingsTab.tsx → shared AI_MODELS from ai-models  │
└──────────────────────┬──────────────────────────────┘
                       │ POST /api/v1/auth/ai/chat
                       ▼
┌─────────────────────────────────────────────────────┐
│  Rust API Layer (af-api::intelligence)              │
│    1. Decrypt AES-256-GCM keys from SQLite (af-db)  │
│    2. Resolve provider & model fallback chain       │
│    3. Inject live telemetry / journald context      │
│    4. Dispatch request & parse proposed actions     │
└──────────────────────┬──────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
  ┌──────────┐  ┌──────────┐  ┌──────────────┐
  │ Gemini   │  │ OpenAI   │  │ Anthropic    │
  │ (HTTPS)  │  │ (HTTPS)  │  │ (HTTPS)      │
  └──────────┘  └──────────┘  └──────────────┘
                     │
                ┌────┴────┐
                │ LocalAI │ (LM Studio / Ollama)
                └─────────┘
```

### Provider Routing

The provider is determined by:
1. **Explicit `provider` field** in the request body (highest priority)
2. **Model ID prefix auto-detection**: `gemini-*` → Gemini (default `gemini-4-argon` with automatic model fallback chain), `gpt-*` → OpenAI, `claude-*` → Anthropic, `lm-studio`/`ollama` → LocalAI
3. **Default fallback**: Gemini

---

## Operational Modes

### 1. Support Mode (Diagnostic)
**Purpose**: Explanation, interpretation, and operator guidance.
- **Grounding**: Injects historical metrics (past 5 minutes) and related service logs.
- **Context Modes**: `full` (logs + metrics), `logs` (logs only), `metrics` (metrics only)
- **Use Cases**: "Why is my qBittorrent service flapping?", "Explain this OOM killer log entry."

### 2. Assistant Mode (Execution)
**Purpose**: Workflow automation and guided system management.
- **Grounding**: Focuses on current service state and marketplace availability.
- **Use Cases**: "Help me migrate my Plex data to a new disk," "Prepare an installation flow for Autobrr."
- **Behavior**: Actively drafts system command payloads that are routed to the **Action Gate**.

---

## The Action Approval Gate

To prevent destructive autonomous actions, FlowAI is constrained by the **Action Approval Gate**.

### The Flow
1. **Proposal**: FlowAI drafts an action (e.g., `systemctl restart af-plex`).
2. **Detection**: The Rust control plane (`af-api::intelligence`) detects the action pattern in the AI's response.
3. **Queue**: The action is serialized into `pending_actions` and placed in the **Approval Inbox** tab in the UI.
4. **Human Review**: The administrator reviews the command and its justification.
5. **Execution**: Only upon clicking **Approve** does `af-api` dispatch the allowlisted request over `/run/aetherflow/runner.sock` and record the resolution in `admin_audit_log`.

> [!WARNING]
> While FlowAI is designed for safety, never approve an action you do not understand.

---

## Configuration & Credentials

### Provider Setup

Configure providers in **Settings → FlowAI Engine**:

| Provider | Credential | Endpoint Override | Notes |
| :--- | :--- | :--- | :--- |
| **Gemini** | `gemini_api_key` | N/A | Default provider (`gemini-4-argon`). Also accepts `GEMINI_API_KEY` env var. |
| **OpenAI** | `openai_api_key` | N/A | Supports GPT-6 / GPT-6.1 models. Also accepts `OPENAI_API_KEY` env var. |
| **Anthropic** | `anthropic_api_key` | `anthropic_endpoint` | Supports Claude 5.1 / 5.5 models. Also accepts `ANTHROPIC_API_KEY` env var. |
| **LM Studio** | N/A | `lm_studio_endpoint` | Defaults to `http://localhost:1234`. OpenAI-compatible API. |
| **Ollama** | N/A | `ollama_endpoint` | Defaults to `http://localhost:11434`. OpenAI-compatible API. |
| **Anthropic-Local** | N/A | `anthropic_endpoint` | Routes `anthropic-local` model to a custom endpoint. Defaults to `http://localhost:8080`. |

### Credential Security

- All API keys are **AES-256-GCM encrypted** (`enc:v1:`) at rest in the SQLite `settings` table (`af-db`).
- Keys are decrypted in-memory only when dispatching a provider request.
- The Settings API masks keys before sending to the frontend (`****` prefix).

### Model Selection

Models are defined in `frontend/src/lib/ai-models.ts`, imported by both `SettingsTab.tsx` (default model) and `AiChatTab.tsx` (per-chat model picker), and validated against the backend model allowlist in `af-api::intelligence` (`backend-rs/crates/af-api/src/intelligence.rs`).

---

## Troubleshooting FlowAI

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| "Model Unreachable" | Missing or invalid API key | Verify key in Settings → FlowAI Engine. Check env vars. |
| 400 "Invalid AI model" | Model not in backend allowlist | Ensure the model ID matches an entry in `frontend/src/lib/ai-models.ts` and `af-api::intelligence`. |
| "AI provider initialization failed" | Provider configuration error | Check that the correct credentials/endpoints are configured. |
| "Connection error" on local AI | LM Studio or Ollama not running | Start the local server and verify the endpoint URL. |
| "Context Overload" | Massive service logs | Clear the chat to reset the context window. Try `logs` mode. |
| "Action Not Detected" | Generic AI suggestion | Ensure the AI specifically names the action to trigger the Gate. |

---

## API Contract

### `POST /api/v1/auth/ai/chat`

```json
{
  "message": "string (required)",
  "model": "string (optional, default from settings)",
  "provider": "gemini | openai | anthropic | localai (optional, auto-detected from model)",
  "history": [{ "role": "user|assistant", "text": "..." }]
}
```

### `POST /api/v1/auth/ai/support`

Extends the chat request with:
```json
{
  "context_mode": "full | logs | metrics"
}
```

### `POST /api/v1/admin/settings/test-ai`

Dynamically tests whichever provider the admin selects. Accepts unsaved keys for pre-save validation:

```json
{
  "gemini_api_key": "string (optional, for Gemini testing)",
  "openai_api_key": "string (optional, for OpenAI testing)",
  "anthropic_api_key": "string (optional, for Anthropic testing)",
  "provider": "gemini | openai | anthropic | localai",
  "endpoint": "string (optional, for local AI endpoint override)"
}
```

The endpoint automatically selects the appropriate test model per provider:
- `gemini` → `gemini-4-argon`
- `openai` → `gpt-6.1-sol`
- `anthropic` → `claude-sonnet-5-5`
- `localai` → uses the provided endpoint directly

> [!TIP]
> In the Settings UI, each provider section has a dedicated "Test" button that invokes this endpoint with the correct provider type. You can test unsaved keys before committing them.

### Response

```json
{
  "reply": "string",
  "proposed_action": {
    "type": "system_action",
    "action_id": 123,
    "title": "Restart nginx",
    "description": "AI-proposed: Restart nginx",
    "danger_level": "info | warn | critical",
    "impact": "Service will be temporarily unavailable."
  }
}
```
