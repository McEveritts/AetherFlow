# FlowAI Assistant

FlowAI is AetherFlow's integrated AI operations layer, designed to help operators observe, diagnose, and manage their infrastructure with human-in-the-loop safety.

## Key Features

- **Context-Aware Assistance**: Automatically pulls recent logs and hardware metrics into the AI session context.
- **Support & Assistant Modes**: Distinct modes for learning versus execution.
- **Action Approval Gate**: A security boundary that intercepts AI-proposed system mutations for manual review.
- **Multi-Provider Support**: Route requests to Gemini, OpenAI, Anthropic, or local LLMs (LM Studio, Ollama) with a single abstraction layer.

---

## Architecture Overview

FlowAI uses a provider-agnostic routing layer (`backend/providers/`) to decouple all AI logic from any specific SDK.

```
┌────────────────────────────────────────────────────┐
│  Frontend (React/Next.js)                          │
│  AiChatTab.tsx → sends { model, provider, ... }    │
│  SettingsTab.tsx → shared AI_MODELS from ai-models │
└──────────────────────┬─────────────────────────────┘
                       │ POST /api/v1/auth/ai/chat
                       ▼
┌────────────────────────────────────────────────────┐
│  API Layer (backend/api/ai.go)                     │
│  runChatSession()                                  │
│    1. ResolveProviderSettings() → decrypted keys   │
│    2. ResolveProvider(hint, model) → provider type │
│    3. buildProviderConfig() → ProviderConfig       │
│    4. providers.NewProvider(type, cfg) → AIProvider │
│    5. provider.Chat(ctx, ...) → Response           │
└──────────────────────┬─────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
  ┌──────────┐  ┌──────────┐  ┌──────────────┐
  │ Gemini   │  │ OpenAI   │  │ Anthropic    │
  │ (genai)  │  │ (HTTP)   │  │ (HTTP)       │
  └──────────┘  └──────────┘  └──────────────┘
                     │
                ┌────┴────┐
                │ LocalAI │ (LM Studio / Ollama)
                └─────────┘
```

### The `AIProvider` Interface

All providers implement this Go interface (`backend/providers/provider.go`):

```go
type AIProvider interface {
    Chat(ctx context.Context, systemPrompt string, history []Message, message string) (*Response, error)
    Generate(ctx context.Context, prompt string) (*Response, error)
    TestConnection(ctx context.Context) error
    Close() error
}
```

### Provider Routing

The provider is determined by:
1. **Explicit `provider` field** in the request body (highest priority)
2. **Model ID prefix auto-detection**: `gemini-*` → Gemini, `gpt-*` → OpenAI, `claude-*` → Anthropic, `lm-studio`/`ollama` → LocalAI
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
2. **Detection**: The Go backend detects the action pattern in the AI's response.
3. **Queue**: The action is placed in the **Approval Inbox** tab in the UI.
4. **Human Review**: The administrator reviews the command and its justification.
5. **Execution**: Only upon clicking **Approve** does the backend run the command.

> [!WARNING]
> While FlowAI is designed for safety, never approve an action you do not understand.

---

## Configuration & Credentials

### Provider Setup

Configure providers in **Settings → FlowAI Engine**:

| Provider | Credential | Endpoint Override | Notes |
| :--- | :--- | :--- | :--- |
| **Gemini** | `gemini_api_key` | N/A | Default provider. Also accepts `GEMINI_API_KEY` env var. |
| **OpenAI** | `openai_api_key` | N/A | Also accepts `OPENAI_API_KEY` env var. |
| **Anthropic** | `anthropic_api_key` | `anthropic_endpoint` | Custom endpoint for proxied access. Also accepts `ANTHROPIC_API_KEY` env var. |
| **LM Studio** | N/A | `lm_studio_endpoint` | Defaults to `http://localhost:1234`. OpenAI-compatible API. |
| **Ollama** | N/A | `ollama_endpoint` | Defaults to `http://localhost:11434`. OpenAI-compatible API. |
| **Anthropic-Local** | N/A | `anthropic_endpoint` | Routes `anthropic-local` model to a custom endpoint. Defaults to `http://localhost:8080`. |

### Credential Security

- All API keys are **AES-encrypted** at rest in the SQLite `settings` table.
- Keys are decrypted in-memory only when creating a provider instance.
- The Settings API masks keys before sending to the frontend (`****` prefix).
- Provider constructors receive decrypted keys via **dependency injection** — they never access the database or environment directly.

### Model Selection

Models are defined in a single source of truth: `frontend/src/lib/ai-models.ts`. This file is imported by both `SettingsTab.tsx` (default model) and `AiChatTab.tsx` (per-chat model picker). Every model listed there must have a corresponding entry in the backend `allowedAIModels` whitelist (`backend/api/ai.go`).

### Background Services

Background services (bandwidth optimizer, resource predictor, metadata enricher, smart backup) use the shared Gemini provider via `services.GenerateWithGemini()`. This function returns a cached, long-lived provider singleton that is automatically recreated if the API key changes.

---

## Troubleshooting FlowAI

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| "Model Unreachable" | Missing or invalid API key | Verify key in Settings → FlowAI Engine. Check env vars. |
| 400 "Invalid AI model" | Model not in backend whitelist | Ensure the model ID matches an entry in `allowedAIModels`. |
| "AI provider initialization failed" | Provider constructor error | Check that the correct credentials/endpoints are configured. |
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

Dynamically tests whichever provider the admin selects. Accepts unsaved keys for pre-save validation.

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
- `gemini` → `gemini-2.0-flash`
- `openai` → `gpt-4o`
- `anthropic` → `claude-sonnet-4.5`
- `localai` → uses the provided endpoint directly

> [!TIP]
> In the Settings UI, each provider section has a dedicated "Test" button that invokes this endpoint with the correct provider type. You can test unsaved keys before committing them.
```

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
