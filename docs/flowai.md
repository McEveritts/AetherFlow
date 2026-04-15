# FlowAI Assistant

FlowAI is AetherFlow’s integrated AI operations layer, designed to help operators observe, diagnose, and manage their infrastructure with human-in-the-loop safety.

## Key Features

- **Context-Aware Assistance**: Automatically pulls recent logs and hardware metrics into the AI session context.
- **Support & Assistant Modes**: Distinct modes for learning versus execution.
- **Action Approval Gate**: A security boundary that intercepts AI-proposed system mutations for manual review.
- **Multi-Model Support**: Compatible with Gemini, Claude, OpenAI, and LocalAI (Ollama).

---

## Operational Modes

FlowAI operates in two distinct modes to match your workflow requirements.

### 1. Support Mode (Diagnostic)
**Purpose**: Explanation, interpretation, and operator guidance.
- **Grounding**: Injects historical metrics (past 5 minutes) and related service logs.
- **Use Cases**: "Why is my qBittorrent service flapping?", "Explain this OOM killer log entry."
- **Behavior**: Favors descriptive responses; does not typically propose system mutations.

### 2. Assistant Mode (Execution)
**Purpose**: Workflow automation and guided system management.
- **Grounding**: Focuses on current service state and marketplace availability.
- **Use Cases**: "Help me migrate my Plex data to a new disk," "Prepare an installation flow for Autobrr."
- **Behavior**: Actively drafts system command payloads that are routed to the **Action Gate**.

---

## The Action Approval Gate

To prevent destructive autonomous actions, FlowAI is constrained by the **Action Approval Gate**. This mechanism ensures that AI can *recommend* but never *execute* without explicit permission.

### The Flow
1. **Proposal**: FlowAI drafts an action (e.g., `systemctl restart af-plex`).
2. **Detection**: The Go backend detects the action pattern in the AI's response.
3. **Queue**: The action is placed in the **Approval Inbox** tab in the UI.
4. **Human Review**: The administrator reviews the command and its justification.
5. **Execution**: Only upon clicking **Approve** does the backend run the command via the System Control Layer.

> [!WARNING]
> While FlowAI is designed for safety, never approve an action you do not understand. The operator remains the ultimate authority for system integrity.

---

## Configuration & Model Selection

You can configure your model provider in the **AI Chat** settings panel.

| Provider | Connection | Best For |
| :--- | :--- | :--- |
| **Gemini** | API Key | Complex architectural reasoning & large context logs. |
| **Claude** | API Key | Concise, high-precision technical instructions. |
| **OpenAI** | API Key | General troubleshooting and platform navigation. |
| **LocalAI** | Ollama/REST | Privacy-conscious local inference (requires GPU). |

> [!TIP]
> Use **Gemini 1.5 Pro** or **Claude 3.5 Sonnet** for the best diagnostic accuracy in Support Mode.

---

## Troubleshooting FlowAI

- **"Model Unreachable"**: Verify your API key in settings or ensure your Ollama service is listening on the configured port.
- **"Context Overload"**: If your service logs are massive, FlowAI may trim them. Try clearing the chat to reset the context window.
- **"Action Not Detected"**: Ensure the AI specifically mentions the action it wants to take; generic suggestions like "maybe restart" won't trigger the Action Gate.
