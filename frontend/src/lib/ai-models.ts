/**
 * Shared AI model definitions — Single Source of Truth.
 * Used by both SettingsTab (default model selector) and AiChatTab (per-chat model picker).
 *
 * Every model listed here MUST have a corresponding entry in the backend's
 * allowedAIModels whitelist (backend/api/ai.go).
 */

export type AIProviderID = 'gemini' | 'openai' | 'anthropic' | 'localai';

export interface AIModelDef {
    id: string;
    name: string;
    tier: 'preview' | 'latest' | 'stable' | 'local';
}

export interface AIProviderDef {
    id: AIProviderID;
    name: string;
}

export const AI_PROVIDERS: AIProviderDef[] = [
    { id: 'gemini', name: 'Gemini' },
    { id: 'openai', name: 'OpenAI' },
    { id: 'anthropic', name: 'Anthropic' },
    { id: 'localai', name: 'Local AI' },
];

export const AI_MODELS: Record<AIProviderID, AIModelDef[]> = {
    gemini: [
        { id: 'gemini-4-argon', name: 'Gemini 4 Argon', tier: 'latest' },
    ],
    openai: [
        { id: 'gpt-6-astra', name: 'GPT-6 Astra', tier: 'latest' },
        { id: 'gpt-6.1-sol', name: 'GPT-6.1 Sol', tier: 'latest' },
        { id: 'gpt-6.1-terra', name: 'GPT-6.1 Terra', tier: 'latest' },
        { id: 'gpt-6-luna', name: 'GPT-6 Luna', tier: 'latest' },
    ],
    anthropic: [
        { id: 'claude-fable-5-1', name: 'Claude Fable 5.1', tier: 'latest' },
        { id: 'claude-opus-5-5', name: 'Claude Opus 5.5', tier: 'latest' },
        { id: 'claude-sonnet-5-5', name: 'Claude Sonnet 5.5', tier: 'latest' },
        { id: 'claude-haiku-5-5', name: 'Claude Haiku 5.5', tier: 'latest' },
    ],
    localai: [
        { id: 'lm-studio', name: 'LM Studio (Local)', tier: 'local' },
        { id: 'ollama', name: 'Ollama (Local)', tier: 'local' },
        { id: 'anthropic-local', name: 'Anthropic Endpoint (Local)', tier: 'local' },
    ],
};

/** Flat list of all model IDs across all providers */
export const ALL_MODEL_IDS = Object.values(AI_MODELS).flat().map(m => m.id);

/** Get the provider for a given model ID */
export function resolveProviderForModel(modelId: string): AIProviderID {
    for (const [providerId, models] of Object.entries(AI_MODELS)) {
        if (models.some(m => m.id === modelId)) {
            return providerId as AIProviderID;
        }
    }
    return 'gemini';
}
