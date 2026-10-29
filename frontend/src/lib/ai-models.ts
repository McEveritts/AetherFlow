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
        { id: 'gemini-3.8-flash', name: 'Gemini 3.8 Flash', tier: 'latest' },
        { id: 'gemini-4-argon', name: 'Gemini 4 Argon', tier: 'latest' },
    ],
    openai: [
        { id: 'gpt-5.4', name: 'GPT 5.4', tier: 'latest' },
        { id: 'gpt-5.4-mini', name: 'GPT 5.4 Mini', tier: 'latest' },
        { id: 'gpt-4o', name: 'GPT 4o', tier: 'stable' },
        { id: 'gpt-4o-mini', name: 'GPT 4o Mini', tier: 'stable' },
        { id: 'gpt-4-turbo', name: 'GPT 4 Turbo', tier: 'stable' },
    ],
    anthropic: [
        { id: 'claude-opus-4.6', name: 'Claude Opus 4.6', tier: 'latest' },
        { id: 'claude-sonnet-4.6', name: 'Claude Sonnet 4.6', tier: 'latest' },
        { id: 'claude-opus-4.5', name: 'Claude Opus 4.5', tier: 'latest' },
        { id: 'claude-sonnet-4.5', name: 'Claude Sonnet 4.5', tier: 'latest' },
        { id: 'claude-opus', name: 'Claude Opus', tier: 'stable' },
        { id: 'claude-4-6-sonnet', name: 'Claude 4.6 Sonnet', tier: 'stable' },
        { id: 'claude-4-6-haiku', name: 'Claude 4.6 Haiku', tier: 'stable' },
        { id: 'claude-4-5-opus', name: 'Claude 4.5 Opus', tier: 'stable' },
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
