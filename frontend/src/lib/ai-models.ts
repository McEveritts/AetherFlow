/**
 * Shared AI model & runtime definitions — Single Source of Truth.
 * Used by both SettingsTab (default model + local runtime/model configuration)
 * and AiChatTab (per-chat provider/runtime/model picker).
 *
 * Provider/locality aliases (`lm-studio`, `ollama`, `anthropic-local`, `localai`,
 * `local-test`, `gemini`, `openai`, `anthropic`) are runtime/provider selectors
 * and MUST NEVER be sent upstream as inference model IDs.
 */

export type AIProviderID = 'gemini' | 'openai' | 'anthropic' | 'localai';

export type LocalAIRuntimeID = 'lm-studio' | 'ollama' | 'anthropic-local';

export interface AIModelDef {
    id: string;
    name: string;
    tier: 'preview' | 'latest' | 'stable' | 'local';
}

export interface AIProviderDef {
    id: AIProviderID;
    name: string;
}

export interface LocalAIRuntimeDef {
    id: LocalAIRuntimeID;
    name: string;
    protocol: 'openai-compatible' | 'anthropic-messages';
    defaultEndpoint: string;
    defaultModel: string;
}

export const AI_PROVIDERS: AIProviderDef[] = [
    { id: 'gemini', name: 'Gemini' },
    { id: 'openai', name: 'OpenAI' },
    { id: 'anthropic', name: 'Anthropic' },
    { id: 'localai', name: 'Local AI' },
];

export const LOCAL_AI_RUNTIMES: LocalAIRuntimeDef[] = [
    {
        id: 'lm-studio',
        name: 'LM Studio (Local)',
        protocol: 'openai-compatible',
        defaultEndpoint: 'http://localhost:1234',
        defaultModel: 'qwen2.5-coder-7b-instruct',
    },
    {
        id: 'ollama',
        name: 'Ollama (Local)',
        protocol: 'openai-compatible',
        defaultEndpoint: 'http://localhost:11434',
        defaultModel: 'llama3.2:latest',
    },
    {
        id: 'anthropic-local',
        name: 'Anthropic Endpoint (Local)',
        protocol: 'anthropic-messages',
        defaultEndpoint: 'http://localhost:8080',
        defaultModel: 'claude-sonnet-5-5',
    },
];

export const DEFAULT_AI_MODEL_ID = 'gemini-4-argon';
export const DEFAULT_LOCAL_RUNTIME_ID: LocalAIRuntimeID = 'ollama';
export const DEFAULT_LOCAL_MODEL_ID = 'llama3.2:latest';

export const FORBIDDEN_MODEL_ALIASES: readonly string[] = [
    'lm-studio',
    'ollama',
    'anthropic-local',
    'localai',
    'local-test',
    'local',
    'gemini',
    'openai',
    'anthropic',
];

export function isForbiddenModelAlias(value: string | null | undefined): boolean {
    if (!value) return true;
    const normalized = value.trim().toLowerCase();
    return normalized.length === 0 || FORBIDDEN_MODEL_ALIASES.includes(normalized);
}

export function isLocalRuntimeId(value: string | null | undefined): value is LocalAIRuntimeID {
    return value === 'lm-studio' || value === 'ollama' || value === 'anthropic-local';
}

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
        { id: 'llama3.2:latest', name: 'Llama 3.2 (Local)', tier: 'local' },
        { id: 'qwen2.5-coder-7b-instruct', name: 'Qwen 2.5 Coder 7B (Local)', tier: 'local' },
    ],
};

/** Flat list of cloud model IDs across cloud providers */
export const CLOUD_MODEL_IDS = [
    ...AI_MODELS.gemini,
    ...AI_MODELS.openai,
    ...AI_MODELS.anthropic,
].map(m => m.id);

/** Flat list of all catalog model IDs (never includes provider/locality aliases) */
export const ALL_MODEL_IDS = Object.values(AI_MODELS).flat().map(m => m.id);

/** Get the provider for a given model ID */
export function resolveProviderForModel(modelId: string): AIProviderID {
    const trimmed = (modelId || '').trim();
    if (!trimmed) return 'gemini';
    if (
        isLocalRuntimeId(trimmed) ||
        trimmed.startsWith('lm-studio:') ||
        trimmed.startsWith('ollama:') ||
        trimmed.startsWith('anthropic-local:')
    ) {
        return 'localai';
    }
    for (const providerId of ['gemini', 'openai', 'anthropic'] as const) {
        if (AI_MODELS[providerId].some(m => m.id === trimmed)) {
            return providerId;
        }
    }
    if (!isForbiddenModelAlias(trimmed)) {
        return 'localai';
    }
    return 'gemini';
}

export interface ParsedAiSettingsConfig {
    provider: AIProviderID;
    aiModel: string;
    localRuntime: LocalAIRuntimeID;
    localModel: string;
}

/**
 * Parse stored settings payload into separated provider, active model ID,
 * local runtime target (`lm-studio` | `ollama` | `anthropic-local`), and
 * installed local model ID (guaranteed never to be a provider/locality alias).
 */
export function parseStoredAiSettings(data?: Record<string, string>): ParsedAiSettingsConfig {
    const rawAiModel = typeof data?.aiModel === 'string' ? data.aiModel.trim() : '';
    const rawLocalModel = typeof data?.localModel === 'string' ? data.localModel.trim() : '';
    const rawLocalProvider =
        typeof data?.localProvider === 'string'
            ? data.localProvider.trim()
            : typeof data?.localRuntime === 'string'
            ? data.localRuntime.trim()
            : '';

    let localRuntime: LocalAIRuntimeID = isLocalRuntimeId(rawLocalProvider)
        ? rawLocalProvider
        : DEFAULT_LOCAL_RUNTIME_ID;

    let explicitLocalModel =
        rawLocalModel && !isForbiddenModelAlias(rawLocalModel) ? rawLocalModel : '';

    // Handle `<localRuntime>:<installedModelId>` encoding if present in aiModel
    for (const rt of LOCAL_AI_RUNTIMES) {
        const prefix = `${rt.id}:`;
        if (rawAiModel.startsWith(prefix)) {
            localRuntime = rt.id;
            const remainder = rawAiModel.slice(prefix.length).trim();
            if (remainder && !isForbiddenModelAlias(remainder)) {
                explicitLocalModel = remainder;
            }
            const resolvedLocal = explicitLocalModel || rt.defaultModel || DEFAULT_LOCAL_MODEL_ID;
            return {
                provider: 'localai',
                aiModel: resolvedLocal,
                localRuntime,
                localModel: resolvedLocal,
            };
        }
    }

    // Handle legacy bare runtime alias in aiModel (`lm-studio`, `ollama`, `anthropic-local`)
    if (isLocalRuntimeId(rawAiModel)) {
        localRuntime = rawAiModel;
        const rtDef = LOCAL_AI_RUNTIMES.find(r => r.id === rawAiModel);
        const resolvedLocal = explicitLocalModel || rtDef?.defaultModel || DEFAULT_LOCAL_MODEL_ID;
        return {
            provider: 'localai',
            aiModel: resolvedLocal,
            localRuntime,
            localModel: resolvedLocal,
        };
    }

    // Known cloud model ID
    if (CLOUD_MODEL_IDS.includes(rawAiModel)) {
        return {
            provider: resolveProviderForModel(rawAiModel),
            aiModel: rawAiModel,
            localRuntime,
            localModel: explicitLocalModel || DEFAULT_LOCAL_MODEL_ID,
        };
    }

    // Custom installed local model ID stored in aiModel
    if (rawAiModel && !isForbiddenModelAlias(rawAiModel)) {
        if (!isLocalRuntimeId(rawLocalProvider)) {
            const anthropicEp = (data?.anthropicEndpoint || '').trim();
            const ollamaEp = (data?.ollamaEndpoint || '').trim();
            const lmStudioEp = (data?.lmStudioEndpoint || '').trim();
            if (anthropicEp && anthropicEp !== 'https://api.anthropic.com') {
                localRuntime = 'anthropic-local';
            } else if (ollamaEp && ollamaEp !== 'http://localhost:11434') {
                localRuntime = 'ollama';
            } else if (lmStudioEp) {
                localRuntime = 'lm-studio';
            }
        }
        return {
            provider: 'localai',
            aiModel: rawAiModel,
            localRuntime,
            localModel: explicitLocalModel || rawAiModel,
        };
    }

    return {
        provider: 'gemini',
        aiModel: DEFAULT_AI_MODEL_ID,
        localRuntime,
        localModel: explicitLocalModel || DEFAULT_LOCAL_MODEL_ID,
    };
}
