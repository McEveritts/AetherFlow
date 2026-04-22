/**
 * Typed API contract types for AetherFlow.
 * Mirrors the backend Go struct shapes exactly.
 */

// ── Error Contract ──────────────────────────────────────────────────────
// Matches backend api.APIError struct from errors.go

/** Machine-readable error codes matching backend constants */
export type APIErrorCode =
    | 'INTERNAL_ERROR'
    | 'BAD_REQUEST'
    | 'UNAUTHORIZED'
    | 'FORBIDDEN'
    | 'NOT_FOUND'
    | 'CONFLICT'
    | 'RATE_LIMIT_EXCEEDED'
    | 'VALIDATION_ERROR'
    | 'QUOTA_EXCEEDED'
    | 'AI_UNAVAILABLE'
    | 'SESSION_EXPIRED'
    | 'SESSION_HIJACKED';

/** Structured API error matching the backend APIError shape */
export interface APIErrorBody {
    code: APIErrorCode;
    message: string;
    details?: unknown;
}

/**
 * Typed Error subclass for API failures.
 * Thrown by fetcher() on non-2xx responses and parsed from the JSON body.
 * Consumers can use `error instanceof APIError` for typed error handling.
 */
export class APIError extends Error {
    public readonly status: number;
    public readonly code: APIErrorCode;
    public readonly details?: unknown;

    constructor(status: number, body: APIErrorBody) {
        super(body.message);
        this.name = 'APIError';
        this.status = status;
        this.code = body.code;
        this.details = body.details;
    }

    /** True if the error indicates an expired or hijacked session */
    get isSessionError(): boolean {
        return this.code === 'SESSION_EXPIRED' || this.code === 'SESSION_HIJACKED';
    }

    /** True if the error is a rate limit (429) */
    get isRateLimit(): boolean {
        return this.code === 'RATE_LIMIT_EXCEEDED';
    }

    /** True if the error indicates the resource was not found */
    get isNotFound(): boolean {
        return this.code === 'NOT_FOUND';
    }
}

// ── Action Gate Contract ────────────────────────────────────────────────
// Matches backend api.PendingAction struct from action_gates.go

export type ActionClassification = 'safe' | 'warn' | 'critical';
export type ActionStatus = 'pending' | 'approved' | 'rejected' | 'executed' | 'failed';

export interface PendingAction {
    id: number;
    classification: ActionClassification;
    source: string;
    action: string;
    reason: string;
    status: ActionStatus;
    created_at: string;
    resolved_at?: string;
    resolved_by?: string;
    execution_log?: string;
}

export interface PendingActionsResponse {
    actions: PendingAction[];
    filter: string;
    count: number;
}

export interface ActionApproveResponse {
    status: 'approved';
    message: string;
}

export interface ActionRejectResponse {
    status: 'rejected';
}

// ── Audit Log Contract ──────────────────────────────────────────────────

export interface AuditLogEntry {
    id: number;
    user_id: number;
    username: string;
    action: string;
    target_type: string;
    target_id: string;
    detail: string;
    ip_address: string;
    user_agent: string;
    created_at: string;
}

export interface AuditLogResponse {
    entries: AuditLogEntry[];
    total: number;
    limit: number;
    offset: number;
}

// ── AI Chat Contract ────────────────────────────────────────────────────

export interface AIChatRequest {
    message: string;
    model?: string;
    provider?: 'gemini' | 'openai' | 'anthropic' | 'localai';
    history?: { role: string; text: string }[];
    context_mode?: 'logs' | 'metrics' | 'full';
    system_metrics?: unknown;
    system_logs?: unknown[];
}

export interface AIProposedAction {
    type: 'system_action';
    action_id: number;
    title: string;
    description: string;
    danger_level: 'info' | 'warn' | 'critical';
    impact: string;
}

export interface AIChatResponse {
    reply: string;
    proposed_action?: AIProposedAction;
}
