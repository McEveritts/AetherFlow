import {
  MCBROWSER_BASE,
  McBrowserRequestError,
  mcbrowserJsonRequest,
} from '@/lib/mcbrowser';

export const MCBROWSER_EVENTS_URL = `${MCBROWSER_BASE}/events`;
export const MCBROWSER_AUDIT_EVENTS_ALIAS_URL = `${MCBROWSER_BASE}/audit-events`;
export const MCBROWSER_EVENT_SETTINGS_URL = `${MCBROWSER_BASE}/events/settings`;
export const MCBROWSER_EVENT_QUEUE_URL = `${MCBROWSER_BASE}/events/queue`;

export const DEFAULT_MCBROWSER_AUDIT_LIST_LIMIT = 100;
export const MAX_MCBROWSER_AUDIT_LIST_LIMIT = 500;
export const DEFAULT_MCBROWSER_QUEUE_LIST_LIMIT = 100;
export const MAX_MCBROWSER_QUEUE_LIST_LIMIT = 500;

export const MCBROWSER_EVENT_TRIGGERS = [
  'upload_completed',
  'entry_deleted',
  'file_saved',
  'entry_copied',
  'entry_renamed',
  'share_created',
  'share_revoked',
] as const;

export type McBrowserEventTrigger = (typeof MCBROWSER_EVENT_TRIGGERS)[number];

export const MCBROWSER_AUDIT_EVENT_STATUSES = [
  'pending',
  'completed',
  'failed',
] as const;

export type McBrowserAuditEventStatus = (typeof MCBROWSER_AUDIT_EVENT_STATUSES)[number];

export const MCBROWSER_EVENT_QUEUE_STATUSES = [
  'queued',
  'acknowledged',
] as const;

export type McBrowserEventQueueStatus = (typeof MCBROWSER_EVENT_QUEUE_STATUSES)[number];

export interface McBrowserAuditEvent {
  event_id: string;
  timestamp: string;
  user_id: number;
  username: string;
  trigger: McBrowserEventTrigger;
  relative_path: string;
  destination_path?: string | null;
  byte_delta: number;
}

export interface McBrowserAuditRecord extends McBrowserAuditEvent {
  status: McBrowserAuditEventStatus;
  error_code?: string | null;
  updated_at: string;
}

export interface McBrowserAuditListQuery {
  limit?: number;
  status?: McBrowserAuditEventStatus | string;
  trigger?: McBrowserEventTrigger | string;
  user_id?: number | string | null;
}

export interface McBrowserAuditListResponse {
  events: McBrowserAuditRecord[];
  truncated: boolean;
}

export interface McBrowserEventSettingsDocument {
  enabled: boolean;
  queue_enabled: boolean;
}

export interface McBrowserUpdateEventSettingsRequest {
  enabled?: boolean;
  queue_enabled?: boolean;
}

export interface McBrowserQueuedEventTask {
  queue_id: number;
  event_id: string;
  status: McBrowserEventQueueStatus;
  event: McBrowserAuditEvent;
  enqueued_at: string;
  acknowledged_at?: string | null;
}

export interface McBrowserEventQueueListQuery {
  limit?: number;
  status?: McBrowserEventQueueStatus | string;
}

export interface McBrowserEventQueueListResponse {
  enabled: boolean;
  queue_enabled: boolean;
  tasks: McBrowserQueuedEventTask[];
  truncated: boolean;
}

export interface McBrowserAcknowledgeQueuedEventResponse {
  success: boolean;
  task: McBrowserQueuedEventTask;
}

const UUID_CANONICAL_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function normalizeMcBrowserBoundedLimit(
  limit: number | undefined,
  defaultLimit = DEFAULT_MCBROWSER_AUDIT_LIST_LIMIT,
  maxLimit = MAX_MCBROWSER_AUDIT_LIST_LIMIT,
): number {
  if (limit === undefined) {
    return defaultLimit;
  }
  if (
    typeof limit !== 'number' ||
    !Number.isFinite(limit) ||
    !Number.isInteger(limit) ||
    limit <= 0 ||
    limit > maxLimit
  ) {
    throw new McBrowserRequestError(
      400,
      'INVALID_QUERY_PARAM',
      `Query parameter 'limit' must be between 1 and ${maxLimit}.`,
    );
  }
  return limit;
}

export function normalizeMcBrowserAuditStatus(
  raw: string,
): McBrowserAuditEventStatus {
  const normalized = (typeof raw === 'string' ? raw : '').trim().toLowerCase();
  if (
    normalized === 'pending' ||
    normalized === 'completed' ||
    normalized === 'failed'
  ) {
    return normalized;
  }
  throw new McBrowserRequestError(
    400,
    'INVALID_QUERY_PARAM',
    `Unsupported audit status filter '${raw}'. Valid values: pending, completed, failed.`,
  );
}

export function normalizeMcBrowserEventTrigger(
  raw: string,
): McBrowserEventTrigger {
  const trimmed = (typeof raw === 'string' ? raw : '').trim();
  const lower = trimmed.toLowerCase();
  switch (lower) {
    case 'upload_completed':
    case 'uploadcompleted':
      return 'upload_completed';
    case 'entry_deleted':
    case 'entrydeleted':
      return 'entry_deleted';
    case 'file_saved':
    case 'filesaved':
      return 'file_saved';
    case 'entry_copied':
    case 'entrycopied':
      return 'entry_copied';
    case 'entry_renamed':
    case 'entryrenamed':
      return 'entry_renamed';
    case 'share_created':
    case 'sharecreated':
      return 'share_created';
    case 'share_revoked':
    case 'sharerevoked':
      return 'share_revoked';
    default:
      throw new McBrowserRequestError(
        400,
        'INVALID_QUERY_PARAM',
        `Unsupported event trigger filter '${raw}'.`,
      );
  }
}

export function normalizeMcBrowserAuditUserId(
  raw: number | string,
): number {
  if (typeof raw === 'number') {
    if (!Number.isFinite(raw) || !Number.isInteger(raw) || raw <= 0) {
      throw new McBrowserRequestError(
        400,
        'INVALID_QUERY_PARAM',
        "Query parameter 'user_id' must be a positive integer.",
      );
    }
    return raw;
  }
  const trimmed = (typeof raw === 'string' ? raw : '').trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new McBrowserRequestError(
      400,
      'INVALID_QUERY_PARAM',
      "Query parameter 'user_id' must be a positive integer.",
    );
  }
  const parsed = Number(trimmed);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new McBrowserRequestError(
      400,
      'INVALID_QUERY_PARAM',
      "Query parameter 'user_id' must be a positive integer.",
    );
  }
  return parsed;
}

export function normalizeMcBrowserEventQueueStatus(
  raw: string,
): McBrowserEventQueueStatus {
  const normalized = (typeof raw === 'string' ? raw : '').trim().toLowerCase();
  if (normalized === 'queued' || normalized === 'pending') {
    return 'queued';
  }
  if (
    normalized === 'acknowledged' ||
    normalized === 'acked' ||
    normalized === 'completed'
  ) {
    return 'acknowledged';
  }
  throw new McBrowserRequestError(
    400,
    'INVALID_QUERY_PARAM',
    `Unsupported event queue status filter '${raw}'. Valid values: queued, acknowledged.`,
  );
}

export function validateMcBrowserEventIdUuid(raw: string): string {
  const trimmed = (typeof raw === 'string' ? raw : '').trim();
  if (!UUID_CANONICAL_REGEX.test(trimmed)) {
    throw new McBrowserRequestError(
      400,
      'INVALID_EVENT_ID',
      `Event ID '${raw}' is not a valid canonical UUID.`,
    );
  }
  return trimmed.toLowerCase();
}

export function normalizeMcBrowserEventSettingsUpdate(
  input: boolean | McBrowserUpdateEventSettingsRequest,
): McBrowserEventSettingsDocument {
  if (typeof input === 'boolean') {
    return {
      enabled: input,
      queue_enabled: input,
    };
  }
  if (!input || typeof input !== 'object') {
    throw new McBrowserRequestError(
      400,
      'INVALID_SETTINGS_PAYLOAD',
      'Event settings payload must specify boolean enabled or queue_enabled.',
    );
  }
  const hasEnabled = typeof input.enabled === 'boolean';
  const hasQueueEnabled = typeof input.queue_enabled === 'boolean';
  if (!hasEnabled && !hasQueueEnabled) {
    throw new McBrowserRequestError(
      400,
      'INVALID_SETTINGS_PAYLOAD',
      'Event settings payload must specify boolean enabled or queue_enabled.',
    );
  }
  if (hasEnabled && hasQueueEnabled && input.enabled !== input.queue_enabled) {
    throw new McBrowserRequestError(
      400,
      'INVALID_SETTINGS_PAYLOAD',
      'enabled and queue_enabled must match when both are provided.',
    );
  }
  const resolved = hasEnabled ? (input.enabled as boolean) : (input.queue_enabled as boolean);
  return {
    enabled: resolved,
    queue_enabled: resolved,
  };
}

export function buildMcBrowserAuditEventsUrl(
  query?: McBrowserAuditListQuery,
): string {
  if (!query) {
    return MCBROWSER_EVENTS_URL;
  }
  const params = new URLSearchParams();
  if (query.limit !== undefined) {
    const limit = normalizeMcBrowserBoundedLimit(
      query.limit,
      DEFAULT_MCBROWSER_AUDIT_LIST_LIMIT,
      MAX_MCBROWSER_AUDIT_LIST_LIMIT,
    );
    params.set('limit', String(limit));
  }
  if (query.status !== undefined && String(query.status).trim() !== '') {
    params.set('status', normalizeMcBrowserAuditStatus(String(query.status)));
  }
  if (query.trigger !== undefined && String(query.trigger).trim() !== '') {
    params.set('trigger', normalizeMcBrowserEventTrigger(String(query.trigger)));
  }
  if (
    query.user_id !== undefined &&
    query.user_id !== null &&
    String(query.user_id).trim() !== ''
  ) {
    params.set('user_id', String(normalizeMcBrowserAuditUserId(query.user_id)));
  }
  const qs = params.toString();
  return qs ? `${MCBROWSER_EVENTS_URL}?${qs}` : MCBROWSER_EVENTS_URL;
}

export function buildMcBrowserEventQueueUrl(
  query?: McBrowserEventQueueListQuery,
): string {
  if (!query) {
    return MCBROWSER_EVENT_QUEUE_URL;
  }
  const params = new URLSearchParams();
  if (query.limit !== undefined) {
    const limit = normalizeMcBrowserBoundedLimit(
      query.limit,
      DEFAULT_MCBROWSER_QUEUE_LIST_LIMIT,
      MAX_MCBROWSER_QUEUE_LIST_LIMIT,
    );
    params.set('limit', String(limit));
  }
  if (query.status !== undefined && String(query.status).trim() !== '') {
    params.set('status', normalizeMcBrowserEventQueueStatus(String(query.status)));
  }
  const qs = params.toString();
  return qs ? `${MCBROWSER_EVENT_QUEUE_URL}?${qs}` : MCBROWSER_EVENT_QUEUE_URL;
}

export function getMcBrowserEventQueueAckUrl(eventId: string): string {
  const normalizedId = validateMcBrowserEventIdUuid(eventId);
  return `${MCBROWSER_EVENT_QUEUE_URL}/${encodeURIComponent(normalizedId)}/ack`;
}

export async function fetchMcBrowserAuditEvents(
  query?: McBrowserAuditListQuery,
  signal?: AbortSignal,
): Promise<McBrowserAuditListResponse> {
  const url = buildMcBrowserAuditEventsUrl(query);
  return mcbrowserJsonRequest<McBrowserAuditListResponse>(
    url,
    {
      method: 'GET',
      signal,
    },
    'Failed to load McBrowser audit events',
  );
}

export async function fetchMcBrowserEventSettings(
  signal?: AbortSignal,
): Promise<McBrowserEventSettingsDocument> {
  return mcbrowserJsonRequest<McBrowserEventSettingsDocument>(
    MCBROWSER_EVENT_SETTINGS_URL,
    {
      method: 'GET',
      signal,
    },
    'Failed to load McBrowser event queue settings',
  );
}

export async function saveMcBrowserEventSettings(
  settings: boolean | McBrowserUpdateEventSettingsRequest,
  signal?: AbortSignal,
): Promise<McBrowserEventSettingsDocument> {
  const normalized = normalizeMcBrowserEventSettingsUpdate(settings);
  return mcbrowserJsonRequest<McBrowserEventSettingsDocument>(
    MCBROWSER_EVENT_SETTINGS_URL,
    {
      method: 'PUT',
      body: JSON.stringify(normalized),
      signal,
    },
    'Failed to save McBrowser event queue settings',
  );
}

export async function fetchMcBrowserEventQueue(
  query?: McBrowserEventQueueListQuery,
  signal?: AbortSignal,
): Promise<McBrowserEventQueueListResponse> {
  const url = buildMcBrowserEventQueueUrl(query);
  return mcbrowserJsonRequest<McBrowserEventQueueListResponse>(
    url,
    {
      method: 'GET',
      signal,
    },
    'Failed to load McBrowser event task queue',
  );
}

export async function acknowledgeMcBrowserEventQueueTask(
  eventId: string,
  signal?: AbortSignal,
): Promise<McBrowserAcknowledgeQueuedEventResponse> {
  const url = getMcBrowserEventQueueAckUrl(eventId);
  return mcbrowserJsonRequest<McBrowserAcknowledgeQueuedEventResponse>(
    url,
    {
      method: 'POST',
      body: JSON.stringify({}),
      signal,
    },
    'Failed to acknowledge McBrowser queued event task',
  );
}
