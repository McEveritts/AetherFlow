import { TextEncoder, TextDecoder } from 'util';
Object.assign(globalThis, { TextEncoder, TextDecoder });

import { apiFetch } from '@/lib/fetcher';
import { MCBROWSER_BASE, McBrowserRequestError } from '@/lib/mcbrowser';
import {
  DEFAULT_MCBROWSER_AUDIT_LIST_LIMIT,
  MAX_MCBROWSER_AUDIT_LIST_LIMIT,
  MCBROWSER_AUDIT_EVENTS_ALIAS_URL,
  MCBROWSER_AUDIT_EVENT_STATUSES,
  MCBROWSER_EVENTS_URL,
  MCBROWSER_EVENT_QUEUE_STATUSES,
  MCBROWSER_EVENT_QUEUE_URL,
  MCBROWSER_EVENT_SETTINGS_URL,
  MCBROWSER_EVENT_TRIGGERS,
  acknowledgeMcBrowserEventQueueTask,
  buildMcBrowserAuditEventsUrl,
  buildMcBrowserEventQueueUrl,
  fetchMcBrowserAuditEvents,
  fetchMcBrowserEventQueue,
  fetchMcBrowserEventSettings,
  getMcBrowserEventQueueAckUrl,
  normalizeMcBrowserAuditStatus,
  normalizeMcBrowserAuditUserId,
  normalizeMcBrowserBoundedLimit,
  normalizeMcBrowserEventQueueStatus,
  normalizeMcBrowserEventSettingsUpdate,
  normalizeMcBrowserEventTrigger,
  saveMcBrowserEventSettings,
  validateMcBrowserEventIdUuid,
} from '@/lib/mcbrowser-events';

jest.mock('@/lib/fetcher', () => ({
  apiFetch: jest.fn(),
}));

const mockedApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;

function mockJsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

describe('mcbrowser-events client library', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('exposes exact endpoints, limits, triggers, and statuses', () => {
    expect(MCBROWSER_EVENTS_URL).toBe(`${MCBROWSER_BASE}/events`);
    expect(MCBROWSER_AUDIT_EVENTS_ALIAS_URL).toBe(`${MCBROWSER_BASE}/audit-events`);
    expect(MCBROWSER_EVENT_SETTINGS_URL).toBe(`${MCBROWSER_BASE}/events/settings`);
    expect(MCBROWSER_EVENT_QUEUE_URL).toBe(`${MCBROWSER_BASE}/events/queue`);
    expect(DEFAULT_MCBROWSER_AUDIT_LIST_LIMIT).toBe(100);
    expect(MAX_MCBROWSER_AUDIT_LIST_LIMIT).toBe(500);
    expect(MCBROWSER_EVENT_TRIGGERS).toEqual([
      'upload_completed',
      'entry_deleted',
      'file_saved',
      'entry_copied',
      'entry_renamed',
      'share_created',
      'share_revoked',
    ]);
    expect(MCBROWSER_AUDIT_EVENT_STATUSES).toEqual(['pending', 'completed', 'failed']);
    expect(MCBROWSER_EVENT_QUEUE_STATUSES).toEqual(['queued', 'acknowledged']);
  });

  test('validates bounded limits, triggers, statuses, user_id, and UUIDs', () => {
    expect(normalizeMcBrowserBoundedLimit(undefined)).toBe(100);
    expect(normalizeMcBrowserBoundedLimit(1)).toBe(1);
    expect(normalizeMcBrowserBoundedLimit(500)).toBe(500);
    expect(() => normalizeMcBrowserBoundedLimit(0)).toThrow(McBrowserRequestError);
    expect(() => normalizeMcBrowserBoundedLimit(501)).toThrow(McBrowserRequestError);
    expect(() => normalizeMcBrowserBoundedLimit(12.5)).toThrow(McBrowserRequestError);

    expect(normalizeMcBrowserAuditStatus('COMPLETED')).toBe('completed');
    expect(() => normalizeMcBrowserAuditStatus('unknown')).toThrow(McBrowserRequestError);

    expect(normalizeMcBrowserEventTrigger('UploadCompleted')).toBe('upload_completed');
    expect(normalizeMcBrowserEventTrigger('share_revoked')).toBe('share_revoked');
    expect(() => normalizeMcBrowserEventTrigger('shell_exec')).toThrow(
      McBrowserRequestError,
    );

    expect(normalizeMcBrowserAuditUserId(42)).toBe(42);
    expect(normalizeMcBrowserAuditUserId('  7 ')).toBe(7);
    expect(() => normalizeMcBrowserAuditUserId(0)).toThrow(McBrowserRequestError);
    expect(() => normalizeMcBrowserAuditUserId('-5')).toThrow(McBrowserRequestError);
    expect(() => normalizeMcBrowserAuditUserId('abc')).toThrow(McBrowserRequestError);

    expect(normalizeMcBrowserEventQueueStatus('pending')).toBe('queued');
    expect(normalizeMcBrowserEventQueueStatus('acked')).toBe('acknowledged');
    expect(normalizeMcBrowserEventQueueStatus('completed')).toBe('acknowledged');
    expect(() => normalizeMcBrowserEventQueueStatus('dropped')).toThrow(
      McBrowserRequestError,
    );

    const sampleUuid = '123E4567-E89B-12D3-A456-426614174000';
    expect(validateMcBrowserEventIdUuid(sampleUuid)).toBe(sampleUuid.toLowerCase());
    expect(getMcBrowserEventQueueAckUrl(sampleUuid)).toBe(
      `${MCBROWSER_BASE}/events/queue/${sampleUuid.toLowerCase()}/ack`,
    );
    expect(() => validateMcBrowserEventIdUuid('not-a-uuid')).toThrow(
      McBrowserRequestError,
    );
  });

  test('builds audit and queue query URLs with normalized parameters', () => {
    expect(buildMcBrowserAuditEventsUrl()).toBe(`${MCBROWSER_BASE}/events`);
    expect(
      buildMcBrowserAuditEventsUrl({
        limit: 250,
        status: 'completed',
        trigger: 'FileSaved',
        user_id: '19',
      }),
    ).toBe(
      `${MCBROWSER_BASE}/events?limit=250&status=completed&trigger=file_saved&user_id=19`,
    );

    expect(
      buildMcBrowserEventQueueUrl({
        limit: 50,
        status: 'pending',
      }),
    ).toBe(`${MCBROWSER_BASE}/events/queue?limit=50&status=queued`);
  });

  test('normalizes event settings update payloads and rejects conflicting booleans', () => {
    expect(normalizeMcBrowserEventSettingsUpdate(true)).toEqual({
      enabled: true,
      queue_enabled: true,
    });
    expect(normalizeMcBrowserEventSettingsUpdate({ queue_enabled: false })).toEqual({
      enabled: false,
      queue_enabled: false,
    });
    expect(() =>
      normalizeMcBrowserEventSettingsUpdate({
        enabled: true,
        queue_enabled: false,
      }),
    ).toThrow(McBrowserRequestError);
    expect(() => normalizeMcBrowserEventSettingsUpdate({})).toThrow(
      McBrowserRequestError,
    );
  });

  test('fetches audit events, gets/saves settings, lists queue, and acknowledges task', async () => {
    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse({
        events: [
          {
            event_id: '123e4567-e89b-12d3-a456-426614174000',
            timestamp: '2026-11-02T00:00:00Z',
            user_id: 1,
            username: 'admin',
            trigger: 'file_saved',
            relative_path: 'docs/notes.md',
            destination_path: null,
            byte_delta: 120,
            status: 'completed',
            error_code: null,
            updated_at: '2026-11-02T00:00:01Z',
          },
        ],
        truncated: false,
      }),
    );

    const auditRes = await fetchMcBrowserAuditEvents({
      limit: 25,
      status: 'completed',
      trigger: 'file_saved',
      user_id: 1,
    });
    expect(auditRes.events).toHaveLength(1);
    expect(mockedApiFetch).toHaveBeenLastCalledWith(
      `${MCBROWSER_BASE}/events?limit=25&status=completed&trigger=file_saved&user_id=1`,
      expect.objectContaining({ method: 'GET' }),
    );

    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse({ enabled: true, queue_enabled: true }),
    );
    const settingsRes = await fetchMcBrowserEventSettings();
    expect(settingsRes).toEqual({ enabled: true, queue_enabled: true });

    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse({ enabled: false, queue_enabled: false }),
    );
    const savedSettings = await saveMcBrowserEventSettings(false);
    expect(savedSettings.queue_enabled).toBe(false);
    expect(mockedApiFetch).toHaveBeenLastCalledWith(
      `${MCBROWSER_BASE}/events/settings`,
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({ enabled: false, queue_enabled: false }),
      }),
    );

    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse({
        enabled: true,
        queue_enabled: true,
        tasks: [
          {
            queue_id: 10,
            event_id: '123e4567-e89b-12d3-a456-426614174000',
            status: 'queued',
            event: {
              event_id: '123e4567-e89b-12d3-a456-426614174000',
              timestamp: '2026-11-02T00:00:00Z',
              user_id: 1,
              username: 'admin',
              trigger: 'file_saved',
              relative_path: 'docs/notes.md',
              destination_path: null,
              byte_delta: 120,
            },
            enqueued_at: '2026-11-02T00:00:01Z',
            acknowledged_at: null,
          },
        ],
        truncated: false,
      }),
    );
    const queueRes = await fetchMcBrowserEventQueue({ limit: 50, status: 'queued' });
    expect(queueRes.tasks).toHaveLength(1);

    mockedApiFetch.mockResolvedValueOnce(
      mockJsonResponse({
        success: true,
        task: {
          queue_id: 10,
          event_id: '123e4567-e89b-12d3-a456-426614174000',
          status: 'acknowledged',
          event: {
            event_id: '123e4567-e89b-12d3-a456-426614174000',
            timestamp: '2026-11-02T00:00:00Z',
            user_id: 1,
            username: 'admin',
            trigger: 'file_saved',
            relative_path: 'docs/notes.md',
            destination_path: null,
            byte_delta: 120,
          },
          enqueued_at: '2026-11-02T00:00:01Z',
          acknowledged_at: '2026-11-02T00:02:00Z',
        },
      }),
    );
    const ackRes = await acknowledgeMcBrowserEventQueueTask(
      '123E4567-E89B-12D3-A456-426614174000',
    );
    expect(ackRes.success).toBe(true);
    expect(ackRes.task.status).toBe('acknowledged');
    expect(mockedApiFetch).toHaveBeenLastCalledWith(
      `${MCBROWSER_BASE}/events/queue/123e4567-e89b-12d3-a456-426614174000/ack`,
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({}),
      }),
    );
  });
});
