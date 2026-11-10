'use client';

import React, { useCallback, useEffect, useId, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Filter,
  ListChecks,
  Loader2,
  RefreshCw,
  Settings,
  X,
} from 'lucide-react';
import {
  extractMcBrowserError,
  formatBytes,
  McBrowserRequestError,
} from '@/lib/mcbrowser';
import {
  DEFAULT_MCBROWSER_AUDIT_LIST_LIMIT,
  DEFAULT_MCBROWSER_QUEUE_LIST_LIMIT,
  MAX_MCBROWSER_AUDIT_LIST_LIMIT,
  MAX_MCBROWSER_QUEUE_LIST_LIMIT,
  MCBROWSER_AUDIT_EVENT_STATUSES,
  MCBROWSER_EVENT_QUEUE_STATUSES,
  MCBROWSER_EVENT_TRIGGERS,
  acknowledgeMcBrowserEventQueueTask,
  fetchMcBrowserAuditEvents,
  fetchMcBrowserEventQueue,
  fetchMcBrowserEventSettings,
  normalizeMcBrowserAuditUserId,
  normalizeMcBrowserBoundedLimit,
  saveMcBrowserEventSettings,
  type McBrowserAuditEventStatus,
  type McBrowserAuditRecord,
  type McBrowserEventQueueStatus,
  type McBrowserEventSettingsDocument,
  type McBrowserEventTrigger,
  type McBrowserQueuedEventTask,
} from '@/lib/mcbrowser-events';

export interface McBrowserEventsAdminProps {
  initialTab?: 'audit' | 'queue';
  initialLimit?: number;
  onClose?: () => void;
  onSettingsChange?: (settings: McBrowserEventSettingsDocument) => void;
  onTaskAcknowledged?: (task: McBrowserQueuedEventTask) => void;
  className?: string;
}

const TRIGGER_LABELS: Record<McBrowserEventTrigger, string> = {
  upload_completed: 'Upload Completed',
  entry_deleted: 'Entry Deleted',
  file_saved: 'File Saved',
  entry_copied: 'Entry Copied',
  entry_renamed: 'Entry Renamed',
  share_created: 'Share Created',
  share_revoked: 'Share Revoked',
};

function formatByteDelta(delta: number): string {
  if (!Number.isFinite(delta) || delta === 0) {
    return '0 B';
  }
  const sign = delta > 0 ? '+' : '-';
  return `${sign}${formatBytes(Math.abs(delta))}`;
}

export function McBrowserEventsAdmin({
  initialTab = 'audit',
  initialLimit = DEFAULT_MCBROWSER_AUDIT_LIST_LIMIT,
  onClose,
  onSettingsChange,
  onTaskAcknowledged,
  className = '',
}: McBrowserEventsAdminProps) {
  const baseId = useId();
  const [activeTab, setActiveTab] = useState<'audit' | 'queue'>(initialTab);

  const [settings, setSettings] = useState<McBrowserEventSettingsDocument>({
    enabled: true,
    queue_enabled: true,
  });
  const [savingSettings, setSavingSettings] = useState<boolean>(false);

  const [auditEvents, setAuditEvents] = useState<McBrowserAuditRecord[]>([]);
  const [auditTruncated, setAuditTruncated] = useState<boolean>(false);
  const [auditStatusFilter, setAuditStatusFilter] = useState<string>('');
  const [auditTriggerFilter, setAuditTriggerFilter] = useState<string>('');
  const [auditUserIdInput, setAuditUserIdInput] = useState<string>('');
  const [auditLimitInput, setAuditLimitInput] = useState<string>(String(initialLimit));

  const [queueTasks, setQueueTasks] = useState<McBrowserQueuedEventTask[]>([]);
  const [queueTruncated, setQueueTruncated] = useState<boolean>(false);
  const [queueStatusFilter, setQueueStatusFilter] = useState<string>('');
  const [queueLimitInput, setQueueLimitInput] = useState<string>(
    String(DEFAULT_MCBROWSER_QUEUE_LIST_LIMIT),
  );
  const [acknowledgingIds, setAcknowledgingIds] = useState<Record<string, boolean>>({});

  const [loading, setLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [statusBanner, setStatusBanner] = useState<string | null>(null);
  const [sessionExpired, setSessionExpired] = useState<boolean>(false);

  const loadAbortRef = useRef<AbortController | null>(null);

  const loadAll = useCallback(
    async (
      auditQueryOverrides?: {
        limit?: number;
        status?: string;
        trigger?: string;
        user_id?: number | string | null;
      },
      queueQueryOverrides?: {
        limit?: number;
        status?: string;
      },
    ) => {
      if (loadAbortRef.current) {
        loadAbortRef.current.abort();
      }
      const controller = new AbortController();
      loadAbortRef.current = controller;

      setLoading(true);
      setErrorMessage(null);

      try {
        const parsedAuditLimit =
          auditQueryOverrides?.limit !== undefined
            ? auditQueryOverrides.limit
            : normalizeMcBrowserBoundedLimit(
                Number(auditLimitInput),
                DEFAULT_MCBROWSER_AUDIT_LIST_LIMIT,
                MAX_MCBROWSER_AUDIT_LIST_LIMIT,
              );

        const rawUserId =
          auditQueryOverrides?.user_id !== undefined
            ? auditQueryOverrides.user_id
            : auditUserIdInput.trim();
        const parsedUserId =
          rawUserId !== null && rawUserId !== undefined && String(rawUserId).trim() !== ''
            ? normalizeMcBrowserAuditUserId(rawUserId)
            : undefined;

        const parsedQueueLimit =
          queueQueryOverrides?.limit !== undefined
            ? queueQueryOverrides.limit
            : normalizeMcBrowserBoundedLimit(
                Number(queueLimitInput),
                DEFAULT_MCBROWSER_QUEUE_LIST_LIMIT,
                MAX_MCBROWSER_QUEUE_LIST_LIMIT,
              );

        const [auditRes, settingsRes, queueRes] = await Promise.all([
          fetchMcBrowserAuditEvents(
            {
              limit: parsedAuditLimit,
              status:
                (auditQueryOverrides?.status ?? auditStatusFilter) as
                  | McBrowserAuditEventStatus
                  | string,
              trigger:
                (auditQueryOverrides?.trigger ?? auditTriggerFilter) as
                  | McBrowserEventTrigger
                  | string,
              user_id: parsedUserId,
            },
            controller.signal,
          ),
          fetchMcBrowserEventSettings(controller.signal),
          fetchMcBrowserEventQueue(
            {
              limit: parsedQueueLimit,
              status:
                (queueQueryOverrides?.status ?? queueStatusFilter) as
                  | McBrowserEventQueueStatus
                  | string,
            },
            controller.signal,
          ),
        ]);

        setAuditEvents(auditRes.events);
        setAuditTruncated(auditRes.truncated);
        setSettings(settingsRes);
        setQueueTasks(queueRes.tasks);
        setQueueTruncated(queueRes.truncated);
      } catch (err) {
        if ((err as Error)?.name === 'AbortError') {
          return;
        }
        if (err instanceof McBrowserRequestError && err.status === 401) {
          setSessionExpired(true);
        }
        setErrorMessage(
          extractMcBrowserError(err, 'Failed to load McBrowser audit events and queue'),
        );
      } finally {
        if (loadAbortRef.current === controller) {
          loadAbortRef.current = null;
          setLoading(false);
        }
      }
    },
    [
      auditLimitInput,
      auditStatusFilter,
      auditTriggerFilter,
      auditUserIdInput,
      queueLimitInput,
      queueStatusFilter,
    ],
  );

  useEffect(() => {
    void loadAll();
    return () => {
      if (loadAbortRef.current) {
        loadAbortRef.current.abort();
      }
    };
  }, []);

  useEffect(() => {
    const handleSessionExpired = () => {
      setSessionExpired(true);
      if (loadAbortRef.current) {
        loadAbortRef.current.abort();
        loadAbortRef.current = null;
      }
      setLoading(false);
      setSavingSettings(false);
      setErrorMessage(
        'Your admin session has expired. Please sign in again to manage McBrowser events.',
      );
    };

    window.addEventListener('af:session-expired', handleSessionExpired);
    return () => {
      window.removeEventListener('af:session-expired', handleSessionExpired);
    };
  }, []);

  const handleToggleQueueSettings = useCallback(async () => {
    if (savingSettings || sessionExpired) {
      return;
    }
    setSavingSettings(true);
    setErrorMessage(null);
    setStatusBanner(null);

    const nextEnabled = !settings.queue_enabled;
    try {
      const updated = await saveMcBrowserEventSettings({
        enabled: nextEnabled,
        queue_enabled: nextEnabled,
      });
      setSettings(updated);
      setStatusBanner(
        updated.queue_enabled
          ? 'Internal event task queue enabled.'
          : 'Internal event task queue disabled.',
      );
      onSettingsChange?.(updated);
    } catch (err) {
      if (err instanceof McBrowserRequestError && err.status === 401) {
        setSessionExpired(true);
      }
      setErrorMessage(
        extractMcBrowserError(err, 'Failed to update event queue settings'),
      );
    } finally {
      setSavingSettings(false);
    }
  }, [onSettingsChange, savingSettings, sessionExpired, settings.queue_enabled]);

  const handleApplyAuditFilters = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (sessionExpired) {
        return;
      }
      setStatusBanner(null);
      await loadAll();
    },
    [loadAll, sessionExpired],
  );

  const handleResetAuditFilters = useCallback(async () => {
    if (sessionExpired) {
      return;
    }
    const defaultLimitStr = String(DEFAULT_MCBROWSER_AUDIT_LIST_LIMIT);
    setAuditStatusFilter('');
    setAuditTriggerFilter('');
    setAuditUserIdInput('');
    setAuditLimitInput(defaultLimitStr);
    setStatusBanner(null);
    await loadAll({
      limit: DEFAULT_MCBROWSER_AUDIT_LIST_LIMIT,
      status: '',
      trigger: '',
      user_id: null,
    });
  }, [loadAll, sessionExpired]);

  const handleApplyQueueFilters = useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (sessionExpired) {
        return;
      }
      setStatusBanner(null);
      await loadAll();
    },
    [loadAll, sessionExpired],
  );

  const handleAcknowledgeTask = useCallback(
    async (eventId: string) => {
      if (sessionExpired || acknowledgingIds[eventId]) {
        return;
      }
      setAcknowledgingIds((prev) => ({ ...prev, [eventId]: true }));
      setErrorMessage(null);
      setStatusBanner(null);

      try {
        const res = await acknowledgeMcBrowserEventQueueTask(eventId);
        setQueueTasks((prev) =>
          prev.map((item) => (item.event_id === res.task.event_id ? res.task : item)),
        );
        setAuditEvents((prev) =>
          prev.map((record) =>
            record.event_id === res.task.event_id
              ? {
                  ...record,
                  status: 'completed',
                  updated_at: res.task.acknowledged_at ?? record.updated_at,
                }
              : record,
          ),
        );
        setStatusBanner(`Acknowledged queued event ${res.task.event_id}.`);
        onTaskAcknowledged?.(res.task);
      } catch (err) {
        if (err instanceof McBrowserRequestError && err.status === 401) {
          setSessionExpired(true);
        }
        setErrorMessage(
          extractMcBrowserError(err, 'Failed to acknowledge queued event task'),
        );
      } finally {
        setAcknowledgingIds((prev) => {
          const next = { ...prev };
          delete next[eventId];
          return next;
        });
      }
    },
    [acknowledgingIds, onTaskAcknowledged, sessionExpired],
  );

  return (
    <section
      aria-label="McBrowser Events & Audit Administration"
      data-testid="mcbrowser-events-admin"
      className={`obs-canvas-section py-4 text-slate-100 ${className}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] pb-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/15 text-indigo-400">
            <Activity className="h-4 w-4" aria-hidden="true" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              McBrowser Event Audit &amp; Task Queue
            </h2>
            <p className="text-xs text-slate-400">
              Inspect structured file lifecycle events, manage queue dispatch settings, and
              acknowledge queued tasks.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void loadAll()}
            disabled={loading || sessionExpired}
            data-testid="mcbrowser-events-refresh"
            className="obs-touch-target-standard inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-[var(--obs-slate-800)] px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-white/10 disabled:opacity-50"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`}
              aria-hidden="true"
            />
            Refresh
          </button>
          {onClose && (
            <button
              type="button"
              onClick={onClose}
              aria-label="Close events administration panel"
              className="obs-touch-target-standard rounded-lg border border-white/10 bg-[var(--obs-slate-800)] p-1.5 text-slate-300 hover:bg-white/10 hover:text-white"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      <div
        data-testid="mcbrowser-events-settings-card"
        className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] py-3"
      >
        <div className="flex items-start gap-2.5">
          <Settings className="mt-0.5 h-4 w-4 text-indigo-400" aria-hidden="true" />
          <div>
            <p className="text-xs font-semibold text-slate-100">
              Internal Event Task Queue Dispatch
            </p>
            <p className="text-xs text-slate-400">
              When enabled, mutations enqueue structured internal tasks in{' '}
              <code className="font-mono text-slate-300">pending</code> status until
              acknowledged. Audit logging remains active regardless of queue state.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <span
            data-testid="mcbrowser-events-queue-state"
            className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
              settings.queue_enabled
                ? 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                : 'border border-white/10 bg-[var(--obs-slate-800)] text-slate-300'
            }`}
          >
            {settings.queue_enabled ? 'Queue Enabled' : 'Queue Disabled'}
          </span>

          <button
            type="button"
            role="switch"
            aria-checked={settings.queue_enabled}
            aria-label="Toggle internal event task queue"
            data-testid="mcbrowser-events-queue-toggle"
            disabled={savingSettings || loading || sessionExpired}
            onClick={() => void handleToggleQueueSettings()}
            className={`rounded-lg border px-3 py-1.5 text-xs font-semibold transition disabled:opacity-50 ${
              settings.queue_enabled
                ? 'border-amber-500/40 bg-amber-500/15 text-amber-200 hover:bg-amber-500/25'
                : 'border-emerald-500/40 bg-emerald-500/15 text-emerald-200 hover:bg-emerald-500/25'
            }`}
          >
            {savingSettings
              ? 'Saving...'
              : settings.queue_enabled
                ? 'Disable Queue'
                : 'Enable Queue'}
          </button>
        </div>
      </div>

      {errorMessage && (
        <div
          role="alert"
          data-testid="mcbrowser-events-error"
          className="mt-3 flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-950/40 p-3 text-xs text-rose-200"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" aria-hidden="true" />
          <span>{errorMessage}</span>
        </div>
      )}

      {statusBanner && (
        <div
          role="status"
          data-testid="mcbrowser-events-status-banner"
          className="mt-3 flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-950/30 p-2.5 text-xs text-emerald-200"
        >
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" aria-hidden="true" />
          <span>{statusBanner}</span>
        </div>
      )}

      <div
        role="tablist"
        aria-label="Event administration views"
        className="mt-4 flex gap-2 border-b border-white/[0.07] pb-2"
      >
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'audit'}
          data-testid="mcbrowser-events-tab-audit"
          onClick={() => setActiveTab('audit')}
          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold ${
            activeTab === 'audit'
              ? 'bg-indigo-600 text-white'
              : 'bg-[var(--obs-slate-800)]/70 text-slate-300 hover:bg-[var(--obs-slate-800)]'
          }`}
        >
          <Activity className="h-3.5 w-3.5" aria-hidden="true" />
          Audit Log ({auditEvents.length})
        </button>

        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'queue'}
          data-testid="mcbrowser-events-tab-queue"
          onClick={() => setActiveTab('queue')}
          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold ${
            activeTab === 'queue'
              ? 'bg-indigo-600 text-white'
              : 'bg-[var(--obs-slate-800)]/70 text-slate-300 hover:bg-[var(--obs-slate-800)]'
          }`}
        >
          <ListChecks className="h-3.5 w-3.5" aria-hidden="true" />
          Internal Task Queue ({queueTasks.length})
        </button>
      </div>

      {activeTab === 'audit' && (
        <div className="mt-4 space-y-3" data-testid="mcbrowser-events-audit-panel">
          <form
            onSubmit={handleApplyAuditFilters}
            className="grid grid-cols-1 gap-3 border-b border-white/[0.07] pb-3 sm:grid-cols-5"
            noValidate
          >
            <div>
              <label
                htmlFor={`${baseId}-audit-status`}
                className="obs-touch-target-standard block text-xs font-medium text-slate-400"
              >
                Audit Status
              </label>
              <select
                id={`${baseId}-audit-status`}
                value={auditStatusFilter}
                onChange={(e) => setAuditStatusFilter(e.target.value)}
                disabled={loading || sessionExpired}
                className="obs-touch-target-standard mt-1 w-full rounded border border-white/10 bg-[var(--obs-bg-primary)] px-2.5 py-1.5 text-xs text-slate-100"
              >
                <option value="">All Statuses</option>
                {MCBROWSER_AUDIT_EVENT_STATUSES.map((status) => (
                  <option key={status} value={status}>
                    {status}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor={`${baseId}-audit-trigger`}
                className="obs-touch-target-standard block text-xs font-medium text-slate-400"
              >
                Event Trigger
              </label>
              <select
                id={`${baseId}-audit-trigger`}
                value={auditTriggerFilter}
                onChange={(e) => setAuditTriggerFilter(e.target.value)}
                disabled={loading || sessionExpired}
                className="obs-touch-target-standard mt-1 w-full rounded border border-white/10 bg-[var(--obs-bg-primary)] px-2.5 py-1.5 text-xs text-slate-100"
              >
                <option value="">All Triggers</option>
                {MCBROWSER_EVENT_TRIGGERS.map((trigger) => (
                  <option key={trigger} value={trigger}>
                    {TRIGGER_LABELS[trigger]} ({trigger})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor={`${baseId}-audit-user-id`}
                className="obs-touch-target-standard block text-xs font-medium text-slate-400"
              >
                User ID
              </label>
              <input
                id={`${baseId}-audit-user-id`}
                type="text"
                inputMode="numeric"
                value={auditUserIdInput}
                onChange={(e) => setAuditUserIdInput(e.target.value)}
                placeholder="Any user ID"
                disabled={loading || sessionExpired}
                className="obs-touch-target-standard mt-1 w-full rounded border border-white/10 bg-[var(--obs-bg-primary)] px-2.5 py-1.5 text-xs text-slate-100 placeholder:text-slate-500"
              />
            </div>

            <div>
              <label
                htmlFor={`${baseId}-audit-limit`}
                className="obs-touch-target-standard block text-xs font-medium text-slate-400"
              >
                Bounded Limit (1–{MAX_MCBROWSER_AUDIT_LIST_LIMIT})
              </label>
              <input
                id={`${baseId}-audit-limit`}
                type="number"
                min={1}
                max={MAX_MCBROWSER_AUDIT_LIST_LIMIT}
                value={auditLimitInput}
                onChange={(e) => setAuditLimitInput(e.target.value)}
                disabled={loading || sessionExpired}
                className="obs-touch-target-standard mt-1 w-full rounded border border-white/10 bg-[var(--obs-bg-primary)] px-2.5 py-1.5 text-xs text-slate-100"
              />
            </div>

            <div className="flex items-end gap-2">
              <button
                type="submit"
                disabled={loading || sessionExpired}
                data-testid="mcbrowser-audit-apply-filters"
                className="obs-touch-target-standard inline-flex items-center gap-1 rounded bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500 disabled:opacity-50"
              >
                <Filter className="h-3.5 w-3.5" aria-hidden="true" />
                Apply Filters
              </button>
              <button
                type="button"
                onClick={() => void handleResetAuditFilters()}
                disabled={loading || sessionExpired}
                data-testid="mcbrowser-audit-reset-filters"
                className="obs-touch-target-standard rounded border border-white/10 bg-[var(--obs-slate-800)] px-2.5 py-1.5 text-xs text-slate-300 hover:bg-white/10 disabled:opacity-50"
              >
                Reset
              </button>
            </div>
          </form>

          {auditTruncated && (
            <p
              data-testid="mcbrowser-audit-truncated"
              className="text-xs text-amber-300"
            >
              Results truncated to the bounded limit. Narrow your filters or adjust the limit
              (up to {MAX_MCBROWSER_AUDIT_LIST_LIMIT}).
            </p>
          )}

          {loading ? (
            <div className="flex items-center justify-center py-8 text-xs text-slate-400">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
              Loading audit records...
            </div>
          ) : auditEvents.length === 0 ? (
            <div
              data-testid="mcbrowser-audit-empty"
              className="py-8 text-center text-xs text-slate-400"
            >
              No audit events match the active filters.
            </div>
          ) : (
            <div className="overflow-x-auto min-w-0">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="border-b border-white/[0.07] text-xs uppercase text-slate-400">
                  <tr>
                    <th className="px-3 py-2">Timestamp</th>
                    <th className="px-3 py-2">Trigger</th>
                    <th className="px-3 py-2">Actor</th>
                    <th className="px-3 py-2">Relative Path</th>
                    <th className="px-3 py-2">Byte Delta</th>
                    <th className="px-3 py-2">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.05]">
                  {auditEvents.map((ev) => (
                    <tr
                      key={ev.event_id}
                      data-testid={`mcbrowser-audit-row-${ev.event_id}`}
                    >
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-300">
                        {ev.timestamp}
                      </td>
                      <td className="px-3 py-2 font-medium text-slate-200">
                        {TRIGGER_LABELS[ev.trigger] ?? ev.trigger}
                      </td>
                      <td className="px-3 py-2 text-slate-300">
                        {ev.username} <span className="text-slate-500">(#{ev.user_id})</span>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-slate-200">
                        <div>{ev.relative_path}</div>
                        {ev.destination_path && (
                          <div className="text-slate-400">→ {ev.destination_path}</div>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-300">
                        {formatByteDelta(ev.byte_delta)}
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${
                            ev.status === 'completed'
                              ? 'bg-emerald-500/15 text-emerald-300'
                              : ev.status === 'failed'
                                ? 'bg-rose-500/15 text-rose-300'
                                : 'bg-amber-500/15 text-amber-300'
                          }`}
                        >
                          {ev.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'queue' && (
        <div className="mt-4 space-y-3" data-testid="mcbrowser-events-queue-panel">
          <form
            onSubmit={handleApplyQueueFilters}
            className="grid grid-cols-1 gap-3 border-b border-white/[0.07] pb-3 sm:grid-cols-3"
            noValidate
          >
            <div>
              <label
                htmlFor={`${baseId}-queue-status`}
                className="obs-touch-target-standard block text-xs font-medium text-slate-400"
              >
                Queue Task Status
              </label>
              <select
                id={`${baseId}-queue-status`}
                value={queueStatusFilter}
                onChange={(e) => setQueueStatusFilter(e.target.value)}
                disabled={loading || sessionExpired}
                className="obs-touch-target-standard mt-1 w-full rounded border border-white/10 bg-[var(--obs-bg-primary)] px-2.5 py-1.5 text-xs text-slate-100"
              >
                <option value="">All Queue Statuses</option>
                {MCBROWSER_EVENT_QUEUE_STATUSES.map((st) => (
                  <option key={st} value={st}>
                    {st}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label
                htmlFor={`${baseId}-queue-limit`}
                className="obs-touch-target-standard block text-xs font-medium text-slate-400"
              >
                Queue Limit (1–{MAX_MCBROWSER_QUEUE_LIST_LIMIT})
              </label>
              <input
                id={`${baseId}-queue-limit`}
                type="number"
                min={1}
                max={MAX_MCBROWSER_QUEUE_LIST_LIMIT}
                value={queueLimitInput}
                onChange={(e) => setQueueLimitInput(e.target.value)}
                disabled={loading || sessionExpired}
                className="obs-touch-target-standard mt-1 w-full rounded border border-white/10 bg-[var(--obs-bg-primary)] px-2.5 py-1.5 text-xs text-slate-100"
              />
            </div>

            <div className="flex items-end">
              <button
                type="submit"
                disabled={loading || sessionExpired}
                data-testid="mcbrowser-queue-apply-filters"
                className="obs-touch-target-standard inline-flex items-center gap-1 rounded bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-indigo-500 disabled:opacity-50"
              >
                <Filter className="h-3.5 w-3.5" aria-hidden="true" />
                Apply Queue Filters
              </button>
            </div>
          </form>

          {queueTruncated && (
            <p
              data-testid="mcbrowser-queue-truncated"
              className="text-xs text-amber-300"
            >
              Queue tasks truncated to the bounded limit (up to{' '}
              {MAX_MCBROWSER_QUEUE_LIST_LIMIT}).
            </p>
          )}

          {loading ? (
            <div className="flex items-center justify-center py-8 text-xs text-slate-400">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
              Loading queued tasks...
            </div>
          ) : queueTasks.length === 0 ? (
            <div
              data-testid="mcbrowser-queue-empty"
              className="py-8 text-center text-xs text-slate-400"
            >
              No queued event tasks match the active filters.
            </div>
          ) : (
            <div className="overflow-x-auto min-w-0">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="border-b border-white/[0.07] text-xs uppercase text-slate-400">
                  <tr>
                    <th className="px-3 py-2">Queue ID</th>
                    <th className="px-3 py-2">Event ID</th>
                    <th className="px-3 py-2">Trigger &amp; Path</th>
                    <th className="px-3 py-2">Enqueued At</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.05]">
                  {queueTasks.map((task) => {
                    const isAcked = task.status === 'acknowledged';
                    const isAcking = Boolean(acknowledgingIds[task.event_id]);
                    return (
                      <tr
                        key={task.event_id}
                        data-testid={`mcbrowser-queue-row-${task.event_id}`}
                      >
                        <td className="px-3 py-2 font-mono text-slate-300">
                          #{task.queue_id}
                        </td>
                        <td className="px-3 py-2 font-mono text-xs text-slate-300">
                          {task.event_id}
                        </td>
                        <td className="px-3 py-2">
                          <div className="font-medium text-slate-200">
                            {TRIGGER_LABELS[task.event.trigger] ?? task.event.trigger}
                          </div>
                          <div className="font-mono text-xs text-slate-400">
                            {task.event.relative_path}
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-300">
                          {task.enqueued_at}
                        </td>
                        <td className="px-3 py-2">
                          <span
                            className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${
                              isAcked
                                ? 'bg-emerald-500/15 text-emerald-300'
                                : 'bg-amber-500/15 text-amber-300'
                            }`}
                          >
                            {isAcked ? (
                              <CheckCircle2 className="h-3 w-3" aria-hidden="true" />
                            ) : (
                              <Clock className="h-3 w-3" aria-hidden="true" />
                            )}
                            {task.status}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-right">
                          <button
                            type="button"
                            data-testid={`mcbrowser-queue-ack-${task.event_id}`}
                            disabled={isAcked || isAcking || sessionExpired}
                            onClick={() => void handleAcknowledgeTask(task.event_id)}
                            className="obs-touch-target-standard rounded border border-indigo-500/40 bg-indigo-500/15 px-2.5 py-1 text-xs font-medium text-indigo-200 hover:bg-indigo-500/25 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {isAcking
                              ? 'Acknowledging...'
                              : isAcked
                                ? 'Acknowledged'
                                : 'Acknowledge'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

export default McBrowserEventsAdmin;
