'use client';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ShieldCheck, Lock, Upload, RefreshCw, Sliders, Users, GitCompare, AlertTriangle, AlertCircle, CheckCircle2, Loader2, Trash2, Plus } from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/ToastContext';
import type { StreamingHistoryCounts } from '@/lib/streaming-history';

export const STREAMING_ADMIN_IMPORT_STATUS_URL = '/api/v1/admin/streaming/imports/status';
export const STREAMING_ADMIN_IMPORT_EVENTS_URL = '/api/v1/admin/streaming/imports/events';
export const STREAMING_ADMIN_IMPORT_PROBE_URL = '/api/v1/admin/streaming/imports/upstream-probe';
export const STREAMING_ADMIN_POLICIES_URL = '/api/v1/admin/streaming/policies';
export const STREAMING_ADMIN_USER_LINKS_URL = '/api/v1/admin/streaming/user-links';
export const STREAMING_ADMIN_RECONCILIATION_PREVIEW_URL = '/api/v1/admin/streaming/reconciliation/preview';
export const STREAMING_ADMIN_RECONCILIATION_APPLY_URL = '/api/v1/admin/streaming/reconciliation/apply';

export const MAX_IMPORT_BATCH_BYTES = 1024 * 1024;
export const MAX_IMPORT_BATCH_EVENTS = 500;
export const MAX_POLICY_TARGETS = 500;
export const MAX_RECONCILIATION_LIMIT = 1000;

export type StreamingAdminSection = 'imports' | 'policies' | 'links' | 'reconciliation';
export interface ImportCheckpointRecord { provider: string; serverId: string; source: string; checkpoint: string; imported: number; lastError: string | null; updatedAt: string; }
export interface UpstreamEventCapability { provider: string; serverId: string; realEventImportSupported: boolean; jsonBatchImportSupported: boolean; upstreamDirectFetchAvailable: boolean; upstreamEndpointClassification: string; reason: string; }
export interface ImportStatusResponse { maxBatchEvents: number; checkpoints: ImportCheckpointRecord[]; capabilities: UpstreamEventCapability[]; }
export interface ImportLabelInput { id: string; name?: string; }
export interface ImportedEventInput {
    sourceEventId: string; userId: string; userName?: string; itemId: string; itemName: string; itemType?: string;
    seriesName?: string; seriesId?: string; seasonNumber?: number; episodeNumber?: number; productionYear?: number;
    startedAt: string; endedAt?: string; watchedSecs?: number; durationSecs?: number; playMethod?: string;
    clientName?: string; deviceName?: string; deviceId?: string; ipAddress?: string; container?: string;
    videoCodec?: string; videoResolution?: string; audioCodec?: string; audioChannels?: number;
    subtitleCodec?: string; hwAccel?: string; bitrateBps?: number; estimatedBytes?: number;
    libraries?: ImportLabelInput[]; genres?: string[];
}
export interface ImportEventsBatchRequest { provider: string; serverId: string; serverName?: string; source: string; checkpoint: string; expectedCheckpoint?: string | null; events: ImportedEventInput[]; }
export interface ImportEventOutcome { sourceEventId: string; historyId: number; disposition: string; policyStatus: string; matchedObservedIds: number[]; }
export interface ImportEventsBatchResponse {
    provider: string; serverId: string; source: string; checkpoint: string; batchSize: number;
    insertedIncluded: number; deduplicatedRetries: number; confirmedOverlapDuplicates: number;
    ambiguousOverlaps: number; cumulativeImported: number; revision: number; outcomes: ImportEventOutcome[];
}
export interface PolicyScopeTarget { provider: string; serverId: string; id: string; name: string; }
export interface PolicyScopeSemantics { minimumWatchSecsEffect: string; excludedUsersEffect: string; excludedLibrariesEffect: string; reconnectWindowSecsEffect: string; rawEvidencePreserved: boolean; }
export interface TrackingPolicyResponse { minimumWatchSecs: number; reconnectWindowSecs: number; excludedUsers: PolicyScopeTarget[]; excludedLibraries: PolicyScopeTarget[]; policyRevision: number; historyRevision: number; semantics: PolicyScopeSemantics; }
export interface UpdateTrackingPolicyRequest { minimumWatchSecs: number; reconnectWindowSecs: number; excludedUsers: PolicyScopeTarget[]; excludedLibraries: PolicyScopeTarget[]; }
export interface StreamingUserLinkRecord { afUserId: number; afUsername: string | null; provider: string; serverId: string; providerUserId: string; }
export interface StreamingUserLinksResponse { links: StreamingUserLinkRecord[]; historyRevision: number; identitySemantics: string; }
export interface UpsertStreamingUserLinkRequest { afUserId: number; provider: string; serverId: string; providerUserId: string; }
export type DeleteStreamingUserLinkRequest = UpsertStreamingUserLinkRequest;
export interface ReconciliationPreviewRequest { candidateIds: number[]; limit: number; }
export interface ReconciliationRowState {
    id: number; sessionKey: string; provider: string; serverId: string; sourceEventId: string | null;
    userId: string; userName: string; itemId: string; itemName: string; itemType: string; playMethod: string;
    clientName: string; deviceName: string; deviceId: string; ipAddress: string; durationSecs: number;
    watchedSecs: number; dataUsedBytes: number; bitrateBps: number; startedAt: string; lastSeenAt: string;
    endedAt: string | null; provenance: string; timestampCertainty: string; byteAccuracy: string; policyStatus: string;
}
export interface ReconciliationFieldChange { field: string; before: string; after: string; reason: string; }
export interface ReconciliationRowChange { id: number; sessionKey: string; classification: string; rowFingerprint: string; before: ReconciliationRowState; after: ReconciliationRowState; changes: ReconciliationFieldChange[]; }
export interface ReconciliationPreviewResponse {
    previewHash: string; approvalToken: string; actorId: number; historyRevision: number; issuedAt: string;
    expiresAt: string; totalAffectedRows: number; countsBefore: StreamingHistoryCounts;
    countsAfter: StreamingHistoryCounts; affectedRows: ReconciliationRowChange[];
}
export interface ReconciliationApplyRequest { previewHash: string; approvalToken: string; }
export interface ReconciliationApplyResponse {
    auditId: number; previewHash: string; appliedRows: number; backupPath: string | null;
    historyRevision: number; countsBefore: StreamingHistoryCounts; countsAfter: StreamingHistoryCounts; createdAt: string;
}
export interface StreamingHistoryAdminProps { onChanged?: () => void; }

function isPlainRecord(v: unknown): v is Record<string, unknown> { return typeof v === 'object' && v !== null && !Array.isArray(v); }
function isSafeInt(v: unknown): v is number { return typeof v === 'number' && Number.isSafeInteger(v); }
function isAbortError(err: unknown): boolean { return isPlainRecord(err) && (err.name === 'AbortError' || err.code === 'ABORT_ERR'); }
export function utf8ByteLength(text: string): number { return typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(text).byteLength : text.length; }

async function readErrorMessage(res: Response, fallback: string): Promise<string> {
    try {
        const raw: unknown = await res.json();
        if (isPlainRecord(raw)) {
            if (isPlainRecord(raw.error) && typeof raw.error.message === 'string' && raw.error.message.trim()) return raw.error.message;
            if (typeof raw.message === 'string' && raw.message.trim()) return raw.message;
        }
    } catch { return fallback; }
    return fallback;
}

export function parsePolicyTargetsJson(rawText: string, fieldName: string): { ok: true; targets: PolicyScopeTarget[] } | { ok: false; error: string } {
    let parsed: unknown;
    try { parsed = JSON.parse(rawText); } catch { return { ok: false, error: `${fieldName} must be valid JSON.` }; }
    if (!Array.isArray(parsed)) return { ok: false, error: `${fieldName} must be a JSON array.` };
    if (parsed.length > MAX_POLICY_TARGETS) return { ok: false, error: `${fieldName} cannot exceed ${MAX_POLICY_TARGETS} entries.` };
    const targets: PolicyScopeTarget[] = [];
    for (let i = 0; i < parsed.length; i += 1) {
        const item: unknown = parsed[i];
        if (!isPlainRecord(item)) return { ok: false, error: `${fieldName}[${i}] must be a JSON object.` };
        for (const k of Object.keys(item)) {
            if (k !== 'provider' && k !== 'serverId' && k !== 'id' && k !== 'name') return { ok: false, error: `${fieldName}[${i}] contains unknown field "${k}".` };
        }
        const provider = typeof item.provider === 'string' ? item.provider.trim().toLowerCase() : '';
        const serverId = typeof item.serverId === 'string' ? item.serverId.trim() : '';
        const id = typeof item.id === 'string' ? item.id.trim() : '';
        const nameRaw = item.name === undefined ? '' : typeof item.name === 'string' ? item.name.trim() : null;
        if (provider !== 'jellyfin' && provider !== 'emby') return { ok: false, error: `${fieldName}[${i}].provider must be "jellyfin" or "emby".` };
        if (!serverId || serverId.length > 128) return { ok: false, error: `${fieldName}[${i}].serverId must be 1..128 characters.` };
        if (!id || id.length > 128) return { ok: false, error: `${fieldName}[${i}].id must be 1..128 characters.` };
        if (nameRaw === null || nameRaw.length > 256) return { ok: false, error: `${fieldName}[${i}].name must be a string up to 256 characters.` };
        targets.push({ provider, serverId, id, name: nameRaw || id });
    }
    return { ok: true, targets };
}

export function parseImportBatchPayload(
    rawText: string,
    fallback: { provider: string; serverId: string; serverName: string; source: string; checkpoint: string; expectedCheckpoint?: string | null }
): { ok: true; request: ImportEventsBatchRequest; byteLength: number } | { ok: false; error: string } {
    const byteLength = utf8ByteLength(rawText);
    if (byteLength === 0 || !rawText.trim()) return { ok: false, error: 'Event batch JSON is required.' };
    if (byteLength > MAX_IMPORT_BATCH_BYTES) return { ok: false, error: `Event batch (${byteLength.toLocaleString()} bytes) exceeds the ${MAX_IMPORT_BATCH_BYTES.toLocaleString()}-byte (1 MiB) limit.` };
    let parsed: unknown;
    try { parsed = JSON.parse(rawText); } catch { return { ok: false, error: 'Event batch payload is not valid JSON.' }; }
    let provider = fallback.provider.trim().toLowerCase();
    let serverId = fallback.serverId.trim();
    let serverName = fallback.serverName.trim();
    let source = fallback.source.trim();
    let checkpoint = fallback.checkpoint.trim();
    let hasExplicitExpected = false;
    let expectedCheckpoint: string | null | undefined = fallback.expectedCheckpoint !== undefined ? (typeof fallback.expectedCheckpoint === 'string' ? fallback.expectedCheckpoint.trim() || null : null) : undefined;
    let rawEvents: unknown;
    if (Array.isArray(parsed)) {
        rawEvents = parsed;
    } else if (isPlainRecord(parsed)) {
        if (typeof parsed.provider === 'string' && parsed.provider.trim()) provider = parsed.provider.trim().toLowerCase();
        if (typeof parsed.serverId === 'string' && parsed.serverId.trim()) serverId = parsed.serverId.trim();
        if (typeof parsed.serverName === 'string' && parsed.serverName.trim()) serverName = parsed.serverName.trim();
        if (typeof parsed.source === 'string' && parsed.source.trim()) source = parsed.source.trim();
        if (typeof parsed.checkpoint === 'string' && parsed.checkpoint.trim()) checkpoint = parsed.checkpoint.trim();
        if ('expectedCheckpoint' in parsed) {
            hasExplicitExpected = true;
            if (parsed.expectedCheckpoint === null) expectedCheckpoint = null;
            else if (typeof parsed.expectedCheckpoint === 'string') expectedCheckpoint = parsed.expectedCheckpoint.trim() || null;
            else if (parsed.expectedCheckpoint !== undefined) return { ok: false, error: 'expectedCheckpoint must be a string or null.' };
        }
        rawEvents = parsed.events;
    } else {
        return { ok: false, error: 'Event batch JSON must be an array of events or a batch object.' };
    }
    if (provider !== 'jellyfin' && provider !== 'emby') return { ok: false, error: 'provider must be "jellyfin" or "emby".' };
    if (!serverId || !source || !checkpoint) return { ok: false, error: 'serverId, source, and checkpoint are required.' };
    if (!Array.isArray(rawEvents)) return { ok: false, error: 'events must be a JSON array.' };
    if (rawEvents.length < 1 || rawEvents.length > MAX_IMPORT_BATCH_EVENTS) return { ok: false, error: `events batch must contain between 1 and ${MAX_IMPORT_BATCH_EVENTS} events (got ${rawEvents.length}).` };
    const events: ImportedEventInput[] = [];
    for (let i = 0; i < rawEvents.length; i += 1) {
        const entry: unknown = rawEvents[i];
        if (!isPlainRecord(entry)) return { ok: false, error: `events[${i}] must be a JSON object.` };
        const sourceEventId = typeof entry.sourceEventId === 'string' ? entry.sourceEventId.trim() : '';
        const userId = typeof entry.userId === 'string' ? entry.userId.trim() : '';
        const itemId = typeof entry.itemId === 'string' ? entry.itemId.trim() : '';
        const itemName = typeof entry.itemName === 'string' ? entry.itemName.trim() : '';
        const startedAt = typeof entry.startedAt === 'string' ? entry.startedAt.trim() : '';
        if (!sourceEventId || !userId || !itemId || !itemName || !startedAt) return { ok: false, error: `events[${i}] requires non-empty sourceEventId, userId, itemId, itemName, and startedAt.` };
        const ev: ImportedEventInput = { sourceEventId, userId, itemId, itemName, startedAt };
        if (typeof entry.userName === 'string') ev.userName = entry.userName;
        if (typeof entry.itemType === 'string') ev.itemType = entry.itemType;
        if (typeof entry.seriesName === 'string') ev.seriesName = entry.seriesName;
        if (typeof entry.seriesId === 'string') ev.seriesId = entry.seriesId;
        if (isSafeInt(entry.seasonNumber)) ev.seasonNumber = entry.seasonNumber;
        if (isSafeInt(entry.episodeNumber)) ev.episodeNumber = entry.episodeNumber;
        if (isSafeInt(entry.productionYear)) ev.productionYear = entry.productionYear;
        if (typeof entry.endedAt === 'string') ev.endedAt = entry.endedAt;
        if (isSafeInt(entry.watchedSecs)) ev.watchedSecs = entry.watchedSecs;
        if (isSafeInt(entry.durationSecs)) ev.durationSecs = entry.durationSecs;
        if (typeof entry.playMethod === 'string') ev.playMethod = entry.playMethod;
        if (typeof entry.clientName === 'string') ev.clientName = entry.clientName;
        if (typeof entry.deviceName === 'string') ev.deviceName = entry.deviceName;
        if (typeof entry.deviceId === 'string') ev.deviceId = entry.deviceId;
        if (typeof entry.ipAddress === 'string') ev.ipAddress = entry.ipAddress;
        if (typeof entry.container === 'string') ev.container = entry.container;
        if (typeof entry.videoCodec === 'string') ev.videoCodec = entry.videoCodec;
        if (typeof entry.videoResolution === 'string') ev.videoResolution = entry.videoResolution;
        if (typeof entry.audioCodec === 'string') ev.audioCodec = entry.audioCodec;
        if (isSafeInt(entry.audioChannels)) ev.audioChannels = entry.audioChannels;
        if (typeof entry.subtitleCodec === 'string') ev.subtitleCodec = entry.subtitleCodec;
        if (typeof entry.hwAccel === 'string') ev.hwAccel = entry.hwAccel;
        if (isSafeInt(entry.bitrateBps)) ev.bitrateBps = entry.bitrateBps;
        if (isSafeInt(entry.estimatedBytes)) ev.estimatedBytes = entry.estimatedBytes;
        if (Array.isArray(entry.libraries)) {
            const libs: ImportLabelInput[] = [];
            for (const lib of entry.libraries) {
                if (!isPlainRecord(lib) || typeof lib.id !== 'string' || !lib.id.trim()) return { ok: false, error: `events[${i}].libraries entries require string id.` };
                libs.push({ id: lib.id.trim(), ...(typeof lib.name === 'string' && lib.name.trim() ? { name: lib.name.trim() } : {}) });
            }
            ev.libraries = libs;
        }
        if (Array.isArray(entry.genres)) {
            if (!entry.genres.every((g): g is string => typeof g === 'string' && g.trim().length > 0)) return { ok: false, error: `events[${i}].genres must be non-empty strings.` };
            ev.genres = entry.genres.map((g) => g.trim());
        }
        events.push(ev);
    }
    const req: ImportEventsBatchRequest = {
        provider,
        serverId,
        ...(serverName ? { serverName } : {}),
        source,
        checkpoint,
        ...(hasExplicitExpected || expectedCheckpoint !== undefined ? { expectedCheckpoint } : {}),
        events,
    };
    return { ok: true, request: req, byteLength };
}

export function parseCandidateIdsInput(raw: string): { ok: true; ids: number[] } | { ok: false; error: string } {
    const trimmed = raw.trim();
    if (!trimmed) return { ok: true, ids: [] };
    const ids: number[] = [];
    for (const part of trimmed.split(',').map((p) => p.trim()).filter(Boolean)) {
        const n = Number(part);
        if (!/^\d+$/.test(part) || !Number.isSafeInteger(n) || n <= 0) return { ok: false, error: `Invalid candidate row ID "${part}". Use comma-separated positive integers.` };
        ids.push(n);
    }
    return { ok: true, ids };
}

export default function StreamingHistoryAdmin({ onChanged }: StreamingHistoryAdminProps = {}) {
    const { user, isAuthenticated, isLoading: authLoading } = useAuth();
    const { addToast } = useToast();
    const isAdmin = Boolean(isAuthenticated && user?.role === 'admin');

    const [activeSection, setActiveSection] = useState<StreamingAdminSection>('imports');
    const [statusData, setStatusData] = useState<ImportStatusResponse | null>(null);
    const [policyData, setPolicyData] = useState<TrackingPolicyResponse | null>(null);
    const [linksData, setLinksData] = useState<StreamingUserLinksResponse | null>(null);
    const [loadError, setLoadError] = useState<string | null>(null);
    const [isLoadingInitial, setIsLoadingInitial] = useState(false);

    const [importProvider, setImportProvider] = useState('jellyfin');
    const [importServerId, setImportServerId] = useState('default');
    const [importServerName] = useState('');
    const [importSource, setImportSource] = useState('playback_reporting_export');
    const [importCheckpoint, setImportCheckpoint] = useState('');
    const [importJsonText, setImportJsonText] = useState('');
    const [importError, setImportError] = useState<string | null>(null);
    const [isImporting, setIsImporting] = useState(false);
    const [importResult, setImportResult] = useState<ImportEventsBatchResponse | null>(null);

    const [minWatchInput, setMinWatchInput] = useState('0');
    const [reconnectInput, setReconnectInput] = useState('0');
    const [excludedUsersText, setExcludedUsersText] = useState('[]');
    const [excludedLibrariesText, setExcludedLibrariesText] = useState('[]');
    const [policyError, setPolicyError] = useState<string | null>(null);
    const [isSavingPolicy, setIsSavingPolicy] = useState(false);

    const [linkAfUserId, setLinkAfUserId] = useState('');
    const [linkProvider, setLinkProvider] = useState('jellyfin');
    const [linkServerId, setLinkServerId] = useState('default');
    const [linkProviderUserId, setLinkProviderUserId] = useState('');
    const [linkError, setLinkError] = useState<string | null>(null);
    const [isMutatingLink, setIsMutatingLink] = useState(false);

    const [candidateIdsInput, setCandidateIdsInput] = useState('');
    const [reconcileLimitInput, setReconcileLimitInput] = useState('500');
    const [reconcilePreview, setReconcilePreview] = useState<ReconciliationPreviewResponse | null>(null);
    const [reconcileApproved, setReconcileApproved] = useState(false);
    const [reconcileError, setReconcileError] = useState<string | null>(null);
    const [reconcileStaleConflict, setReconcileStaleConflict] = useState<string | null>(null);
    const [reconcileResult, setReconcileResult] = useState<ReconciliationApplyResponse | null>(null);
    const [isPreviewingReconcile, setIsPreviewingReconcile] = useState(false);
    const [isApplyingReconcile, setIsApplyingReconcile] = useState(false);

    const mountedRef = useRef(true);
    const loadGenRef = useRef(0);
    const importGenRef = useRef(0);
    const policyGenRef = useRef(0);
    const linkGenRef = useRef(0);
    const reconcileGenRef = useRef(0);
    const loadAbortRef = useRef<AbortController | null>(null);
    const importAbortRef = useRef<AbortController | null>(null);
    const policyAbortRef = useRef<AbortController | null>(null);
    const linkAbortRef = useRef<AbortController | null>(null);
    const reconcileAbortRef = useRef<AbortController | null>(null);
    const policyBaselineRef = useRef({ minimum: '0', reconnect: '0', users: '[]', libraries: '[]', revision: -1 });

    const acceptPolicy = useCallback((body: TrackingPolicyResponse, submitted?: Omit<typeof policyBaselineRef.current, 'revision'>) => {
        if (body.policyRevision < policyBaselineRef.current.revision) return;
        const previous = submitted ?? policyBaselineRef.current;
        const baseline = { minimum: String(body.minimumWatchSecs), reconnect: String(body.reconnectWindowSecs), users: JSON.stringify(body.excludedUsers, null, 2), libraries: JSON.stringify(body.excludedLibraries, null, 2), revision: body.policyRevision };
        setPolicyData(body);
        setMinWatchInput((current) => current === previous.minimum ? baseline.minimum : current);
        setReconnectInput((current) => current === previous.reconnect ? baseline.reconnect : current);
        setExcludedUsersText((current) => current === previous.users ? baseline.users : current);
        setExcludedLibrariesText((current) => current === previous.libraries ? baseline.libraries : current);
        policyBaselineRef.current = baseline;
    }, []);

    const invalidateReconcileApproval = useCallback(() => {
        reconcileGenRef.current += 1;
        reconcileAbortRef.current?.abort();
        reconcileAbortRef.current = null;
        setIsPreviewingReconcile(false);
        setIsApplyingReconcile(false);
        setReconcilePreview(null);
        setReconcileApproved(false);
    }, []);

    const loadAdminState = useCallback(async () => {
        if (!isAdmin) return;
        loadAbortRef.current?.abort();
        const controller = new AbortController();
        loadAbortRef.current = controller;
        const gen = ++loadGenRef.current;
        setIsLoadingInitial(true);
        setLoadError(null);
        try {
            const [statusRes, policyRes, linksRes] = await Promise.all([
                apiFetch(STREAMING_ADMIN_IMPORT_STATUS_URL, { method: 'GET', signal: controller.signal }),
                apiFetch(STREAMING_ADMIN_POLICIES_URL, { method: 'GET', signal: controller.signal }),
                apiFetch(STREAMING_ADMIN_USER_LINKS_URL, { method: 'GET', signal: controller.signal }),
            ]);
            if (!mountedRef.current || controller.signal.aborted || gen !== loadGenRef.current) return;
            if (!statusRes.ok || !policyRes.ok || !linksRes.ok) {
                const failed = !statusRes.ok ? statusRes : !policyRes.ok ? policyRes : linksRes;
                const msg = await readErrorMessage(failed, `Failed to load streaming admin state (HTTP ${failed.status}).`);
                if (mountedRef.current && gen === loadGenRef.current) setLoadError(msg);
                return;
            }
            const [statusBody, policyBody, linksBody] = (await Promise.all([statusRes.json(), policyRes.json(), linksRes.json()])) as [ImportStatusResponse, TrackingPolicyResponse, StreamingUserLinksResponse];
            if (!mountedRef.current || controller.signal.aborted || gen !== loadGenRef.current) return;
            setStatusData(statusBody);
            acceptPolicy(policyBody);
            setLinksData(linksBody);
        } catch (err: unknown) {
            if (!mountedRef.current || controller.signal.aborted || isAbortError(err) || gen !== loadGenRef.current) return;
            setLoadError(err instanceof Error ? err.message : 'Failed to load streaming admin state.');
        } finally {
            if (mountedRef.current && gen === loadGenRef.current) setIsLoadingInitial(false);
        }
    }, [isAdmin, acceptPolicy]);

    useEffect(() => {
        mountedRef.current = true;
        if (isAdmin) void loadAdminState();
        return () => {
            mountedRef.current = false;
            loadGenRef.current += 1;
            importGenRef.current += 1;
            policyGenRef.current += 1;
            linkGenRef.current += 1;
            reconcileGenRef.current += 1;
            loadAbortRef.current?.abort();
            importAbortRef.current?.abort();
            policyAbortRef.current?.abort();
            linkAbortRef.current?.abort();
            reconcileAbortRef.current?.abort();
        };
    }, [isAdmin, loadAdminState]);

    const handleSectionChange = (section: StreamingAdminSection) => {
        if (section === activeSection) return;
        setActiveSection(section);
        invalidateReconcileApproval();
        setReconcileError(null);
        setReconcileStaleConflict(null);
    };

    const handleImportFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        setImportError(null);
        setImportResult(null);
        if (!file) return;
        if (file.size > MAX_IMPORT_BATCH_BYTES) {
            const msg = `Selected file (${file.size.toLocaleString()} bytes) exceeds the ${MAX_IMPORT_BATCH_BYTES.toLocaleString()}-byte (1 MiB) limit.`;
            setImportError(msg);
            addToast(msg, 'error');
            return;
        }
        try {
            const text = typeof file.text === 'function' ? await file.text() : '';
            if (!mountedRef.current) return;
            if (utf8ByteLength(text) > MAX_IMPORT_BATCH_BYTES) {
                const msg = `Selected file content exceeds the ${MAX_IMPORT_BATCH_BYTES.toLocaleString()}-byte (1 MiB) limit.`;
                setImportError(msg);
                addToast(msg, 'error');
                return;
            }
            setImportJsonText(text);
        } catch {
            if (mountedRef.current) setImportError('Failed to read selected JSON file.');
        }
    };

    const handleSubmitImportBatch = async () => {
        if (!isAdmin || isImporting) return;
        setImportError(null);
        setImportResult(null);
        const matchingCp = statusData?.checkpoints.find(
            (cp) => cp.provider === importProvider.trim().toLowerCase() && cp.serverId === importServerId.trim() && cp.source === importSource.trim()
        )?.checkpoint;
        const parsed = parseImportBatchPayload(importJsonText, {
            provider: importProvider,
            serverId: importServerId,
            serverName: importServerName,
            source: importSource,
            checkpoint: importCheckpoint,
            ...(matchingCp !== undefined ? { expectedCheckpoint: matchingCp } : {}),
        });
        if (!parsed.ok) {
            setImportError(parsed.error);
            addToast(parsed.error, 'error');
            return;
        }
        importAbortRef.current?.abort();
        const controller = new AbortController();
        importAbortRef.current = controller;
        const gen = ++importGenRef.current;
        setIsImporting(true);
        try {
            const res = await apiFetch(STREAMING_ADMIN_IMPORT_EVENTS_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(parsed.request), signal: controller.signal });
            if (!mountedRef.current || controller.signal.aborted || gen !== importGenRef.current) return;
            if (!res.ok) {
                const msg = await readErrorMessage(res, `Import failed (HTTP ${res.status}).`);
                if (mountedRef.current && gen === importGenRef.current) { setImportError(msg); addToast(msg, 'error'); }
                return;
            }
            const body = (await res.json()) as ImportEventsBatchResponse;
            if (!mountedRef.current || controller.signal.aborted || gen !== importGenRef.current) return;
            setImportResult(body);
            setImportCheckpoint('');
            invalidateReconcileApproval();
            onChanged?.();
            void loadAdminState();
            addToast(`Imported ${body.batchSize} events (checkpoint ${body.checkpoint}). Provide a new opaque checkpoint for the next fresh batch.`, 'success');
        } catch (err: unknown) {
            if (!mountedRef.current || controller.signal.aborted || isAbortError(err) || gen !== importGenRef.current) return;
            const msg = err instanceof Error ? err.message : 'Event batch import failed.';
            setImportError(msg);
            addToast(msg, 'error');
        } finally {
            if (mountedRef.current && gen === importGenRef.current) setIsImporting(false);
        }
    };

    const handleSavePolicy = async () => {
        if (!isAdmin || isSavingPolicy) return;
        setPolicyError(null);
        const minWatch = Number(minWatchInput.trim());
        const reconnect = Number(reconnectInput.trim());
        if (!Number.isSafeInteger(minWatch) || minWatch < 0 || minWatch > 86_400) { setPolicyError('minimumWatchSecs must be an integer between 0 and 86400.'); return; }
        if (!Number.isSafeInteger(reconnect) || reconnect < 0 || reconnect > 300) { setPolicyError('reconnectWindowSecs must be an integer between 0 and 300.'); return; }
        const usersParsed = parsePolicyTargetsJson(excludedUsersText, 'excludedUsers');
        if (!usersParsed.ok) { setPolicyError(usersParsed.error); return; }
        const libsParsed = parsePolicyTargetsJson(excludedLibrariesText, 'excludedLibraries');
        if (!libsParsed.ok) { setPolicyError(libsParsed.error); return; }
        const payload: UpdateTrackingPolicyRequest = { minimumWatchSecs: minWatch, reconnectWindowSecs: reconnect, excludedUsers: usersParsed.targets, excludedLibraries: libsParsed.targets };
        const submitted = { minimum: minWatchInput, reconnect: reconnectInput, users: excludedUsersText, libraries: excludedLibrariesText };
        loadGenRef.current += 1;
        loadAbortRef.current?.abort();
        setIsLoadingInitial(false);
        policyAbortRef.current?.abort();
        const controller = new AbortController();
        policyAbortRef.current = controller;
        const gen = ++policyGenRef.current;
        setIsSavingPolicy(true);
        try {
            const res = await apiFetch(STREAMING_ADMIN_POLICIES_URL, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: controller.signal });
            if (!mountedRef.current || controller.signal.aborted || gen !== policyGenRef.current) return;
            if (!res.ok) {
                const msg = await readErrorMessage(res, `Failed to update tracking policy (HTTP ${res.status}).`);
                if (mountedRef.current && gen === policyGenRef.current) { setPolicyError(msg); addToast(msg, 'error'); }
                return;
            }
            const body = (await res.json()) as TrackingPolicyResponse;
            if (!mountedRef.current || controller.signal.aborted || gen !== policyGenRef.current) return;
            acceptPolicy(body, submitted);
            invalidateReconcileApproval();
            onChanged?.();
            addToast(`Tracking policy updated (revision ${body.policyRevision}).`, 'success');
        } catch (err: unknown) {
            if (!mountedRef.current || controller.signal.aborted || isAbortError(err) || gen !== policyGenRef.current) return;
            setPolicyError(err instanceof Error ? err.message : 'Failed to update tracking policy.');
        } finally {
            if (mountedRef.current && gen === policyGenRef.current) setIsSavingPolicy(false);
        }
    };

    const handleUpsertUserLink = async () => {
        if (!isAdmin || isMutatingLink) return;
        setLinkError(null);
        const afUserId = Number(linkAfUserId.trim());
        const provider = linkProvider.trim().toLowerCase();
        const serverId = linkServerId.trim();
        const providerUserId = linkProviderUserId.trim();
        if (!Number.isSafeInteger(afUserId) || afUserId <= 0) { setLinkError('afUserId must be a positive integer.'); return; }
        if (provider !== 'jellyfin' && provider !== 'emby') { setLinkError('provider must be "jellyfin" or "emby".'); return; }
        if (!serverId || !providerUserId) { setLinkError('serverId and providerUserId are required (no display-name guessing).'); return; }
        const payload: UpsertStreamingUserLinkRequest = { afUserId, provider, serverId, providerUserId };
        linkAbortRef.current?.abort();
        const controller = new AbortController();
        linkAbortRef.current = controller;
        const gen = ++linkGenRef.current;
        setIsMutatingLink(true);
        try {
            const res = await apiFetch(STREAMING_ADMIN_USER_LINKS_URL, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: controller.signal });
            if (!mountedRef.current || controller.signal.aborted || gen !== linkGenRef.current) return;
            if (!res.ok) {
                const msg = await readErrorMessage(res, `Failed to save user link (HTTP ${res.status}).`);
                if (mountedRef.current && gen === linkGenRef.current) { setLinkError(msg); addToast(msg, 'error'); }
                return;
            }
            const body = (await res.json()) as StreamingUserLinksResponse;
            if (!mountedRef.current || controller.signal.aborted || gen !== linkGenRef.current) return;
            setLinksData(body);
            setLinkProviderUserId('');
            invalidateReconcileApproval();
            onChanged?.();
            addToast('Explicit user identity link saved.', 'success');
        } catch (err: unknown) {
            if (!mountedRef.current || controller.signal.aborted || isAbortError(err) || gen !== linkGenRef.current) return;
            setLinkError(err instanceof Error ? err.message : 'Failed to save user link.');
        } finally {
            if (mountedRef.current && gen === linkGenRef.current) setIsMutatingLink(false);
        }
    };

    const handleDeleteUserLink = async (link: StreamingUserLinkRecord) => {
        if (!isAdmin || isMutatingLink) return;
        setLinkError(null);
        const payload: DeleteStreamingUserLinkRequest = { afUserId: link.afUserId, provider: link.provider, serverId: link.serverId, providerUserId: link.providerUserId };
        linkAbortRef.current?.abort();
        const controller = new AbortController();
        linkAbortRef.current = controller;
        const gen = ++linkGenRef.current;
        setIsMutatingLink(true);
        try {
            const res = await apiFetch(STREAMING_ADMIN_USER_LINKS_URL, { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: controller.signal });
            if (!mountedRef.current || controller.signal.aborted || gen !== linkGenRef.current) return;
            if (!res.ok) {
                const msg = await readErrorMessage(res, `Failed to delete user link (HTTP ${res.status}).`);
                if (mountedRef.current && gen === linkGenRef.current) { setLinkError(msg); addToast(msg, 'error'); }
                return;
            }
            const body = (await res.json()) as StreamingUserLinksResponse;
            if (!mountedRef.current || controller.signal.aborted || gen !== linkGenRef.current) return;
            setLinksData(body);
            invalidateReconcileApproval();
            onChanged?.();
            addToast('Explicit user identity link removed.', 'success');
        } catch (err: unknown) {
            if (!mountedRef.current || controller.signal.aborted || isAbortError(err) || gen !== linkGenRef.current) return;
            setLinkError(err instanceof Error ? err.message : 'Failed to delete user link.');
        } finally {
            if (mountedRef.current && gen === linkGenRef.current) setIsMutatingLink(false);
        }
    };

    const handlePreviewReconciliation = async () => {
        if (!isAdmin || isPreviewingReconcile || isApplyingReconcile) return;
        invalidateReconcileApproval();
        setReconcileError(null);
        setReconcileStaleConflict(null);
        setReconcileResult(null);
        const idsParsed = parseCandidateIdsInput(candidateIdsInput);
        if (!idsParsed.ok) { setReconcileError(idsParsed.error); return; }
        const limitNum = Number(reconcileLimitInput.trim());
        if (!Number.isSafeInteger(limitNum) || limitNum < 1 || limitNum > MAX_RECONCILIATION_LIMIT) {
            setReconcileError(`limit must be an integer between 1 and ${MAX_RECONCILIATION_LIMIT}.`);
            return;
        }
        const payload: ReconciliationPreviewRequest = { candidateIds: idsParsed.ids, limit: limitNum };
        const controller = new AbortController();
        reconcileAbortRef.current = controller;
        const gen = ++reconcileGenRef.current;
        setIsPreviewingReconcile(true);
        try {
            const res = await apiFetch(STREAMING_ADMIN_RECONCILIATION_PREVIEW_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: controller.signal });
            if (!mountedRef.current || controller.signal.aborted || gen !== reconcileGenRef.current) return;
            if (!res.ok) {
                const msg = await readErrorMessage(res, `Failed to preview reconciliation (HTTP ${res.status}).`);
                if (mountedRef.current && gen === reconcileGenRef.current) { setReconcileError(msg); addToast(msg, 'error'); }
                return;
            }
            const body = (await res.json()) as ReconciliationPreviewResponse;
            if (!mountedRef.current || controller.signal.aborted || gen !== reconcileGenRef.current) return;
            setReconcilePreview(body);
            setReconcileApproved(false);
            addToast('Reconciliation preview generated. Review and approve before applying.', 'info');
        } catch (err: unknown) {
            if (!mountedRef.current || controller.signal.aborted || isAbortError(err) || gen !== reconcileGenRef.current) return;
            setReconcileError(err instanceof Error ? err.message : 'Reconciliation preview failed.');
        } finally {
            if (mountedRef.current && gen === reconcileGenRef.current) setIsPreviewingReconcile(false);
        }
    };

    const handleApplyReconciliation = async () => {
        if (!isAdmin || !reconcilePreview || !reconcileApproved || isApplyingReconcile || isPreviewingReconcile) return;
        const payload: ReconciliationApplyRequest = { previewHash: reconcilePreview.previewHash, approvalToken: reconcilePreview.approvalToken };
        reconcileAbortRef.current?.abort();
        const controller = new AbortController();
        reconcileAbortRef.current = controller;
        const gen = ++reconcileGenRef.current;
        setIsApplyingReconcile(true);
        setReconcileError(null);
        setReconcileStaleConflict(null);
        try {
            const res = await apiFetch(STREAMING_ADMIN_RECONCILIATION_APPLY_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload), signal: controller.signal });
            if (!mountedRef.current || controller.signal.aborted || gen !== reconcileGenRef.current) return;
            if (res.status === 409) {
                const msg = await readErrorMessage(res, 'Streaming history changed or approval token expired (HTTP 409). Generate a fresh preview.');
                if (mountedRef.current && gen === reconcileGenRef.current) {
                    setReconcilePreview(null);
                    setReconcileApproved(false);
                    setReconcileStaleConflict(msg);
                    setReconcileError(msg);
                    addToast(msg, 'error');
                }
                return;
            }
            if (!res.ok) {
                const msg = await readErrorMessage(res, `Failed to apply reconciliation (HTTP ${res.status}).`);
                if (mountedRef.current && gen === reconcileGenRef.current) {
                    setReconcilePreview(null);
                    setReconcileApproved(false);
                    setReconcileError(msg);
                    addToast(msg, 'error');
                }
                return;
            }
            const body = (await res.json()) as ReconciliationApplyResponse;
            if (!mountedRef.current || controller.signal.aborted || gen !== reconcileGenRef.current) return;
            setReconcilePreview(null);
            setReconcileApproved(false);
            setReconcileResult(body);
            onChanged?.();
            addToast(`Applied legacy reconciliation to ${body.appliedRows} rows.`, 'success');
        } catch (err: unknown) {
            if (!mountedRef.current || controller.signal.aborted || isAbortError(err) || gen !== reconcileGenRef.current) return;
            setReconcilePreview(null);
            setReconcileApproved(false);
            setReconcileError(err instanceof Error ? err.message : 'Reconciliation apply failed.');
        } finally {
            if (mountedRef.current && gen === reconcileGenRef.current) setIsApplyingReconcile(false);
        }
    };

    if (authLoading) {
        return (
            <section aria-label="Streaming History Administration" data-testid="streaming-history-admin-loading" className="rounded-2xl border border-white/[0.06] bg-slate-900/40 p-5 w-full min-w-0 max-w-full">
                <div className="flex items-center gap-2 text-xs text-slate-300"><Loader2 size={14} className="animate-spin text-indigo-400" /><span>Verifying administrative permissions...</span></div>
            </section>
        );
    }

    if (!isAdmin) {
        return (
            <section aria-label="Streaming History Administration" data-testid="streaming-history-admin-boundary" className="rounded-2xl border border-amber-500/25 bg-amber-950/20 p-5 w-full min-w-0 max-w-full">
                <div className="flex items-start gap-3">
                    <Lock size={18} className="text-amber-400 shrink-0 mt-0.5" />
                    <div className="space-y-1 min-w-0">
                        <h3 className="text-sm font-bold text-amber-200">Administrative Access Required</h3>
                        <p className="text-xs text-amber-100/80">Streaming history event imports, tracking policies, explicit user-link mappings, and legacy reconciliation are restricted to administrators.</p>
                    </div>
                </div>
            </section>
        );
    }

    return (
        <section aria-label="Streaming History Administration" data-testid="streaming-history-admin" className="rounded-2xl border border-white/[0.06] bg-slate-900/40 p-5 space-y-4 w-full min-w-0 max-w-full">
            <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-white/[0.06]">
                <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-base font-bold text-slate-100 flex items-center gap-2"><ShieldCheck size={18} className="text-indigo-400 shrink-0" /><span>Streaming History Administration</span></h3>
                        <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-purple-500/15 text-purple-300 border border-purple-500/30">Admin Only</span>
                    </div>
                    <p className="text-xs text-slate-400">Bounded event imports (&le;1 MiB, &le;500 events), tracking policies, explicit user identity links, and verified-backup legacy reconciliation.</p>
                </div>
                <div className="flex flex-wrap items-center gap-1.5" role="tablist" aria-label="Streaming Admin Sections">
                    {([
                        { id: 'imports', label: 'Event Imports', icon: Upload },
                        { id: 'policies', label: 'Tracking Policies', icon: Sliders },
                        { id: 'links', label: 'User Links', icon: Users },
                        { id: 'reconciliation', label: 'Reconciliation', icon: GitCompare },
                    ] as const).map(({ id, label, icon: Icon }) => (
                        <button key={id} type="button" role="tab" aria-selected={activeSection === id} data-testid={`admin-tab-${id}`} onClick={() => handleSectionChange(id)} className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition-all ${activeSection === id ? 'bg-indigo-600 text-white' : 'bg-black/30 text-slate-300 hover:bg-white/[0.08]'}`}>
                            <Icon size={13} /><span>{label}</span>
                        </button>
                    ))}
                    <button type="button" onClick={() => void loadAdminState()} disabled={isLoadingInitial} data-testid="admin-refresh-btn" className="px-2.5 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.06] hover:bg-white/[0.12] text-slate-200 flex items-center gap-1">
                        <RefreshCw size={13} className={isLoadingInitial ? 'animate-spin' : ''} /><span>Refresh</span>
                    </button>
                </div>
            </div>

            {loadError && (
                <div role="alert" data-testid="admin-load-error" className="p-3 rounded-xl border border-rose-500/30 bg-rose-950/30 text-xs text-rose-200 flex items-center gap-2">
                    <AlertCircle size={14} className="text-rose-400 shrink-0" /><span className="min-w-0 break-words">{loadError}</span>
                </div>
            )}

            {activeSection === 'imports' && (
                <div data-testid="admin-section-imports" className="space-y-4 min-w-0 max-w-full">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <div className="rounded-xl border border-white/[0.06] bg-black/30 p-4 space-y-2 min-w-0">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">Upstream Capabilities &amp; Checkpoints (Max {statusData?.maxBatchEvents ?? MAX_IMPORT_BATCH_EVENTS} events/batch)</h4>
                            <div className="overflow-x-auto min-w-0 max-w-full space-y-2">
                                {statusData?.capabilities.map((cap) => (
                                    <div key={`${cap.provider}:${cap.serverId}`} data-testid="import-capability-row" className="p-2.5 rounded-lg bg-slate-900/60 border border-white/[0.05] text-xs space-y-1">
                                        <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                                            <span className="font-bold text-indigo-300">{cap.provider} / {cap.serverId}</span>
                                            <span className="text-amber-300">{cap.upstreamEndpointClassification}</span>
                                        </div>
                                        <p className="text-xs text-slate-400">{cap.reason}</p>
                                    </div>
                                ))}
                                {statusData && statusData.checkpoints.length > 0 ? (
                                    <table className="w-full text-left text-xs border-collapse" data-testid="import-checkpoints-table">
                                        <thead><tr className="border-b border-white/10 text-slate-400"><th className="py-1.5 pr-2">Provider/Server</th><th className="py-1.5 pr-2">Source</th><th className="py-1.5 pr-2">Checkpoint</th><th className="py-1.5 pr-2">Imported</th><th className="py-1.5">Last Error</th></tr></thead>
                                        <tbody>
                                            {statusData.checkpoints.map((cp) => (
                                                <tr key={`${cp.provider}:${cp.serverId}:${cp.source}`} className="border-b border-white/[0.04] font-mono">
                                                    <td className="py-1.5 pr-2 text-slate-200">{cp.provider}:{cp.serverId}</td>
                                                    <td className="py-1.5 pr-2 text-slate-300">{cp.source}</td>
                                                    <td className="py-1.5 pr-2 text-indigo-300">{cp.checkpoint}</td>
                                                    <td className="py-1.5 pr-2 text-emerald-300">{cp.imported}</td>
                                                    <td className="py-1.5 text-rose-300">{cp.lastError ?? 'None'}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                ) : <p className="text-xs text-slate-400">No import checkpoints recorded yet.</p>}
                            </div>
                        </div>

                        <div className="rounded-xl border border-white/[0.06] bg-black/30 p-4 space-y-3 min-w-0">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">Bounded Event JSON Batch Import (&le;1 MiB, &le;500 events)</h4>
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                                <label className="space-y-1"><span className="text-slate-400">Provider</span><select aria-label="Import Provider" data-testid="import-provider-select" value={importProvider} onChange={(e) => setImportProvider(e.target.value)} className="w-full rounded-lg bg-slate-900 border border-white/10 px-2.5 py-1.5 text-xs text-slate-100"><option value="jellyfin">jellyfin</option><option value="emby">emby</option></select></label>
                                <label className="space-y-1"><span className="text-slate-400">Server ID</span><input type="text" aria-label="Import Server ID" data-testid="import-server-id-input" value={importServerId} onChange={(e) => setImportServerId(e.target.value)} className="w-full rounded-lg bg-slate-900 border border-white/10 px-2.5 py-1.5 text-xs text-slate-100" /></label>
                                <label className="space-y-1"><span className="text-slate-400">Source</span><input type="text" aria-label="Import Source" data-testid="import-source-input" value={importSource} onChange={(e) => setImportSource(e.target.value)} className="w-full rounded-lg bg-slate-900 border border-white/10 px-2.5 py-1.5 text-xs text-slate-100" /></label>
                                <label className="space-y-1"><span className="text-slate-400">Opaque Checkpoint</span><input type="text" aria-label="Import Checkpoint" data-testid="import-checkpoint-input" value={importCheckpoint} onChange={(e) => setImportCheckpoint(e.target.value)} placeholder="Upstream cursor / batch token" className="w-full rounded-lg bg-slate-900 border border-white/10 px-2.5 py-1.5 text-xs text-slate-100" /></label>
                            </div>
                            <input type="file" aria-label="Upload Event Batch JSON" data-testid="import-file-input" accept=".json,application/json" onChange={(e) => void handleImportFileChange(e)} className="block w-full text-xs text-slate-300" />
                            <textarea aria-label="Event Batch JSON Payload" data-testid="import-json-textarea" rows={5} value={importJsonText} onChange={(e) => { setImportJsonText(e.target.value); setImportError(null); }} placeholder='[{"sourceEventId":"evt-1","userId":"u-1","itemId":"i-1","itemName":"Dune","startedAt":"2026-03-01T20:00:00Z"}]' className="w-full rounded-lg bg-slate-950 border border-white/10 p-2.5 text-xs font-mono text-slate-100" />
                            {importError && <div role="alert" data-testid="import-error" className="p-2.5 rounded-lg border border-rose-500/30 bg-rose-950/30 text-xs text-rose-200">{importError}</div>}
                            <div className="flex justify-end">
                                <button type="button" data-testid="import-submit-btn" disabled={isImporting} onClick={() => void handleSubmitImportBatch()} className="px-3.5 py-2 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white flex items-center gap-1.5">
                                    {isImporting ? <Loader2 size={14} className="animate-spin" /> : <Upload size={14} />}<span>Submit Event Batch</span>
                                </button>
                            </div>
                        </div>
                    </div>

                    {importResult && (
                        <div data-testid="import-outcomes-panel" className="rounded-xl border border-emerald-500/25 bg-emerald-950/15 p-4 space-y-2 text-xs min-w-0 max-w-full">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                                <strong className="text-emerald-200 flex items-center gap-1.5"><CheckCircle2 size={14} /><span>Batch Imported: Checkpoint {importResult.checkpoint} (Revision {importResult.revision})</span></strong>
                                <div className="flex flex-wrap gap-3 font-mono text-slate-200">
                                    <span>Inserted: <strong data-testid="import-inserted-count">{importResult.insertedIncluded}</strong></span>
                                    <span>Dedup Retries: <strong data-testid="import-dedup-count">{importResult.deduplicatedRetries}</strong></span>
                                    <span>Overlap Duplicates: <strong data-testid="import-overlap-dup-count">{importResult.confirmedOverlapDuplicates}</strong></span>
                                    <span>Ambiguous Overlaps: <strong data-testid="import-ambiguous-count" className="text-amber-300">{importResult.ambiguousOverlaps}</strong></span>
                                    <span>Cumulative: <strong data-testid="import-cumulative-count">{importResult.cumulativeImported}</strong></span>
                                </div>
                            </div>
                            <p data-testid="import-next-checkpoint-notice" className="text-xs text-amber-200">Checkpoint <code className="font-mono">{importResult.checkpoint}</code> is now recorded. Enter a new opaque upstream checkpoint before importing fresh events.</p>
                            <div className="overflow-x-auto min-w-0 max-w-full">
                                <table className="w-full text-left text-xs font-mono border-collapse">
                                    <thead><tr className="border-b border-white/10 text-slate-400"><th className="py-1 pr-2">Source Event ID</th><th className="py-1 pr-2">History ID</th><th className="py-1 pr-2">Disposition</th><th className="py-1 pr-2">Policy Status</th><th className="py-1">Matched Observed IDs</th></tr></thead>
                                    <tbody>
                                        {importResult.outcomes.map((o, idx) => (
                                            <tr key={`${o.sourceEventId}-${idx}`} data-testid={`import-outcome-${o.sourceEventId}`} className="border-b border-white/[0.04]">
                                                <td className="py-1 pr-2 text-slate-100">{o.sourceEventId}</td>
                                                <td className="py-1 pr-2 text-slate-300">{o.historyId}</td>
                                                <td className="py-1 pr-2 text-indigo-300">{o.disposition}</td>
                                                <td className={`py-1 pr-2 ${o.policyStatus === 'ambiguous' ? 'text-amber-300 font-bold' : 'text-emerald-300'}`}>{o.policyStatus}</td>
                                                <td className="py-1 text-slate-400">{o.matchedObservedIds.join(', ') || '-'}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {activeSection === 'policies' && (
                <div data-testid="admin-section-policies" className="rounded-xl border border-white/[0.06] bg-black/30 p-4 space-y-3 text-xs min-w-0 max-w-full">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <label className="space-y-1"><span className="text-slate-300 font-semibold">Minimum Watch Seconds (0..86400)</span><input type="number" aria-label="Minimum Watch Seconds" data-testid="policy-min-watch-input" value={minWatchInput} onChange={(e) => setMinWatchInput(e.target.value)} className="w-full rounded-lg bg-slate-900 border border-white/10 px-3 py-1.5 text-xs text-slate-100" /></label>
                        <label className="space-y-1"><span className="text-slate-300 font-semibold">Reconnect Window Seconds (0..300)</span><input type="number" aria-label="Reconnect Window Seconds" data-testid="policy-reconnect-input" value={reconnectInput} onChange={(e) => setReconnectInput(e.target.value)} className="w-full rounded-lg bg-slate-900 border border-white/10 px-3 py-1.5 text-xs text-slate-100" /></label>
                    </div>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                        <label className="space-y-1"><span className="text-slate-300 font-semibold">Excluded Users JSON Array (provider, serverId, id, name)</span><textarea aria-label="Excluded Users JSON" data-testid="policy-excluded-users-textarea" rows={4} value={excludedUsersText} onChange={(e) => setExcludedUsersText(e.target.value)} className="w-full rounded-lg bg-slate-950 border border-white/10 p-2.5 text-xs font-mono text-slate-100" /></label>
                        <label className="space-y-1"><span className="text-slate-300 font-semibold">Excluded Libraries JSON Array (provider, serverId, id, name)</span><textarea aria-label="Excluded Libraries JSON" data-testid="policy-excluded-libraries-textarea" rows={4} value={excludedLibrariesText} onChange={(e) => setExcludedLibrariesText(e.target.value)} className="w-full rounded-lg bg-slate-950 border border-white/10 p-2.5 text-xs font-mono text-slate-100" /></label>
                    </div>
                    {policyError && <div role="alert" data-testid="policy-error" className="p-2.5 rounded-lg border border-rose-500/30 bg-rose-950/30 text-xs text-rose-200">{policyError}</div>}
                    <div className="flex items-center justify-between gap-2">
                        <span className="text-xs text-slate-400">Policy Revision: <strong className="font-mono text-slate-200">{policyData?.policyRevision ?? 1}</strong></span>
                        <button type="button" data-testid="policy-save-btn" disabled={isSavingPolicy} onClick={() => void handleSavePolicy()} className="px-3.5 py-2 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white">Save Tracking Policy</button>
                    </div>
                </div>
            )}

            {activeSection === 'links' && (
                <div data-testid="admin-section-links" className="rounded-xl border border-white/[0.06] bg-black/30 p-4 space-y-3 text-xs min-w-0 max-w-full">
                    <p className="text-xs text-slate-400">{linksData?.identitySemantics ?? 'Explicit (afUserId, provider, serverId, providerUserId) mappings only; display names are never used for implicit matching.'}</p>
                    <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 items-end">
                        <label className="space-y-1"><span className="text-slate-400">AF User ID</span><input type="number" aria-label="AF User ID" data-testid="link-af-user-id-input" value={linkAfUserId} onChange={(e) => setLinkAfUserId(e.target.value)} className="w-full rounded-lg bg-slate-900 border border-white/10 px-2.5 py-1.5 text-xs text-slate-100" /></label>
                        <label className="space-y-1"><span className="text-slate-400">Provider</span><select aria-label="Link Provider" data-testid="link-provider-select" value={linkProvider} onChange={(e) => setLinkProvider(e.target.value)} className="w-full rounded-lg bg-slate-900 border border-white/10 px-2.5 py-1.5 text-xs text-slate-100"><option value="jellyfin">jellyfin</option><option value="emby">emby</option></select></label>
                        <label className="space-y-1"><span className="text-slate-400">Server ID</span><input type="text" aria-label="Link Server ID" data-testid="link-server-id-input" value={linkServerId} onChange={(e) => setLinkServerId(e.target.value)} className="w-full rounded-lg bg-slate-900 border border-white/10 px-2.5 py-1.5 text-xs text-slate-100" /></label>
                        <label className="space-y-1"><span className="text-slate-400">Provider User ID</span><input type="text" aria-label="Provider User ID" data-testid="link-provider-user-id-input" value={linkProviderUserId} onChange={(e) => setLinkProviderUserId(e.target.value)} className="w-full rounded-lg bg-slate-900 border border-white/10 px-2.5 py-1.5 text-xs text-slate-100" /></label>
                        <button type="button" data-testid="link-upsert-btn" disabled={isMutatingLink} onClick={() => void handleUpsertUserLink()} className="px-3 py-1.5 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white flex items-center justify-center gap-1"><Plus size={14} /><span>Save Link</span></button>
                    </div>
                    {linkError && <div role="alert" data-testid="link-error" className="p-2.5 rounded-lg border border-rose-500/30 bg-rose-950/30 text-xs text-rose-200">{linkError}</div>}
                    <div className="overflow-x-auto min-w-0 max-w-full">
                        <table className="w-full text-left text-xs font-mono border-collapse" data-testid="user-links-table">
                            <thead><tr className="border-b border-white/10 text-slate-400"><th className="py-1.5 pr-2">AF User</th><th className="py-1.5 pr-2">Provider</th><th className="py-1.5 pr-2">Server ID</th><th className="py-1.5 pr-2">Provider User ID</th><th className="py-1.5 text-right">Action</th></tr></thead>
                            <tbody>
                                {(linksData?.links ?? []).map((lnk) => {
                                    const key = `${lnk.afUserId}:${lnk.provider}:${lnk.serverId}:${lnk.providerUserId}`;
                                    return (
                                        <tr key={key} data-testid={`user-link-row-${key}`} className="border-b border-white/[0.04]">
                                            <td className="py-1.5 pr-2 text-slate-100">#{lnk.afUserId} {lnk.afUsername ? `(${lnk.afUsername})` : ''}</td>
                                            <td className="py-1.5 pr-2 text-indigo-300">{lnk.provider}</td>
                                            <td className="py-1.5 pr-2 text-slate-300">{lnk.serverId}</td>
                                            <td className="py-1.5 pr-2 text-emerald-300">{lnk.providerUserId}</td>
                                            <td className="py-1.5 text-right">
                                                <button type="button" data-testid={`delete-link-${key}`} disabled={isMutatingLink} onClick={() => void handleDeleteUserLink(lnk)} className="px-2 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 inline-flex items-center gap-1"><Trash2 size={12} /><span>Delete</span></button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {activeSection === 'reconciliation' && (
                <div data-testid="admin-section-reconciliation" className="rounded-xl border border-white/[0.06] bg-black/30 p-4 space-y-4 text-xs min-w-0 max-w-full">
                    <div role="note" data-testid="reconciliation-backup-warning" className="p-3 rounded-xl border border-amber-500/30 bg-amber-950/25 text-amber-100 flex items-start gap-2.5">
                        <AlertTriangle size={16} className="text-amber-400 shrink-0 mt-0.5" />
                        <p className="text-xs"><strong>Verified SQLite Backup Requirement:</strong> Applying legacy reconciliation requires a verified SQLite backup (<code className="font-mono">VACUUM INTO</code>) and a valid 15-minute signed approval token bound to the exact preview hash. Preview never auto-applies changes.</p>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
                        <label className="space-y-1"><span className="text-slate-300 font-semibold">Candidate Row IDs (comma-separated, optional)</span><input type="text" aria-label="Candidate Row IDs" data-testid="reconcile-candidate-ids-input" value={candidateIdsInput} onChange={(e) => { setCandidateIdsInput(e.target.value); invalidateReconcileApproval(); }} placeholder="e.g. 10, 12, 19" className="w-full rounded-lg bg-slate-900 border border-white/10 px-3 py-1.5 text-xs text-slate-100" /></label>
                        <label className="space-y-1"><span className="text-slate-300 font-semibold">Preview Limit (1..1000)</span><input type="number" aria-label="Reconciliation Preview Limit" data-testid="reconcile-limit-input" value={reconcileLimitInput} onChange={(e) => { setReconcileLimitInput(e.target.value); invalidateReconcileApproval(); }} className="w-full rounded-lg bg-slate-900 border border-white/10 px-3 py-1.5 text-xs text-slate-100" /></label>
                        <button type="button" data-testid="reconcile-preview-btn" disabled={isPreviewingReconcile || isApplyingReconcile} onClick={() => void handlePreviewReconciliation()} className="px-3.5 py-2 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white">{isPreviewingReconcile ? 'Generating Preview...' : 'Generate Reconciliation Preview'}</button>
                    </div>

                    {reconcileStaleConflict && <div role="alert" data-testid="reconcile-stale-conflict" className="p-3 rounded-xl border border-amber-500/40 bg-amber-950/35 text-xs text-amber-200"><strong>Stale Preview Conflict (409):</strong> {reconcileStaleConflict}</div>}
                    {reconcileError && !reconcileStaleConflict && <div role="alert" data-testid="reconcile-error" className="p-3 rounded-xl border border-rose-500/30 bg-rose-950/30 text-xs text-rose-200">{reconcileError}</div>}

                    {reconcilePreview && (
                        <div data-testid="reconcile-preview-panel" className="space-y-3 rounded-xl border border-indigo-500/25 bg-indigo-950/15 p-4 min-w-0 max-w-full">
                            <div className="flex flex-wrap items-center justify-between gap-2 font-mono">
                                <span>Preview Hash: <code data-testid="reconcile-preview-hash" className="text-indigo-200">{reconcilePreview.previewHash}</code></span>
                                <span>Affected Rows: <strong data-testid="reconcile-affected-count">{reconcilePreview.totalAffectedRows}</strong></span>
                            </div>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono">
                                <div data-testid="reconcile-counts-before" className="p-2.5 rounded-lg bg-black/30 border border-white/[0.06]"><div className="font-bold text-slate-300 mb-1">Counts Before</div><div>Legacy: {reconcilePreview.countsBefore.legacyRecords} | Summaries: {reconcilePreview.countsBefore.itemSummaries} | Undated: {reconcilePreview.countsBefore.undatedRecords} | Confirmed: {reconcilePreview.countsBefore.confirmedPlays}</div></div>
                                <div data-testid="reconcile-counts-after" className="p-2.5 rounded-lg bg-black/30 border border-white/[0.06]"><div className="font-bold text-slate-300 mb-1">Projected Counts After</div><div>Legacy: {reconcilePreview.countsAfter.legacyRecords} | Summaries: {reconcilePreview.countsAfter.itemSummaries} | Undated: {reconcilePreview.countsAfter.undatedRecords} | Confirmed: {reconcilePreview.countsAfter.confirmedPlays}</div></div>
                            </div>
                            <div className="overflow-x-auto min-w-0 max-w-full">
                                <table className="w-full text-left text-xs font-mono border-collapse" data-testid="reconcile-changes-table">
                                    <thead><tr className="border-b border-white/10 text-slate-400"><th className="py-1 pr-2">Row ID</th><th className="py-1 pr-2">Classification</th><th className="py-1 pr-2">Before State</th><th className="py-1 pr-2">After State</th><th className="py-1">Field Changes</th></tr></thead>
                                    <tbody>
                                        {reconcilePreview.affectedRows.map((row) => (
                                            <tr key={row.id} data-testid={`reconcile-row-${row.id}`} className="border-b border-white/[0.05] align-top">
                                                <td className="py-1.5 pr-2 text-slate-100">#{row.id}</td>
                                                <td className="py-1.5 pr-2 text-amber-300">{row.classification}</td>
                                                <td className="py-1.5 pr-2 text-slate-300">{row.before.provenance} / {row.before.timestampCertainty} / {row.before.byteAccuracy}</td>
                                                <td className="py-1.5 pr-2 text-emerald-300">{row.after.provenance} / {row.after.timestampCertainty} / {row.after.byteAccuracy}</td>
                                                <td className="py-1.5 text-slate-200">{row.changes.map((c) => `${c.field}: "${c.before}" -> "${c.after}"`).join('; ')}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                            <div role="note" data-testid="reconcile-unverified-proposal-warning" className="p-2.5 rounded-lg border border-amber-500/35 bg-amber-950/30 text-xs text-amber-100">
                                <strong>Unverified Proposals Warning:</strong> Suspected classifications and epoch/undated matches are unverified proposals, not proof of fabricated data. The operator must verify upstream source evidence before approving.
                            </div>
                            <div className="pt-2 border-t border-white/10 flex flex-wrap items-center justify-between gap-3">
                                <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-200">
                                    <input type="checkbox" data-testid="reconcile-approve-checkbox" checked={reconcileApproved} onChange={(e) => setReconcileApproved(e.target.checked)} />
                                    <span>I explicitly approve applying preview hash <code className="font-mono">{reconcilePreview.previewHash}</code> after verifying source evidence and SQLite backup.</span>
                                </label>
                                <button type="button" data-testid="reconcile-apply-btn" disabled={!reconcileApproved || isApplyingReconcile || isPreviewingReconcile} onClick={() => void handleApplyReconciliation()} className="px-3.5 py-2 rounded-xl text-xs font-bold bg-amber-600 hover:bg-amber-500 disabled:opacity-40 text-white">{isApplyingReconcile ? 'Applying...' : 'Apply Approved Reconciliation'}</button>
                            </div>
                        </div>
                    )}

                    {reconcileResult && (
                        <div data-testid="reconcile-apply-result" className="p-3.5 rounded-xl border border-emerald-500/30 bg-emerald-950/20 text-xs text-emerald-100 space-y-1">
                            <div><strong>Reconciliation Applied:</strong> Audit #{reconcileResult.auditId} | Applied Rows: {reconcileResult.appliedRows} | Revision: {reconcileResult.historyRevision}</div>
                            <div className="font-mono">Hash: {reconcileResult.previewHash} | Backup: {reconcileResult.backupPath ?? 'in-memory'}</div>
                        </div>
                    )}
                </div>
            )}
        </section>
    );
}
