'use client';

import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
    Archive,
    Download,
    Upload,
    ShieldCheck,
    AlertTriangle,
    AlertCircle,
    CheckCircle2,
    Loader2,
    FileJson,
    RefreshCw,
    Lock,
    GitMerge,
    Replace,
} from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/contexts/ToastContext';

export const STREAMING_PORTABILITY_EXPORT_URL = '/api/v1/admin/streaming/portability/export';
export const STREAMING_PORTABILITY_PREVIEW_URL = '/api/v1/admin/streaming/portability/preview';
export const STREAMING_PORTABILITY_RESTORE_URL = '/api/v1/admin/streaming/portability/restore';

export const STREAMING_ARCHIVE_FORMAT = 'aetherflow.streaming-history';
export const STREAMING_ARCHIVE_FORMAT_VERSION = 1;
export const STREAMING_DATABASE_SCHEMA_VERSION = 20;
export const STREAMING_PROVENANCE_VERSION = 1;
export const MAX_STREAMING_ARCHIVE_BYTES = 8 * 1024 * 1024;
export const MAX_STREAMING_PORTABLE_ROWS = 10_000;

export type StreamingRestoreMode = 'merge' | 'replace';

export interface StreamingPortabilityRecordCounts {
    history: number;
    labels: number;
    sessionSamples: number;
    bandwidthSamples: number;
    trackingPolicies: number;
}

export interface StreamingPortabilityPlanCounts {
    insert: StreamingPortabilityRecordCounts;
    exactDuplicate: StreamingPortabilityRecordCounts;
    conflict: StreamingPortabilityRecordCounts;
}

export interface StreamingPortabilityConflict {
    table: string;
    archiveKey: string;
    existingKey: string | null;
    reason: string;
    action: string;
}

export interface StreamingArchiveManifest {
    format: string;
    formatVersion: number;
    schemaVersion: number;
    provenanceVersion: number;
    exportedAt: string;
    recordCounts: StreamingPortabilityRecordCounts;
    redactedFields: string[];
    omittedTables: string[];
    sha256: string;
}

export interface StreamingArchiveData {
    history: unknown[];
    labels: unknown[];
    sessionSamples: unknown[];
    bandwidthSamples: unknown[];
    trackingPolicy: Record<string, unknown>;
}

export interface StreamingArchive {
    manifest: StreamingArchiveManifest;
    data: StreamingArchiveData;
}

export interface StreamingPortabilityPreviewRequest {
    mode: StreamingRestoreMode;
    archive: StreamingArchive;
}

export interface StreamingPortabilityRestoreRequest {
    mode: StreamingRestoreMode;
    archive: StreamingArchive;
    approvalToken: string;
}

export interface StreamingPortabilityPreviewResponse {
    mode: StreamingRestoreMode;
    archiveSha256: string;
    previewSha256: string;
    expiresAt: string;
    archiveCounts: StreamingPortabilityRecordCounts;
    targetCounts: StreamingPortabilityRecordCounts;
    plan: StreamingPortabilityPlanCounts;
    replacementCounts: StreamingPortabilityRecordCounts | null;
    replacementNotice: string | null;
    conflicts: StreamingPortabilityConflict[];
    approvalToken: string;
}

export interface StreamingPortabilityRestoreResponse {
    mode: StreamingRestoreMode;
    archiveSha256: string;
    previewSha256: string;
    backupVerified: boolean;
    archiveCounts: StreamingPortabilityRecordCounts;
    resultingCounts: StreamingPortabilityRecordCounts;
    plan: StreamingPortabilityPlanCounts;
    conflicts: StreamingPortabilityConflict[];
}

export interface StreamingPortabilityProps {
    initialMode?: StreamingRestoreMode;
    onRestoreApplied?: (response: StreamingPortabilityRestoreResponse) => void;
}

interface ValidatedArchiveSelection {
    fileKey: string;
    fileName: string;
    byteLength: number;
    archive: StreamingArchive;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonNegativeSafeInteger(value: unknown): value is number {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isHexSha256(value: unknown): value is string {
    return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value);
}

function isStringArray(value: unknown): value is string[] {
    return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

function isAbortError(error: unknown): boolean {
    if (!isPlainRecord(error)) return false;
    return error.name === 'AbortError' || error.code === 'ABORT_ERR';
}

function utf8ByteLength(text: string): number {
    if (typeof TextEncoder !== 'undefined') {
        return new TextEncoder().encode(text).byteLength;
    }
    return text.length;
}

export function sumRecordCounts(counts: StreamingPortabilityRecordCounts): number {
    return (
        counts.history +
        counts.labels +
        counts.sessionSamples +
        counts.bandwidthSamples +
        counts.trackingPolicies
    );
}

export function parseRecordCounts(value: unknown): StreamingPortabilityRecordCounts | null {
    if (!isPlainRecord(value)) return null;
    const { history, labels, sessionSamples, bandwidthSamples, trackingPolicies } = value;
    if (
        !isNonNegativeSafeInteger(history) ||
        !isNonNegativeSafeInteger(labels) ||
        !isNonNegativeSafeInteger(sessionSamples) ||
        !isNonNegativeSafeInteger(bandwidthSamples) ||
        !isNonNegativeSafeInteger(trackingPolicies)
    ) {
        return null;
    }
    return {
        history,
        labels,
        sessionSamples,
        bandwidthSamples,
        trackingPolicies,
    };
}

export function parsePlanCounts(value: unknown): StreamingPortabilityPlanCounts | null {
    if (!isPlainRecord(value)) return null;
    const insert = parseRecordCounts(value.insert);
    const exactDuplicate = parseRecordCounts(value.exactDuplicate);
    const conflict = parseRecordCounts(value.conflict);
    if (!insert || !exactDuplicate || !conflict) return null;
    return { insert, exactDuplicate, conflict };
}

export function parseConflict(value: unknown): StreamingPortabilityConflict | null {
    if (!isPlainRecord(value)) return null;
    if (
        typeof value.table !== 'string' ||
        value.table.length === 0 ||
        typeof value.archiveKey !== 'string' ||
        value.archiveKey.length === 0 ||
        typeof value.reason !== 'string' ||
        value.reason.length === 0 ||
        typeof value.action !== 'string' ||
        value.action.length === 0
    ) {
        return null;
    }
    const existingKey =
        value.existingKey === null || value.existingKey === undefined
            ? null
            : typeof value.existingKey === 'string'
              ? value.existingKey
              : null;
    if (
        value.existingKey !== null &&
        value.existingKey !== undefined &&
        typeof value.existingKey !== 'string'
    ) {
        return null;
    }
    return {
        table: value.table,
        archiveKey: value.archiveKey,
        existingKey,
        reason: value.reason,
        action: value.action,
    };
}

export function parseStreamingArchive(
    value: unknown
): { ok: true; archive: StreamingArchive } | { ok: false; error: string } {
    if (!isPlainRecord(value)) {
        return { ok: false, error: 'Archive file must be a JSON object with manifest and data.' };
    }
    const manifestRaw = value.manifest;
    const dataRaw = value.data;
    if (!isPlainRecord(manifestRaw) || !isPlainRecord(dataRaw)) {
        return { ok: false, error: 'Archive JSON is missing required manifest or data sections.' };
    }
    if (manifestRaw.format !== STREAMING_ARCHIVE_FORMAT) {
        return {
            ok: false,
            error: `Unsupported archive format "${String(manifestRaw.format ?? '')}". Expected "${STREAMING_ARCHIVE_FORMAT}".`,
        };
    }
    if (
        manifestRaw.formatVersion !== STREAMING_ARCHIVE_FORMAT_VERSION ||
        manifestRaw.schemaVersion !== STREAMING_DATABASE_SCHEMA_VERSION ||
        manifestRaw.provenanceVersion !== STREAMING_PROVENANCE_VERSION
    ) {
        return {
            ok: false,
            error: `Unsupported archive version metadata (formatVersion=${String(manifestRaw.formatVersion)}, schemaVersion=${String(manifestRaw.schemaVersion)}, provenanceVersion=${String(manifestRaw.provenanceVersion)}).`,
        };
    }
    if (typeof manifestRaw.exportedAt !== 'string' || manifestRaw.exportedAt.trim().length === 0) {
        return { ok: false, error: 'Archive manifest is missing a valid exportedAt timestamp.' };
    }
    if (!isHexSha256(manifestRaw.sha256)) {
        return {
            ok: false,
            error: 'Archive manifest sha256 must be a 64-character hexadecimal digest.',
        };
    }
    if (!isStringArray(manifestRaw.redactedFields) || !isStringArray(manifestRaw.omittedTables)) {
        return {
            ok: false,
            error: 'Archive manifest redactedFields and omittedTables must be string arrays.',
        };
    }
    const recordCounts = parseRecordCounts(manifestRaw.recordCounts);
    if (!recordCounts) {
        return { ok: false, error: 'Archive manifest recordCounts is missing or malformed.' };
    }
    if (
        !Array.isArray(dataRaw.history) ||
        !Array.isArray(dataRaw.labels) ||
        !Array.isArray(dataRaw.sessionSamples) ||
        !Array.isArray(dataRaw.bandwidthSamples) ||
        !isPlainRecord(dataRaw.trackingPolicy)
    ) {
        return {
            ok: false,
            error: 'Archive data must contain history, labels, sessionSamples, bandwidthSamples arrays and a trackingPolicy object.',
        };
    }
    const actualCounts: StreamingPortabilityRecordCounts = {
        history: dataRaw.history.length,
        labels: dataRaw.labels.length,
        sessionSamples: dataRaw.sessionSamples.length,
        bandwidthSamples: dataRaw.bandwidthSamples.length,
        trackingPolicies: 1,
    };
    if (
        recordCounts.history !== actualCounts.history ||
        recordCounts.labels !== actualCounts.labels ||
        recordCounts.sessionSamples !== actualCounts.sessionSamples ||
        recordCounts.bandwidthSamples !== actualCounts.bandwidthSamples ||
        recordCounts.trackingPolicies !== actualCounts.trackingPolicies
    ) {
        return {
            ok: false,
            error: 'Archive manifest recordCounts do not match the actual data array lengths.',
        };
    }
    const totalRows = sumRecordCounts(actualCounts);
    if (totalRows > MAX_STREAMING_PORTABLE_ROWS) {
        return {
            ok: false,
            error: `Archive contains ${totalRows.toLocaleString()} portable rows, exceeding the ${MAX_STREAMING_PORTABLE_ROWS.toLocaleString()}-row limit.`,
        };
    }
    return {
        ok: true,
        archive: {
            manifest: {
                format: manifestRaw.format,
                formatVersion: manifestRaw.formatVersion,
                schemaVersion: manifestRaw.schemaVersion,
                provenanceVersion: manifestRaw.provenanceVersion,
                exportedAt: manifestRaw.exportedAt,
                recordCounts,
                redactedFields: manifestRaw.redactedFields,
                omittedTables: manifestRaw.omittedTables,
                sha256: manifestRaw.sha256.toLowerCase(),
            },
            data: {
                history: dataRaw.history,
                labels: dataRaw.labels,
                sessionSamples: dataRaw.sessionSamples,
                bandwidthSamples: dataRaw.bandwidthSamples,
                trackingPolicy: dataRaw.trackingPolicy,
            },
        },
    };
}

export function parsePreviewResponse(
    value: unknown
): StreamingPortabilityPreviewResponse | null {
    if (!isPlainRecord(value)) return null;
    if (value.mode !== 'merge' && value.mode !== 'replace') return null;
    if (!isHexSha256(value.archiveSha256) || !isHexSha256(value.previewSha256)) return null;
    if (typeof value.expiresAt !== 'string' || value.expiresAt.length === 0) return null;
    if (typeof value.approvalToken !== 'string' || value.approvalToken.trim().length === 0) {
        return null;
    }
    const archiveCounts = parseRecordCounts(value.archiveCounts);
    const targetCounts = parseRecordCounts(value.targetCounts);
    const plan = parsePlanCounts(value.plan);
    if (!archiveCounts || !targetCounts || !plan) return null;

    let replacementCounts: StreamingPortabilityRecordCounts | null = null;
    if (value.replacementCounts !== null && value.replacementCounts !== undefined) {
        replacementCounts = parseRecordCounts(value.replacementCounts);
        if (!replacementCounts) return null;
    }

    let replacementNotice: string | null = null;
    if (value.replacementNotice !== null && value.replacementNotice !== undefined) {
        if (typeof value.replacementNotice !== 'string') return null;
        replacementNotice = value.replacementNotice;
    }

    if (!Array.isArray(value.conflicts)) return null;
    const conflicts: StreamingPortabilityConflict[] = [];
    for (const rawConflict of value.conflicts) {
        const parsedConflict = parseConflict(rawConflict);
        if (!parsedConflict) return null;
        conflicts.push(parsedConflict);
    }

    return {
        mode: value.mode,
        archiveSha256: value.archiveSha256.toLowerCase(),
        previewSha256: value.previewSha256.toLowerCase(),
        expiresAt: value.expiresAt,
        archiveCounts,
        targetCounts,
        plan,
        replacementCounts,
        replacementNotice,
        conflicts,
        approvalToken: value.approvalToken,
    };
}

export function parseRestoreResponse(
    value: unknown
): StreamingPortabilityRestoreResponse | null {
    if (!isPlainRecord(value)) return null;
    if (value.mode !== 'merge' && value.mode !== 'replace') return null;
    if (!isHexSha256(value.archiveSha256) || !isHexSha256(value.previewSha256)) return null;
    if (typeof value.backupVerified !== 'boolean') return null;
    const archiveCounts = parseRecordCounts(value.archiveCounts);
    const resultingCounts = parseRecordCounts(value.resultingCounts);
    const plan = parsePlanCounts(value.plan);
    if (!archiveCounts || !resultingCounts || !plan) return null;

    if (!Array.isArray(value.conflicts)) return null;
    const conflicts: StreamingPortabilityConflict[] = [];
    for (const rawConflict of value.conflicts) {
        const parsedConflict = parseConflict(rawConflict);
        if (!parsedConflict) return null;
        conflicts.push(parsedConflict);
    }

    return {
        mode: value.mode,
        archiveSha256: value.archiveSha256.toLowerCase(),
        previewSha256: value.previewSha256.toLowerCase(),
        backupVerified: value.backupVerified,
        archiveCounts,
        resultingCounts,
        plan,
        conflicts,
    };
}

function parseFilenameFromContentDisposition(headerValue: string | null): string | null {
    if (!headerValue) return null;
    const match = /filename="?([^";\r\n]+)"?/i.exec(headerValue);
    if (!match || !match[1]) return null;
    const sanitized = match[1].trim();
    return sanitized.length > 0 ? sanitized : null;
}

async function readResponseErrorDetails(
    res: Response,
    fallbackMessage: string
): Promise<{ code: string | null; message: string }> {
    try {
        const text = await res.text();
        if (!text) return { code: null, message: fallbackMessage };
        const parsed: unknown = JSON.parse(text);
        if (isPlainRecord(parsed)) {
            if (isPlainRecord(parsed.error)) {
                const nestedCode =
                    typeof parsed.error.code === 'string' ? parsed.error.code : null;
                const nestedMsg =
                    typeof parsed.error.message === 'string' && parsed.error.message.trim().length > 0
                        ? parsed.error.message
                        : fallbackMessage;
                return { code: nestedCode, message: nestedMsg };
            }
            const directCode = typeof parsed.code === 'string' ? parsed.code : null;
            const directMsg =
                typeof parsed.message === 'string' && parsed.message.trim().length > 0
                    ? parsed.message
                    : fallbackMessage;
            return { code: directCode, message: directMsg };
        }
    } catch {
        return { code: null, message: fallbackMessage };
    }
    return { code: null, message: fallbackMessage };
}

async function readFileAsTextBounded(file: File, maxBytes: number): Promise<string> {
    if (file.size > maxBytes) {
        throw new Error(
            `Archive file (${file.size.toLocaleString()} bytes) exceeds the ${maxBytes.toLocaleString()}-byte (8 MiB) limit.`
        );
    }
    if (typeof file.text === 'function') {
        const text = await file.text();
        if (utf8ByteLength(text) > maxBytes) {
            throw new Error(
                `Archive content exceeds the ${maxBytes.toLocaleString()}-byte (8 MiB) limit.`
            );
        }
        return text;
    }
    return new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
            const result = typeof reader.result === 'string' ? reader.result : '';
            if (utf8ByteLength(result) > maxBytes) {
                reject(
                    new Error(
                        `Archive content exceeds the ${maxBytes.toLocaleString()}-byte (8 MiB) limit.`
                    )
                );
                return;
            }
            resolve(result);
        };
        reader.onerror = () => {
            reject(new Error('Failed to read the selected archive file.'));
        };
        reader.readAsText(file);
    });
}

function CountsBreakdownCard({
    title,
    counts,
    testIdPrefix,
    accentClass,
}: {
    title: string;
    counts: StreamingPortabilityRecordCounts;
    testIdPrefix: string;
    accentClass: string;
}) {
    const total = sumRecordCounts(counts);
    return (
        <div
            data-testid={`${testIdPrefix}-card`}
            className={`rounded-xl border p-3.5 space-y-2 ${accentClass}`}
        >
            <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                    {title}
                </span>
                <span
                    data-testid={`${testIdPrefix}-total`}
                    className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-white/[0.06] text-slate-100 tabular-nums"
                >
                    {total.toLocaleString()} total
                </span>
            </div>
            <dl className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs">
                <div className="rounded-lg bg-black/25 px-2.5 py-1.5 border border-white/[0.05]">
                    <dt className="text-slate-400">History</dt>
                    <dd
                        data-testid={`${testIdPrefix}-history`}
                        className="font-mono font-bold text-slate-100 tabular-nums"
                    >
                        {counts.history.toLocaleString()}
                    </dd>
                </div>
                <div className="rounded-lg bg-black/25 px-2.5 py-1.5 border border-white/[0.05]">
                    <dt className="text-slate-400">Labels</dt>
                    <dd
                        data-testid={`${testIdPrefix}-labels`}
                        className="font-mono font-bold text-slate-100 tabular-nums"
                    >
                        {counts.labels.toLocaleString()}
                    </dd>
                </div>
                <div className="rounded-lg bg-black/25 px-2.5 py-1.5 border border-white/[0.05]">
                    <dt className="text-slate-400">Session Samples</dt>
                    <dd
                        data-testid={`${testIdPrefix}-session-samples`}
                        className="font-mono font-bold text-slate-100 tabular-nums"
                    >
                        {counts.sessionSamples.toLocaleString()}
                    </dd>
                </div>
                <div className="rounded-lg bg-black/25 px-2.5 py-1.5 border border-white/[0.05]">
                    <dt className="text-slate-400">Bandwidth</dt>
                    <dd
                        data-testid={`${testIdPrefix}-bandwidth-samples`}
                        className="font-mono font-bold text-slate-100 tabular-nums"
                    >
                        {counts.bandwidthSamples.toLocaleString()}
                    </dd>
                </div>
                <div className="rounded-lg bg-black/25 px-2.5 py-1.5 border border-white/[0.05]">
                    <dt className="text-slate-400">Policies</dt>
                    <dd
                        data-testid={`${testIdPrefix}-tracking-policies`}
                        className="font-mono font-bold text-slate-100 tabular-nums"
                    >
                        {counts.trackingPolicies.toLocaleString()}
                    </dd>
                </div>
            </dl>
        </div>
    );
}

export default function StreamingPortability({
    initialMode = 'merge',
    onRestoreApplied,
}: StreamingPortabilityProps = {}) {
    const { user, isAuthenticated, isLoading: authLoading } = useAuth();
    const { addToast } = useToast();

    const isAdmin = Boolean(isAuthenticated && user?.role === 'admin');

    const [mode, setMode] = useState<StreamingRestoreMode>(initialMode);
    const [selectedArchive, setSelectedArchive] = useState<ValidatedArchiveSelection | null>(null);
    const [fileError, setFileError] = useState<string | null>(null);
    const [isReadingFile, setIsReadingFile] = useState(false);

    const [isExporting, setIsExporting] = useState(false);
    const [exportError, setExportError] = useState<string | null>(null);
    const [lastExportedArchiveSha256, setLastExportedArchiveSha256] = useState<string | null>(null);

    const [isPreviewing, setIsPreviewing] = useState(false);
    const [previewError, setPreviewError] = useState<string | null>(null);
    const [previewData, setPreviewData] = useState<StreamingPortabilityPreviewResponse | null>(
        null
    );
    const [previewContext, setPreviewContext] = useState<{
        fileKey: string;
        archiveSha256: string;
        mode: StreamingRestoreMode;
    } | null>(null);

    const [isApproved, setIsApproved] = useState(false);
    const [isRestoring, setIsRestoring] = useState(false);
    const [restoreError, setRestoreError] = useState<string | null>(null);
    const [staleConflictMessage, setStaleConflictMessage] = useState<string | null>(null);
    const [restoreResult, setRestoreResult] = useState<StreamingPortabilityRestoreResponse | null>(
        null
    );

    const mountedRef = useRef(true);
    const fileGenRef = useRef(0);
    const exportGenRef = useRef(0);
    const operationGenRef = useRef(0);
    const exportAbortRef = useRef<AbortController | null>(null);
    const previewAbortRef = useRef<AbortController | null>(null);
    const restoreAbortRef = useRef<AbortController | null>(null);

    const abortPendingPreviewAndRestore = useCallback(() => {
        operationGenRef.current += 1;
        if (previewAbortRef.current) {
            previewAbortRef.current.abort();
            previewAbortRef.current = null;
        }
        if (restoreAbortRef.current) {
            restoreAbortRef.current.abort();
            restoreAbortRef.current = null;
        }
    }, []);

    const resetPreviewAndApprovalState = useCallback(() => {
        abortPendingPreviewAndRestore();
        setIsPreviewing(false);
        setIsRestoring(false);
        setPreviewData(null);
        setPreviewContext(null);
        setIsApproved(false);
        setPreviewError(null);
        setRestoreError(null);
    }, [abortPendingPreviewAndRestore]);

    useEffect(() => {
        mountedRef.current = true;
        return () => {
            mountedRef.current = false;
            fileGenRef.current += 1;
            exportGenRef.current += 1;
            operationGenRef.current += 1;
            if (exportAbortRef.current) {
                exportAbortRef.current.abort();
                exportAbortRef.current = null;
            }
            if (previewAbortRef.current) {
                previewAbortRef.current.abort();
                previewAbortRef.current = null;
            }
            if (restoreAbortRef.current) {
                restoreAbortRef.current.abort();
                restoreAbortRef.current = null;
            }
        };
    }, []);

    const handleModeChange = useCallback(
        (nextMode: StreamingRestoreMode) => {
            if (nextMode === mode) return;
            setMode(nextMode);
            setStaleConflictMessage(null);
            setRestoreResult(null);
            resetPreviewAndApprovalState();
        },
        [mode, resetPreviewAndApprovalState]
    );

    const handleFileChange = useCallback(
        async (event: React.ChangeEvent<HTMLInputElement>) => {
            const file = event.target.files?.[0] ?? null;
            resetPreviewAndApprovalState();
            setStaleConflictMessage(null);
            setRestoreResult(null);
            setSelectedArchive(null);
            setFileError(null);

            if (!file) {
                setIsReadingFile(false);
                return;
            }

            const currentFileGen = ++fileGenRef.current;
            setIsReadingFile(true);

            if (file.size > MAX_STREAMING_ARCHIVE_BYTES) {
                const sizeMsg = `Archive file "${file.name}" (${file.size.toLocaleString()} bytes) exceeds the maximum allowed size of ${MAX_STREAMING_ARCHIVE_BYTES.toLocaleString()} bytes (8 MiB).`;
                setIsReadingFile(false);
                setFileError(sizeMsg);
                addToast(sizeMsg, 'error');
                return;
            }

            try {
                const rawText = await readFileAsTextBounded(file, MAX_STREAMING_ARCHIVE_BYTES);
                if (!mountedRef.current || currentFileGen !== fileGenRef.current) return;

                const byteLength = utf8ByteLength(rawText);
                if (byteLength > MAX_STREAMING_ARCHIVE_BYTES) {
                    const sizeMsg = `Archive file "${file.name}" (${byteLength.toLocaleString()} bytes) exceeds the maximum allowed size of ${MAX_STREAMING_ARCHIVE_BYTES.toLocaleString()} bytes (8 MiB).`;
                    setFileError(sizeMsg);
                    addToast(sizeMsg, 'error');
                    return;
                }

                let parsedJson: unknown;
                try {
                    parsedJson = JSON.parse(rawText);
                } catch {
                    const jsonMsg = `Selected file "${file.name}" is not valid JSON.`;
                    setFileError(jsonMsg);
                    addToast(jsonMsg, 'error');
                    return;
                }

                const validation = parseStreamingArchive(parsedJson);
                if (!validation.ok) {
                    setFileError(validation.error);
                    addToast(validation.error, 'error');
                    return;
                }

                const fileKey = `${file.name}:${byteLength}:${file.lastModified}:${validation.archive.manifest.sha256}`;
                setSelectedArchive({
                    fileKey,
                    fileName: file.name,
                    byteLength,
                    archive: validation.archive,
                });
            } catch (err: unknown) {
                if (!mountedRef.current || currentFileGen !== fileGenRef.current) return;
                const msg =
                    err instanceof Error
                        ? err.message
                        : 'Failed to read or validate the selected archive file.';
                setFileError(msg);
                addToast(msg, 'error');
            } finally {
                if (mountedRef.current && currentFileGen === fileGenRef.current) {
                    setIsReadingFile(false);
                }
            }
        },
        [addToast, resetPreviewAndApprovalState]
    );

    const handleExportArchive = useCallback(async () => {
        if (!isAdmin || isExporting) return;

        if (exportAbortRef.current) {
            exportAbortRef.current.abort();
        }
        const controller = new AbortController();
        exportAbortRef.current = controller;
        const currentExportGen = ++exportGenRef.current;

        setIsExporting(true);
        setExportError(null);

        try {
            const res = await apiFetch(STREAMING_PORTABILITY_EXPORT_URL, {
                method: 'GET',
                signal: controller.signal,
            });

            if (
                !mountedRef.current ||
                controller.signal.aborted ||
                currentExportGen !== exportGenRef.current
            ) {
                return;
            }

            if (!res.ok) {
                const { message } = await readResponseErrorDetails(
                    res,
                    `Failed to export streaming portability archive (HTTP ${res.status}).`
                );
                if (!mountedRef.current || currentExportGen !== exportGenRef.current) return;
                setExportError(message);
                addToast(message, 'error');
                return;
            }

            const rawText = await res.text();
            if (
                !mountedRef.current ||
                controller.signal.aborted ||
                currentExportGen !== exportGenRef.current
            ) {
                return;
            }

            const byteLength = utf8ByteLength(rawText);
            if (byteLength > MAX_STREAMING_ARCHIVE_BYTES) {
                const tooLargeMsg = `Exported archive (${byteLength.toLocaleString()} bytes) exceeds the 8 MiB limit.`;
                setExportError(tooLargeMsg);
                addToast(tooLargeMsg, 'error');
                return;
            }

            let parsedJson: unknown;
            try {
                parsedJson = JSON.parse(rawText);
            } catch {
                const invalidJsonMsg = 'Export response is not valid JSON.';
                setExportError(invalidJsonMsg);
                addToast(invalidJsonMsg, 'error');
                return;
            }

            const validation = parseStreamingArchive(parsedJson);
            if (!validation.ok) {
                setExportError(validation.error);
                addToast(validation.error, 'error');
                return;
            }

            const serialized = JSON.stringify(parsedJson);
            if (utf8ByteLength(serialized) > MAX_STREAMING_ARCHIVE_BYTES) {
                throw new Error('Exported archive exceeds the 8 MiB restore limit.');
            }
            const filename =
                parseFilenameFromContentDisposition(res.headers.get('Content-Disposition')) ||
                'streaming-history-backup.json';

            if (typeof URL.createObjectURL === 'function') {
                const blob = new Blob([serialized], { type: 'application/json;charset=utf-8' });
                const objectUrl = URL.createObjectURL(blob);
                try {
                    const anchor = document.createElement('a');
                    anchor.href = objectUrl;
                    anchor.download = filename;
                    anchor.style.display = 'none';
                    document.body.appendChild(anchor);
                    anchor.click();
                    document.body.removeChild(anchor);
                } finally {
                    if (typeof URL.revokeObjectURL === 'function') {
                        URL.revokeObjectURL(objectUrl);
                    }
                }
            }

            setLastExportedArchiveSha256(validation.archive.manifest.sha256);
            addToast(`Exported portable streaming archive (${filename}).`, 'success');
        } catch (err: unknown) {
            if (
                !mountedRef.current ||
                controller.signal.aborted ||
                isAbortError(err) ||
                currentExportGen !== exportGenRef.current
            ) {
                return;
            }
            const msg =
                err instanceof Error
                    ? err.message
                    : 'Failed to export portable streaming archive.';
            setExportError(msg);
            addToast(msg, 'error');
        } finally {
            if (exportAbortRef.current === controller) {
                exportAbortRef.current = null;
            }
            if (mountedRef.current && currentExportGen === exportGenRef.current) {
                setIsExporting(false);
            }
        }
    }, [addToast, isAdmin, isExporting]);

    const handlePreviewRestore = useCallback(async () => {
        if (!isAdmin || !selectedArchive || isPreviewing || isRestoring) return;

        abortPendingPreviewAndRestore();
        const controller = new AbortController();
        previewAbortRef.current = controller;
        const currentOpGen = ++operationGenRef.current;

        const targetArchive = selectedArchive.archive;
        const targetFileKey = selectedArchive.fileKey;
        const targetMode = mode;

        setIsPreviewing(true);
        setPreviewError(null);
        setRestoreError(null);
        setStaleConflictMessage(null);
        setRestoreResult(null);
        setPreviewData(null);
        setPreviewContext(null);
        setIsApproved(false);

        const payload: StreamingPortabilityPreviewRequest = {
            archive: targetArchive,
            mode: targetMode,
        };

        try {
            const res = await apiFetch(STREAMING_PORTABILITY_PREVIEW_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
                signal: controller.signal,
            });

            if (
                !mountedRef.current ||
                controller.signal.aborted ||
                currentOpGen !== operationGenRef.current
            ) {
                return;
            }

            if (!res.ok) {
                const { message } = await readResponseErrorDetails(
                    res,
                    `Failed to preview streaming archive restore (HTTP ${res.status}).`
                );
                if (!mountedRef.current || currentOpGen !== operationGenRef.current) return;
                setPreviewError(message);
                addToast(message, 'error');
                return;
            }

            let rawBody: unknown;
            try {
                rawBody = await res.json();
            } catch {
                const parseErr = 'Preview response body is not valid JSON.';
                setPreviewError(parseErr);
                addToast(parseErr, 'error');
                return;
            }

            if (
                !mountedRef.current ||
                controller.signal.aborted ||
                currentOpGen !== operationGenRef.current
            ) {
                return;
            }

            const validatedPreview = parsePreviewResponse(rawBody);
            if (!validatedPreview) {
                const contractErr =
                    'Preview response did not match the canonical streaming portability contract.';
                setPreviewError(contractErr);
                addToast(contractErr, 'error');
                return;
            }

            if (
                validatedPreview.mode !== targetMode ||
                validatedPreview.archiveSha256 !== targetArchive.manifest.sha256.toLowerCase()
            ) {
                const mismatchErr =
                    'Preview response mode or archive SHA-256 did not match the requested archive.';
                setPreviewError(mismatchErr);
                addToast(mismatchErr, 'error');
                return;
            }

            setPreviewData(validatedPreview);
            setPreviewContext({
                fileKey: targetFileKey,
                archiveSha256: validatedPreview.archiveSha256,
                mode: validatedPreview.mode,
            });
            setIsApproved(false);
            addToast(
                'Restore preview generated. Review the plan and explicitly approve before applying.',
                'info'
            );
        } catch (err: unknown) {
            if (
                !mountedRef.current ||
                controller.signal.aborted ||
                isAbortError(err) ||
                currentOpGen !== operationGenRef.current
            ) {
                return;
            }
            const msg =
                err instanceof Error ? err.message : 'Restore preview request failed.';
            setPreviewError(msg);
            addToast(msg, 'error');
        } finally {
            if (previewAbortRef.current === controller) {
                previewAbortRef.current = null;
            }
            if (mountedRef.current && currentOpGen === operationGenRef.current) {
                setIsPreviewing(false);
            }
        }
    }, [
        abortPendingPreviewAndRestore,
        addToast,
        isAdmin,
        isPreviewing,
        isRestoring,
        mode,
        selectedArchive,
    ]);

    const isPreviewBoundToCurrentSelection = Boolean(
        previewData &&
            previewContext &&
            selectedArchive &&
            previewContext.fileKey === selectedArchive.fileKey &&
            previewContext.archiveSha256 ===
                selectedArchive.archive.manifest.sha256.toLowerCase() &&
            previewContext.mode === mode &&
            previewData.mode === mode &&
            previewData.archiveSha256 === selectedArchive.archive.manifest.sha256.toLowerCase()
    );

    const handleApplyRestore = useCallback(async () => {
        if (
            !isAdmin ||
            !selectedArchive ||
            !previewData ||
            !isPreviewBoundToCurrentSelection ||
            !isApproved ||
            isRestoring ||
            isPreviewing
        ) {
            return;
        }

        abortPendingPreviewAndRestore();
        const controller = new AbortController();
        restoreAbortRef.current = controller;
        const currentOpGen = ++operationGenRef.current;

        const approvedArchive = selectedArchive.archive;
        const approvedMode = previewData.mode;
        const approvedToken = previewData.approvalToken;

        setIsRestoring(true);
        setRestoreError(null);
        setStaleConflictMessage(null);

        const payload: StreamingPortabilityRestoreRequest = {
            archive: approvedArchive,
            mode: approvedMode,
            approvalToken: approvedToken,
        };

        try {
            const res = await apiFetch(STREAMING_PORTABILITY_RESTORE_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
                signal: controller.signal,
            });

            if (
                !mountedRef.current ||
                controller.signal.aborted ||
                currentOpGen !== operationGenRef.current
            ) {
                return;
            }

            if (res.status === 409) {
                const { message } = await readResponseErrorDetails(
                    res,
                    'Streaming data or approval state changed after preview (HTTP 409). Please run a new preview and re-approve before restoring.'
                );
                if (!mountedRef.current || currentOpGen !== operationGenRef.current) return;
                setPreviewData(null);
                setPreviewContext(null);
                setIsApproved(false);
                setStaleConflictMessage(message);
                setRestoreError(message);
                addToast(message, 'error');
                return;
            }

            if (!res.ok) {
                const { message } = await readResponseErrorDetails(
                    res,
                    `Failed to apply streaming archive restore (HTTP ${res.status}).`
                );
                if (!mountedRef.current || currentOpGen !== operationGenRef.current) return;
                setPreviewData(null);
                setPreviewContext(null);
                setIsApproved(false);
                setRestoreError(message);
                addToast(message, 'error');
                return;
            }

            let rawBody: unknown;
            try {
                rawBody = await res.json();
            } catch {
                const parseErr = 'Restore response body is not valid JSON.';
                setPreviewData(null);
                setPreviewContext(null);
                setIsApproved(false);
                setRestoreError(parseErr);
                addToast(parseErr, 'error');
                return;
            }

            if (
                !mountedRef.current ||
                controller.signal.aborted ||
                currentOpGen !== operationGenRef.current
            ) {
                return;
            }

            const validatedRestore = parseRestoreResponse(rawBody);
            if (!validatedRestore) {
                const contractErr =
                    'Restore response did not match the canonical streaming portability contract.';
                setPreviewData(null);
                setPreviewContext(null);
                setIsApproved(false);
                setRestoreError(contractErr);
                addToast(contractErr, 'error');
                return;
            }

            setPreviewData(null);
            setPreviewContext(null);
            setIsApproved(false);
            setRestoreResult(validatedRestore);
            if (onRestoreApplied) {
                onRestoreApplied(validatedRestore);
            }
            addToast(
                `Streaming archive ${validatedRestore.mode} restore completed with verified backup.`,
                'success'
            );
        } catch (err: unknown) {
            if (
                !mountedRef.current ||
                controller.signal.aborted ||
                isAbortError(err) ||
                currentOpGen !== operationGenRef.current
            ) {
                return;
            }
            const msg = err instanceof Error ? err.message : 'Restore operation failed.';
            setPreviewData(null);
            setPreviewContext(null);
            setIsApproved(false);
            setRestoreError(msg);
            addToast(msg, 'error');
        } finally {
            if (restoreAbortRef.current === controller) {
                restoreAbortRef.current = null;
            }
            if (mountedRef.current && currentOpGen === operationGenRef.current) {
                setIsRestoring(false);
            }
        }
    }, [
        abortPendingPreviewAndRestore,
        addToast,
        isAdmin,
        isApproved,
        isPreviewBoundToCurrentSelection,
        isPreviewing,
        isRestoring,
        onRestoreApplied,
        previewData,
        selectedArchive,
    ]);

    if (authLoading) {
        return (
            <section
                aria-label="Streaming History Portability"
                data-testid="streaming-portability-loading"
                className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 w-full min-w-0 max-w-full"
            >
                <div className="flex items-center gap-2.5 text-xs text-slate-300">
                    <Loader2 size={15} className="animate-spin text-indigo-400" />
                    <span>Verifying administrative permissions for streaming portability...</span>
                </div>
            </section>
        );
    }

    if (!isAdmin) {
        return (
            <section
                aria-label="Streaming History Portability"
                data-testid="streaming-portability-admin-boundary"
                className="rounded-2xl border border-amber-500/25 bg-amber-950/20 backdrop-blur-xl p-5 w-full min-w-0 max-w-full"
            >
                <div className="flex items-start gap-3">
                    <Lock size={18} className="text-amber-400 shrink-0 mt-0.5" />
                    <div className="space-y-1 min-w-0">
                        <h3 className="text-sm font-bold text-amber-200">
                            Administrative Access Required
                        </h3>
                        <p className="text-xs text-amber-100/80">
                            Streaming history portability export, dry-run restore preview, and
                            database restore are restricted to administrators. Non-admin sessions
                            cannot export or modify the portable streaming archive.
                        </p>
                    </div>
                </div>
            </section>
        );
    }

    const canPreview = Boolean(selectedArchive && !isReadingFile && !isPreviewing && !isRestoring);
    const canApplyRestore = Boolean(
        isPreviewBoundToCurrentSelection &&
            previewData &&
            isApproved &&
            !isPreviewing &&
            !isRestoring
    );

    return (
        <section
            aria-label="Streaming History Portability"
            data-testid="streaming-portability"
            className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 space-y-5 w-full min-w-0 max-w-full"
        >
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-white/[0.06]">
                <div className="space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2.5">
                        <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                            <Archive size={18} className="text-indigo-400 shrink-0" />
                            <span>Streaming History Portability &amp; Verified Restore</span>
                        </h3>
                        <span
                            data-testid="portability-admin-badge"
                            className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-purple-500/15 text-purple-300 border border-purple-500/30 inline-flex items-center gap-1.5"
                        >
                            <ShieldCheck size={12} />
                            <span>Admin Only</span>
                        </span>
                        <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-white/[0.06] border border-white/10 text-slate-300">
                            {STREAMING_ARCHIVE_FORMAT} v{STREAMING_ARCHIVE_FORMAT_VERSION} (schema v
                            {STREAMING_DATABASE_SCHEMA_VERSION})
                        </span>
                    </div>
                    <p className="text-xs text-slate-400">
                        Export a privacy-redacted versioned JSON archive (&le;8 MiB, &le;10,000
                        portable rows) or run a mandatory dry-run preview before explicitly
                        approving a Merge or Replace restore.
                    </p>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0">
                    <button
                        type="button"
                        onClick={() => void handleExportArchive()}
                        disabled={isExporting || isPreviewing || isRestoring}
                        data-testid="portability-export-btn"
                        className="px-3.5 py-2 rounded-xl text-xs font-bold bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white shadow-md shadow-indigo-500/20 flex items-center gap-1.5 transition-all"
                    >
                        {isExporting ? (
                            <Loader2 size={14} className="animate-spin" />
                        ) : (
                            <Download size={14} />
                        )}
                        <span>
                            {isExporting ? 'Exporting Archive...' : 'Download Portable JSON Archive'}
                        </span>
                    </button>
                </div>
            </div>

            {exportError && (
                <div
                    role="alert"
                    data-testid="portability-export-error"
                    className="px-3.5 py-2.5 rounded-xl border border-rose-500/30 bg-rose-950/30 text-xs text-rose-200 flex items-start gap-2.5"
                >
                    <AlertCircle size={15} className="text-rose-400 shrink-0 mt-0.5" />
                    <div className="min-w-0">
                        <strong className="font-bold">Export Failed:</strong> {exportError}
                    </div>
                </div>
            )}

            {lastExportedArchiveSha256 && (
                <div
                    data-testid="portability-export-success"
                    className="px-3.5 py-2.5 rounded-xl border border-emerald-500/25 bg-emerald-950/20 text-xs text-emerald-200 flex items-start gap-2.5"
                >
                    <CheckCircle2 size={15} className="text-emerald-400 shrink-0 mt-0.5" />
                    <div className="min-w-0 break-all">
                        <strong className="font-bold">Archive Exported:</strong> SHA-256{' '}
                        <code
                            data-testid="portability-exported-sha256"
                            className="font-mono text-emerald-100"
                        >
                            {lastExportedArchiveSha256}
                        </code>
                    </div>
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-4 space-y-3 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                        <label
                            htmlFor="streaming-portability-file-input"
                            className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5"
                        >
                            <FileJson size={14} className="text-indigo-400" />
                            <span>1. Select Portable Archive File (&le;8 MiB)</span>
                        </label>
                        <span className="text-xs font-mono text-slate-400">
                            Max {(MAX_STREAMING_ARCHIVE_BYTES / (1024 * 1024)).toFixed(0)} MiB
                        </span>
                    </div>

                    <input
                        id="streaming-portability-file-input"
                        data-testid="portability-file-input"
                        type="file"
                        accept=".json,application/json"
                        onChange={(e) => void handleFileChange(e)}
                        disabled={isPreviewing || isRestoring}
                        className="block w-full text-xs text-slate-300 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border file:border-white/10 file:text-xs file:font-semibold file:bg-white/[0.06] file:text-slate-100 hover:file:bg-white/[0.1] cursor-pointer"
                    />

                    {isReadingFile && (
                        <div
                            data-testid="portability-file-reading"
                            className="flex items-center gap-2 text-xs text-slate-300"
                        >
                            <Loader2 size={14} className="animate-spin text-indigo-400" />
                            <span>Validating archive manifest and row counts...</span>
                        </div>
                    )}

                    {fileError && (
                        <div
                            role="alert"
                            data-testid="portability-file-error"
                            className="px-3 py-2 rounded-lg border border-rose-500/30 bg-rose-950/30 text-xs text-rose-200 flex items-start gap-2"
                        >
                            <AlertCircle size={14} className="text-rose-400 shrink-0 mt-0.5" />
                            <span className="min-w-0 break-words">{fileError}</span>
                        </div>
                    )}

                    {selectedArchive && (
                        <div
                            data-testid="portability-selected-archive-summary"
                            className="rounded-lg border border-indigo-500/25 bg-indigo-950/20 p-3 space-y-1.5 text-xs"
                        >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                                <span
                                    data-testid="portability-selected-filename"
                                    className="font-bold text-indigo-200 truncate"
                                >
                                    {selectedArchive.fileName}
                                </span>
                                <span
                                    data-testid="portability-selected-bytes"
                                    className="font-mono text-slate-300"
                                >
                                    {selectedArchive.byteLength.toLocaleString()} bytes
                                </span>
                            </div>
                            <div className="text-slate-300 break-all">
                                <span className="text-slate-400">Manifest SHA-256: </span>
                                <code
                                    data-testid="portability-selected-manifest-sha256"
                                    className="font-mono text-indigo-100"
                                >
                                    {selectedArchive.archive.manifest.sha256}
                                </code>
                            </div>
                            <div className="flex flex-wrap items-center gap-3 text-slate-300">
                                <span>
                                    Exported:{' '}
                                    <code className="font-mono text-slate-200">
                                        {selectedArchive.archive.manifest.exportedAt}
                                    </code>
                                </span>
                                <span>
                                    Total Rows:{' '}
                                    <strong className="font-mono text-slate-100">
                                        {sumRecordCounts(
                                            selectedArchive.archive.manifest.recordCounts
                                        ).toLocaleString()}
                                    </strong>
                                </span>
                            </div>
                        </div>
                    )}
                </div>

                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-4 space-y-3 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                            2. Select Restore Mode &amp; Generate Dry-Run Preview
                        </span>
                    </div>

                    <div
                        role="radiogroup"
                        aria-label="Restore Mode"
                        className="grid grid-cols-1 sm:grid-cols-2 gap-2.5"
                    >
                        <button
                            type="button"
                            role="radio"
                            aria-checked={mode === 'merge'}
                            data-testid="portability-mode-merge-btn"
                            onClick={() => handleModeChange('merge')}
                            disabled={isPreviewing || isRestoring}
                            className={`p-3 rounded-xl border text-left transition-all space-y-1 ${
                                mode === 'merge'
                                    ? 'border-indigo-500/60 bg-indigo-500/15 text-slate-100'
                                    : 'border-white/10 bg-white/[0.03] text-slate-300 hover:bg-white/[0.06]'
                            }`}
                        >
                            <div className="flex items-center gap-1.5 text-xs font-bold">
                                <GitMerge size={14} className="text-indigo-400 shrink-0" />
                                <span>Merge Mode (Non-Destructive)</span>
                            </div>
                            <p className="text-xs text-slate-400">
                                Inserts non-colliding records, skips exact duplicates, and reports
                                identity collisions without deleting existing history.
                            </p>
                        </button>

                        <button
                            type="button"
                            role="radio"
                            aria-checked={mode === 'replace'}
                            data-testid="portability-mode-replace-btn"
                            onClick={() => handleModeChange('replace')}
                            disabled={isPreviewing || isRestoring}
                            className={`p-3 rounded-xl border text-left transition-all space-y-1 ${
                                mode === 'replace'
                                    ? 'border-amber-500/60 bg-amber-500/15 text-slate-100'
                                    : 'border-white/10 bg-white/[0.03] text-slate-300 hover:bg-white/[0.06]'
                            }`}
                        >
                            <div className="flex items-center gap-1.5 text-xs font-bold">
                                <Replace size={14} className="text-amber-400 shrink-0" />
                                <span>Replace Mode (Destructive)</span>
                            </div>
                            <p className="text-xs text-slate-400">
                                Replaces destination portable history, labels, samples, and tracking
                                policy after creating a verified private database backup.
                            </p>
                        </button>
                    </div>

                    {mode === 'replace' && (
                        <div
                            role="note"
                            data-testid="portability-replace-warning"
                            className="px-3.5 py-2.5 rounded-xl border border-amber-500/40 bg-amber-950/30 text-xs text-amber-100 flex items-start gap-2.5"
                        >
                            <AlertTriangle size={16} className="text-amber-400 shrink-0 mt-0.5" />
                            <div className="space-y-1 min-w-0">
                                <strong className="font-bold block text-amber-200">
                                    Replacement Data-Loss Warning:
                                </strong>
                                <p>
                                    Replace mode deletes all existing destination rows in{' '}
                                    <code className="font-mono">streaming_history</code>,{' '}
                                    <code className="font-mono">streaming_history_labels</code>,{' '}
                                    <code className="font-mono">streaming_session_samples</code>,
                                    and{' '}
                                    <code className="font-mono">streaming_bandwidth_samples</code>{' '}
                                    before inserting the archive. Destination device names, device
                                    IDs, and IP addresses are permanently cleared because those
                                    fields are redacted from portable archives.
                                </p>
                            </div>
                        </div>
                    )}

                    <div className="pt-1 flex items-center justify-end">
                        <button
                            type="button"
                            onClick={() => void handlePreviewRestore()}
                            disabled={!canPreview}
                            data-testid="portability-preview-btn"
                            className="px-4 py-2 rounded-xl text-xs font-bold bg-sky-600 hover:bg-sky-500 disabled:opacity-40 disabled:cursor-not-allowed text-white shadow-md shadow-sky-500/20 flex items-center gap-1.5 transition-all"
                        >
                            {isPreviewing ? (
                                <Loader2 size={14} className="animate-spin" />
                            ) : (
                                <RefreshCw size={14} />
                            )}
                            <span>
                                {isPreviewing
                                    ? 'Computing Dry-Run Preview...'
                                    : `Preview ${mode === 'replace' ? 'Replace' : 'Merge'} Restore Plan`}
                            </span>
                        </button>
                    </div>
                </div>
            </div>

            {staleConflictMessage && (
                <div
                    role="alert"
                    data-testid="portability-stale-conflict-banner"
                    className="px-4 py-3 rounded-xl border border-amber-500/40 bg-amber-950/35 text-xs text-amber-100 flex items-start gap-3"
                >
                    <AlertTriangle size={16} className="text-amber-400 shrink-0 mt-0.5" />
                    <div className="space-y-1 min-w-0">
                        <strong className="font-bold block text-amber-200">
                            Preview Invalidated (HTTP 409 Conflict) — New Preview Required
                        </strong>
                        <p>{staleConflictMessage}</p>
                        <p className="text-amber-200/90">
                            Previous preview hashes and approval tokens have been cleared. Run a
                            fresh preview and re-approve to proceed.
                        </p>
                    </div>
                </div>
            )}

            {previewError && (
                <div
                    role="alert"
                    data-testid="portability-preview-error"
                    className="px-3.5 py-2.5 rounded-xl border border-rose-500/30 bg-rose-950/30 text-xs text-rose-200 flex items-start gap-2.5"
                >
                    <AlertCircle size={15} className="text-rose-400 shrink-0 mt-0.5" />
                    <div className="min-w-0">
                        <strong className="font-bold">Preview Failed:</strong> {previewError}
                    </div>
                </div>
            )}

            {restoreError && !staleConflictMessage && (
                <div
                    role="alert"
                    data-testid="portability-restore-error"
                    className="px-3.5 py-2.5 rounded-xl border border-rose-500/30 bg-rose-950/30 text-xs text-rose-200 flex items-start gap-2.5"
                >
                    <AlertCircle size={15} className="text-rose-400 shrink-0 mt-0.5" />
                    <div className="min-w-0">
                        <strong className="font-bold">Restore Failed:</strong> {restoreError}
                    </div>
                </div>
            )}

            {previewData && isPreviewBoundToCurrentSelection && (
                <div
                    data-testid="portability-preview-panel"
                    className="rounded-xl border border-sky-500/30 bg-slate-950/60 p-4 space-y-4 min-w-0"
                >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 pb-3 border-b border-white/[0.06]">
                        <div className="flex flex-wrap items-center gap-2">
                            <h4 className="text-sm font-bold text-slate-100">
                                Dry-Run Restore Preview ({previewData.mode.toUpperCase()})
                            </h4>
                            <span
                                data-testid="preview-mode-badge"
                                className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${
                                    previewData.mode === 'replace'
                                        ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                        : 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30'
                                }`}
                            >
                                {previewData.mode === 'replace' ? 'Replace Mode' : 'Merge Mode'}
                            </span>
                        </div>
                        <div className="text-xs text-slate-400">
                            Approval expires at:{' '}
                            <code
                                data-testid="preview-expires-at"
                                className="font-mono text-slate-200"
                            >
                                {previewData.expiresAt}
                            </code>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                        <div className="rounded-lg border border-white/[0.06] bg-black/30 p-3 space-y-1 min-w-0">
                            <span className="text-slate-400 font-semibold block">
                                Archive SHA-256 Digest
                            </span>
                            <code
                                data-testid="preview-archive-sha256"
                                className="font-mono text-sky-200 break-all block"
                            >
                                {previewData.archiveSha256}
                            </code>
                        </div>
                        <div className="rounded-lg border border-white/[0.06] bg-black/30 p-3 space-y-1 min-w-0">
                            <span className="text-slate-400 font-semibold block">
                                Preview Plan Fingerprint SHA-256
                            </span>
                            <code
                                data-testid="preview-fingerprint-sha256"
                                className="font-mono text-emerald-200 break-all block"
                            >
                                {previewData.previewSha256}
                            </code>
                        </div>
                    </div>

                    {previewData.replacementNotice && (
                        <div
                            data-testid="preview-replacement-notice"
                            className="px-3.5 py-2.5 rounded-xl border border-amber-500/35 bg-amber-950/30 text-xs text-amber-100 flex items-start gap-2.5"
                        >
                            <AlertTriangle size={15} className="text-amber-400 shrink-0 mt-0.5" />
                            <span className="min-w-0">{previewData.replacementNotice}</span>
                        </div>
                    )}

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                        <CountsBreakdownCard
                            title="Archive Source Counts"
                            counts={previewData.archiveCounts}
                            testIdPrefix="preview-archive-counts"
                            accentClass="border-white/[0.08] bg-black/20"
                        />
                        <CountsBreakdownCard
                            title="Destination Target Counts"
                            counts={previewData.targetCounts}
                            testIdPrefix="preview-target-counts"
                            accentClass="border-white/[0.08] bg-black/20"
                        />
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                        <CountsBreakdownCard
                            title="Planned Inserts"
                            counts={previewData.plan.insert}
                            testIdPrefix="preview-plan-insert"
                            accentClass="border-emerald-500/25 bg-emerald-950/15"
                        />
                        <CountsBreakdownCard
                            title="Exact Duplicates (Skipped)"
                            counts={previewData.plan.exactDuplicate}
                            testIdPrefix="preview-plan-duplicate"
                            accentClass="border-sky-500/25 bg-sky-950/15"
                        />
                        <CountsBreakdownCard
                            title="Conflicts (Skipped)"
                            counts={previewData.plan.conflict}
                            testIdPrefix="preview-plan-conflict"
                            accentClass="border-amber-500/25 bg-amber-950/15"
                        />
                    </div>

                    {previewData.replacementCounts && (
                        <CountsBreakdownCard
                            title="Destination Rows Replaced / Cleared"
                            counts={previewData.replacementCounts}
                            testIdPrefix="preview-replacement-counts"
                            accentClass="border-rose-500/30 bg-rose-950/20"
                        />
                    )}

                    <div className="space-y-2">
                        <div className="flex items-center justify-between">
                            <h5 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                                Detected Conflicts ({previewData.conflicts.length.toLocaleString()})
                            </h5>
                        </div>

                        {previewData.conflicts.length === 0 ? (
                            <p
                                data-testid="preview-no-conflicts"
                                className="text-xs text-slate-400 italic"
                            >
                                No row identity or policy conflicts detected in this preview.
                            </p>
                        ) : (
                            <div className="w-full min-w-0 max-w-full overflow-x-auto rounded-xl border border-white/[0.08]">
                                <table
                                    data-testid="preview-conflicts-table"
                                    className="w-full text-left border-collapse text-xs"
                                >
                                    <thead>
                                        <tr className="border-b border-white/[0.08] bg-white/[0.03] text-slate-300">
                                            <th className="py-2 px-3 font-semibold">Table</th>
                                            <th className="py-2 px-3 font-semibold">Archive Key</th>
                                            <th className="py-2 px-3 font-semibold">
                                                Existing Key
                                            </th>
                                            <th className="py-2 px-3 font-semibold">Reason</th>
                                            <th className="py-2 px-3 font-semibold">Action</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-white/[0.05]">
                                        {previewData.conflicts.map((item, idx) => (
                                            <tr
                                                key={`${item.table}:${item.archiveKey}:${idx}`}
                                                data-testid={`preview-conflict-row-${idx}`}
                                                className="text-slate-200"
                                            >
                                                <td className="py-2 px-3 font-mono">{item.table}</td>
                                                <td className="py-2 px-3 font-mono">
                                                    {item.archiveKey}
                                                </td>
                                                <td className="py-2 px-3 font-mono text-slate-400">
                                                    {item.existingKey ?? 'None'}
                                                </td>
                                                <td className="py-2 px-3 font-mono text-amber-300">
                                                    {item.reason}
                                                </td>
                                                <td className="py-2 px-3 font-mono uppercase">
                                                    {item.action}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>

                    <div className="pt-3 border-t border-white/[0.08] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                        <label
                            htmlFor="portability-approve-checkbox"
                            className="flex items-start gap-2.5 text-xs text-slate-200 cursor-pointer select-none"
                        >
                            <input
                                id="portability-approve-checkbox"
                                data-testid="portability-approve-checkbox"
                                type="checkbox"
                                checked={isApproved}
                                onChange={(e) => setIsApproved(e.target.checked)}
                                disabled={isRestoring || isPreviewing}
                                className="mt-0.5 rounded border-white/20 bg-slate-900 text-indigo-600 focus:ring-indigo-500"
                            />
                            <span>
                                I have reviewed the dry-run preview hashes, counts, and conflicts,
                                and explicitly approve applying this{' '}
                                <strong className="font-bold uppercase">{previewData.mode}</strong>{' '}
                                restore.
                            </span>
                        </label>

                        <button
                            type="button"
                            onClick={() => void handleApplyRestore()}
                            disabled={!canApplyRestore}
                            data-testid="portability-apply-restore-btn"
                            className={`px-4 py-2 rounded-xl text-xs font-bold text-white shadow-md flex items-center gap-1.5 transition-all shrink-0 disabled:opacity-40 disabled:cursor-not-allowed ${
                                previewData.mode === 'replace'
                                    ? 'bg-amber-600 hover:bg-amber-500 shadow-amber-500/20'
                                    : 'bg-emerald-600 hover:bg-emerald-500 shadow-emerald-500/20'
                            }`}
                        >
                            {isRestoring ? (
                                <Loader2 size={14} className="animate-spin" />
                            ) : (
                                <Upload size={14} />
                            )}
                            <span>
                                {isRestoring
                                    ? 'Applying Restore...'
                                    : `Apply Approved ${
                                          previewData.mode === 'replace' ? 'Replace' : 'Merge'
                                      } Restore`}
                            </span>
                        </button>
                    </div>
                </div>
            )}

            {restoreResult && (
                <div
                    data-testid="portability-restore-result"
                    className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-4 space-y-3"
                >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2 text-sm font-bold text-emerald-200">
                            <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
                            <span>
                                Restore Completed ({restoreResult.mode.toUpperCase()})
                            </span>
                        </div>
                        <span
                            data-testid="restore-backup-verified-badge"
                            className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/20 border border-emerald-500/30 text-emerald-200"
                        >
                            Backup Verified: {restoreResult.backupVerified ? 'Yes' : 'No'}
                        </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                        <div className="rounded-lg bg-black/30 p-2.5 border border-white/[0.06] break-all">
                            <span className="text-slate-400 block">Restored Archive SHA-256</span>
                            <code
                                data-testid="restore-result-archive-sha256"
                                className="font-mono text-emerald-100"
                            >
                                {restoreResult.archiveSha256}
                            </code>
                        </div>
                        <div className="rounded-lg bg-black/30 p-2.5 border border-white/[0.06] break-all">
                            <span className="text-slate-400 block">Applied Preview SHA-256</span>
                            <code
                                data-testid="restore-result-preview-sha256"
                                className="font-mono text-emerald-100"
                            >
                                {restoreResult.previewSha256}
                            </code>
                        </div>
                    </div>

                    <CountsBreakdownCard
                        title="Resulting Database Counts"
                        counts={restoreResult.resultingCounts}
                        testIdPrefix="restore-resulting-counts"
                        accentClass="border-emerald-500/25 bg-black/25"
                    />
                </div>
            )}
        </section>
    );
}
