import { TextEncoder, TextDecoder } from 'util';
import { readFileSync } from 'node:fs';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import StreamingPortability, {
    MAX_STREAMING_ARCHIVE_BYTES,
    STREAMING_ARCHIVE_FORMAT,
    STREAMING_ARCHIVE_FORMAT_VERSION,
    STREAMING_DATABASE_SCHEMA_VERSION,
    STREAMING_PORTABILITY_EXPORT_URL,
    STREAMING_PORTABILITY_PREVIEW_URL,
    STREAMING_PORTABILITY_RESTORE_URL,
    STREAMING_PROVENANCE_VERSION,
    StreamingArchive,
    StreamingPortabilityPreviewResponse,
    StreamingPortabilityRestoreResponse,
    parseStreamingArchive,
    parsePreviewResponse,
    parseRestoreResponse,
} from '@/components/streaming/StreamingPortability';
import { apiFetch } from '@/lib/fetcher';

Object.assign(globalThis, { TextEncoder, TextDecoder });

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

const mockAddToast = jest.fn();
jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
    }),
}));

let mockAuthUser: { id: number; username: string; role: string } | null = {
    id: 1,
    username: 'admin_operator',
    role: 'admin',
};
let mockAuthLoading = false;

jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => ({
        user: mockAuthUser,
        isAuthenticated: Boolean(mockAuthUser),
        isLoading: mockAuthLoading,
    }),
}));

const mockedApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;

const ARCHIVE_SHA_A = 'a'.repeat(64);
const ARCHIVE_SHA_B = 'b'.repeat(64);
const PREVIEW_SHA_MERGE = 'c'.repeat(64);
const PREVIEW_SHA_REPLACE = 'd'.repeat(64);

function createJsonResponse(body: unknown, status = 200, headersInit?: Record<string, string>): Response {
    const serialized = typeof body === 'string' ? body : JSON.stringify(body);
    return {
        ok: status >= 200 && status < 300,
        status,
        statusText: status === 200 ? 'OK' : 'Error',
        headers: new Headers({
            'Content-Type': 'application/json',
            ...(headersInit || {}),
        }),
        json: async () => (typeof body === 'string' ? JSON.parse(body) : body),
        text: async () => serialized,
    } as unknown as Response;
}

function makeArchive(overrides: Partial<StreamingArchive> = {}, sha256 = ARCHIVE_SHA_A): StreamingArchive {
    const baseData: StreamingArchive['data'] = {
        history: [
            {
                id: 7,
                sessionKey: 'jellyfin:session-7:item-2',
                provider: 'jellyfin',
                serverName: 'Media',
                userId: 'provider-user-2',
                userName: 'Sam',
                clientName: 'TV',
                itemId: 'item-2',
                itemName: 'Example Movie',
                itemType: 'Movie',
                seriesName: '',
                seriesId: '',
                seasonNumber: null,
                episodeNumber: null,
                productionYear: 2026,
                playMethod: 'DirectPlay',
                container: 'mkv',
                videoCodec: 'hevc',
                videoResolution: '4K',
                audioCodec: 'eac3',
                audioChannels: 6,
                subtitleCodec: 'srt',
                hwAccel: 'vaapi',
                transcodeReasons: '',
                bitrateBps: 12000000,
                durationSecs: 7200,
                watchedSecs: 3600,
                dataUsedBytes: 5400000000,
                completionPct: 50.0,
                startedAt: '2026-10-01T12:00:00Z',
                lastSeenAt: '2026-10-01T13:00:00Z',
                endedAt: '2026-10-01T13:00:00Z',
                isActive: 0,
                provenance: 'imported_event',
                serverId: 'server-a',
                sourceEventId: 'event-7',
                timestampCertainty: 'source_event',
                byteAccuracy: 'estimated',
                policyStatus: 'included',
            },
        ],
        labels: [
            {
                historyId: 7,
                kind: 'library',
                value: 'library-3',
                name: 'Films',
            },
        ],
        sessionSamples: [
            {
                historyId: 7,
                sampledAt: 1790856000,
                observedSecs: 30,
                playing: true,
                bitrateBps: 12000000,
            },
        ],
        bandwidthSamples: [
            {
                id: 4,
                timestamp: '2026-10-01T12:00:30Z',
                provider: 'jellyfin',
                activeStreams: 1,
                directPlayCount: 1,
                directStreamCount: 0,
                transcodeCount: 0,
                totalBitrateBps: 12000000,
                bytesDelta: 45000000,
            },
        ],
        trackingPolicy: {
            minimumWatchSecs: 45,
            excludedUsers: '[]',
            excludedLibraries: '[]',
            reconnectWindowSecs: 30,
        },
        ...(overrides.data || {}),
    };

    const counts = {
        history: baseData.history.length,
        labels: baseData.labels.length,
        sessionSamples: baseData.sessionSamples.length,
        bandwidthSamples: baseData.bandwidthSamples.length,
        trackingPolicies: 1,
    };

    return {
        manifest: {
            format: STREAMING_ARCHIVE_FORMAT,
            formatVersion: STREAMING_ARCHIVE_FORMAT_VERSION,
            schemaVersion: STREAMING_DATABASE_SCHEMA_VERSION,
            provenanceVersion: STREAMING_PROVENANCE_VERSION,
            exportedAt: '2026-11-01T20:00:00Z',
            recordCounts: counts,
            redactedFields: [
                'streaming_history.device_name',
                'streaming_history.device_id',
                'streaming_history.ip_address',
                'streaming_servers.api_key',
            ],
            omittedTables: [
                'streaming_servers (connection settings and credentials)',
                'streaming_user_links (AetherFlow-local user IDs)',
                'streaming_import_checkpoints (destination-specific cursors)',
                'streaming_history_audit (destination-local audit trail)',
                'streaming_history_revision (destination-local revision counter)',
            ],
            sha256,
            ...(overrides.manifest || {}),
        },
        data: baseData,
    };
}

function makePreviewResponse(
    overrides: Partial<StreamingPortabilityPreviewResponse> = {}
): StreamingPortabilityPreviewResponse {
    return {
        mode: 'merge',
        archiveSha256: ARCHIVE_SHA_A,
        previewSha256: PREVIEW_SHA_MERGE,
        expiresAt: '2026-11-01T20:05:00Z',
        archiveCounts: {
            history: 1,
            labels: 1,
            sessionSamples: 1,
            bandwidthSamples: 1,
            trackingPolicies: 1,
        },
        targetCounts: {
            history: 5,
            labels: 8,
            sessionSamples: 20,
            bandwidthSamples: 12,
            trackingPolicies: 1,
        },
        plan: {
            insert: {
                history: 1,
                labels: 1,
                sessionSamples: 1,
                bandwidthSamples: 1,
                trackingPolicies: 0,
            },
            exactDuplicate: {
                history: 0,
                labels: 0,
                sessionSamples: 0,
                bandwidthSamples: 0,
                trackingPolicies: 0,
            },
            conflict: {
                history: 0,
                labels: 0,
                sessionSamples: 0,
                bandwidthSamples: 0,
                trackingPolicies: 1,
            },
        },
        replacementCounts: null,
        replacementNotice: null,
        conflicts: [
            {
                table: 'streaming_tracking_policies',
                archiveKey: '1',
                existingKey: '1',
                reason: 'tracking_policy_collision',
                action: 'skip',
            },
        ],
        approvalToken: 'approval-token-merge-001',
        ...overrides,
    };
}

function makeRestoreResponse(
    overrides: Partial<StreamingPortabilityRestoreResponse> = {}
): StreamingPortabilityRestoreResponse {
    return {
        mode: 'merge',
        archiveSha256: ARCHIVE_SHA_A,
        previewSha256: PREVIEW_SHA_MERGE,
        backupVerified: true,
        archiveCounts: {
            history: 1,
            labels: 1,
            sessionSamples: 1,
            bandwidthSamples: 1,
            trackingPolicies: 1,
        },
        resultingCounts: {
            history: 6,
            labels: 9,
            sessionSamples: 21,
            bandwidthSamples: 13,
            trackingPolicies: 1,
        },
        plan: {
            insert: {
                history: 1,
                labels: 1,
                sessionSamples: 1,
                bandwidthSamples: 1,
                trackingPolicies: 0,
            },
            exactDuplicate: {
                history: 0,
                labels: 0,
                sessionSamples: 0,
                bandwidthSamples: 0,
                trackingPolicies: 0,
            },
            conflict: {
                history: 0,
                labels: 0,
                sessionSamples: 0,
                bandwidthSamples: 0,
                trackingPolicies: 1,
            },
        },
        conflicts: [
            {
                table: 'streaming_tracking_policies',
                archiveKey: '1',
                existingKey: '1',
                reason: 'tracking_policy_collision',
                action: 'skip',
            },
        ],
        ...overrides,
    };
}

function makeArchiveFile(archive: unknown, filename = 'portable-archive.json'): File {
    const content = typeof archive === 'string' ? archive : JSON.stringify(archive);
    return new File([content], filename, { type: 'application/json' });
}

describe('StreamingPortability', () => {
    (process.env.AF_STREAMING_PORTABILITY_FIXTURE ? it : it.skip)('accepts archive, preview and restore responses serialized by the real Rust core', () => {
        const fixture: { archive: unknown; preview: unknown; restored: unknown } = JSON.parse(readFileSync(process.env.AF_STREAMING_PORTABILITY_FIXTURE!, 'utf8'));
        const archive = parseStreamingArchive(fixture.archive);
        expect(archive.ok).toBe(true);
        const preview = parsePreviewResponse(fixture.preview);
        const restored = parseRestoreResponse(fixture.restored);
        expect(preview).not.toBeNull();
        expect(restored).not.toBeNull();
        expect(preview?.archiveSha256).toBe(restored?.archiveSha256);
        expect(preview?.previewSha256).toBe(restored?.previewSha256);
        expect(restored?.backupVerified).toBe(true);
        if (archive.ok) {
            expect(archive.archive.manifest.recordCounts).toEqual(preview?.archiveCounts);
        }
    });

    beforeEach(() => {
        jest.clearAllMocks();
        mockAuthUser = {
            id: 1,
            username: 'admin_operator',
            role: 'admin',
        };
        mockAuthLoading = false;
    });

    it('enforces the admin-only boundary via useAuth and hides export/preview/restore controls for non-admin users', () => {
        mockAuthUser = {
            id: 42,
            username: 'standard_viewer',
            role: 'user',
        };

        render(<StreamingPortability />);

        expect(screen.getByTestId('streaming-portability-admin-boundary')).toBeInTheDocument();
        expect(screen.getByText('Administrative Access Required')).toBeInTheDocument();
        expect(screen.queryByTestId('portability-export-btn')).not.toBeInTheDocument();
        expect(screen.queryByTestId('portability-file-input')).not.toBeInTheDocument();
        expect(screen.queryByTestId('portability-preview-btn')).not.toBeInTheDocument();
        expect(screen.queryByTestId('portability-apply-restore-btn')).not.toBeInTheDocument();
        expect(mockedApiFetch).not.toHaveBeenCalled();
    });

    it('exports a versioned JSON archive via GET /api/v1/admin/streaming/portability/export for admin users', async () => {
        const archive = makeArchive();
        const originalCreateObjectURL = URL.createObjectURL;
        const originalRevokeObjectURL = URL.revokeObjectURL;
        const createObjectURL = jest.fn((blob: Blob) => `blob:streaming-export-${blob.size}`);
        URL.createObjectURL = createObjectURL;
        URL.revokeObjectURL = jest.fn();
        const anchorClick = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
        mockedApiFetch.mockResolvedValueOnce(
            createJsonResponse(archive, 200, {
                'Content-Disposition': 'attachment; filename="streaming-history-backup.json"',
            })
        );

        render(<StreamingPortability />);

        fireEvent.click(screen.getByTestId('portability-export-btn'));

        await waitFor(() => {
            expect(screen.getByTestId('portability-export-success')).toBeInTheDocument();
        });

        expect(mockedApiFetch).toHaveBeenCalledTimes(1);
        expect(mockedApiFetch.mock.calls[0][0]).toBe(STREAMING_PORTABILITY_EXPORT_URL);
        expect(mockedApiFetch.mock.calls[0][1]?.method).toBe('GET');
        expect(screen.getByTestId('portability-exported-sha256')).toHaveTextContent(ARCHIVE_SHA_A);
        expect(createObjectURL.mock.calls[0][0].size).toBe(new TextEncoder().encode(JSON.stringify(archive)).byteLength);
        URL.createObjectURL = originalCreateObjectURL;
        URL.revokeObjectURL = originalRevokeObjectURL;
        anchorClick.mockRestore();
    });

    it('runs dry-run preview without auto-applying restore and displays exact hashes, counts, and conflicts', async () => {
        const archive = makeArchive();
        const preview = makePreviewResponse();
        mockedApiFetch.mockResolvedValueOnce(createJsonResponse(preview, 200));

        render(<StreamingPortability />);

        const fileInput = screen.getByTestId('portability-file-input');
        fireEvent.change(fileInput, {
            target: { files: [makeArchiveFile(archive)] },
        });

        await waitFor(() => {
            expect(screen.getByTestId('portability-selected-archive-summary')).toBeInTheDocument();
        });

        fireEvent.click(screen.getByTestId('portability-preview-btn'));

        await waitFor(() => {
            expect(screen.getByTestId('portability-preview-panel')).toBeInTheDocument();
        });

        expect(mockedApiFetch).toHaveBeenCalledTimes(1);
        expect(mockedApiFetch.mock.calls[0][0]).toBe(STREAMING_PORTABILITY_PREVIEW_URL);
        expect(mockedApiFetch.mock.calls[0][1]?.method).toBe('POST');

        const sentPreviewBody = JSON.parse(String(mockedApiFetch.mock.calls[0][1]?.body));
        expect(sentPreviewBody).toEqual({
            archive,
            mode: 'merge',
        });

        expect(screen.getByTestId('preview-archive-sha256')).toHaveTextContent(ARCHIVE_SHA_A);
        expect(screen.getByTestId('preview-fingerprint-sha256')).toHaveTextContent(
            PREVIEW_SHA_MERGE
        );
        expect(screen.getByTestId('preview-archive-counts-total')).toHaveTextContent('5 total');
        expect(screen.getByTestId('preview-target-counts-history')).toHaveTextContent('5');
        expect(screen.getByTestId('preview-plan-insert-history')).toHaveTextContent('1');
        expect(screen.getByTestId('preview-plan-conflict-tracking-policies')).toHaveTextContent('1');
        expect(screen.getByTestId('preview-conflict-row-0')).toHaveTextContent(
            'streaming_tracking_policies'
        );
        expect(screen.getByTestId('preview-conflict-row-0')).toHaveTextContent(
            'tracking_policy_collision'
        );

        const applyBtn = screen.getByTestId('portability-apply-restore-btn');
        expect(applyBtn).toBeDisabled();
        expect(
            mockedApiFetch.mock.calls.some(
                (call) => call[0] === STREAMING_PORTABILITY_RESTORE_URL
            )
        ).toBe(false);
    });

    it('submits the exact approved token, archive, and mode on restore and resets preview/approval when file or mode changes', async () => {
        const archiveA = makeArchive({}, ARCHIVE_SHA_A);
        const archiveB = makeArchive({}, ARCHIVE_SHA_B);

        const replacePreview = makePreviewResponse({
            mode: 'replace',
            archiveSha256: ARCHIVE_SHA_A,
            previewSha256: PREVIEW_SHA_REPLACE,
            replacementCounts: {
                history: 5,
                labels: 8,
                sessionSamples: 20,
                bandwidthSamples: 12,
                trackingPolicies: 1,
            },
            replacementNotice:
                'Replacement clears destination device names, device IDs, and IP addresses because they are intentionally omitted from this archive.',
            conflicts: [],
            approvalToken: 'exact-approval-token-replace-999',
        });

        mockedApiFetch.mockResolvedValueOnce(createJsonResponse(replacePreview, 200));

        render(<StreamingPortability />);

        fireEvent.click(screen.getByTestId('portability-mode-replace-btn'));
        expect(screen.getByTestId('portability-replace-warning')).toBeInTheDocument();

        const fileInput = screen.getByTestId('portability-file-input');
        fireEvent.change(fileInput, {
            target: { files: [makeArchiveFile(archiveA, 'archive-a.json')] },
        });

        await waitFor(() => {
            expect(screen.getByTestId('portability-selected-filename')).toHaveTextContent(
                'archive-a.json'
            );
        });

        fireEvent.click(screen.getByTestId('portability-preview-btn'));

        await waitFor(() => {
            expect(screen.getByTestId('portability-preview-panel')).toBeInTheDocument();
        });

        expect(screen.getByTestId('preview-replacement-notice')).toHaveTextContent(
            'Replacement clears destination device names'
        );
        expect(screen.getByTestId('preview-replacement-counts-history')).toHaveTextContent('5');

        const approveCheckbox = screen.getByTestId('portability-approve-checkbox');
        fireEvent.click(approveCheckbox);
        expect(screen.getByTestId('portability-apply-restore-btn')).not.toBeDisabled();

        fireEvent.click(screen.getByTestId('portability-mode-merge-btn'));
        expect(screen.queryByTestId('portability-preview-panel')).not.toBeInTheDocument();
        expect(screen.queryByTestId('portability-apply-restore-btn')).not.toBeInTheDocument();

        const mergePreview = makePreviewResponse({
            mode: 'merge',
            archiveSha256: ARCHIVE_SHA_A,
            previewSha256: PREVIEW_SHA_MERGE,
            approvalToken: 'exact-approval-token-merge-777',
        });
        mockedApiFetch.mockResolvedValueOnce(createJsonResponse(mergePreview, 200));

        fireEvent.click(screen.getByTestId('portability-preview-btn'));
        await waitFor(() => {
            expect(screen.getByTestId('portability-preview-panel')).toBeInTheDocument();
        });
        fireEvent.click(screen.getByTestId('portability-approve-checkbox'));

        fireEvent.change(fileInput, {
            target: { files: [makeArchiveFile(archiveB, 'archive-b.json')] },
        });
        await waitFor(() => {
            expect(screen.getByTestId('portability-selected-filename')).toHaveTextContent(
                'archive-b.json'
            );
        });
        expect(screen.queryByTestId('portability-preview-panel')).not.toBeInTheDocument();

        const finalPreview = makePreviewResponse({
            mode: 'merge',
            archiveSha256: ARCHIVE_SHA_B,
            previewSha256: PREVIEW_SHA_MERGE,
            approvalToken: 'approved-token-for-archive-b',
        });
        const finalRestore = makeRestoreResponse({
            mode: 'merge',
            archiveSha256: ARCHIVE_SHA_B,
            previewSha256: PREVIEW_SHA_MERGE,
        });

        mockedApiFetch
            .mockResolvedValueOnce(createJsonResponse(finalPreview, 200))
            .mockResolvedValueOnce(createJsonResponse(finalRestore, 200));

        fireEvent.click(screen.getByTestId('portability-preview-btn'));
        await waitFor(() => {
            expect(screen.getByTestId('portability-preview-panel')).toBeInTheDocument();
        });

        fireEvent.click(screen.getByTestId('portability-approve-checkbox'));
        fireEvent.click(screen.getByTestId('portability-apply-restore-btn'));

        await waitFor(() => {
            expect(screen.getByTestId('portability-restore-result')).toBeInTheDocument();
        });

        const restoreCall = mockedApiFetch.mock.calls.find(
            (call) => call[0] === STREAMING_PORTABILITY_RESTORE_URL
        );
        expect(restoreCall).toBeDefined();
        expect(restoreCall?.[1]?.method).toBe('POST');
        const restorePayload = JSON.parse(String(restoreCall?.[1]?.body));
        expect(restorePayload).toEqual({
            archive: archiveB,
            mode: 'merge',
            approvalToken: 'approved-token-for-archive-b',
        });
        expect(screen.getByTestId('restore-backup-verified-badge')).toHaveTextContent(
            'Backup Verified: Yes'
        );
    });

    it('invalidates preview and approval on HTTP 409 conflict during restore and forces a new preview', async () => {
        const archive = makeArchive();
        const preview = makePreviewResponse({
            approvalToken: 'stale-token-409',
        });

        mockedApiFetch
            .mockResolvedValueOnce(createJsonResponse(preview, 200))
            .mockResolvedValueOnce(
                createJsonResponse(
                    {
                        code: 'streaming_preview_changed',
                        message:
                            'Streaming data changed after preview; create and approve a new preview',
                    },
                    409
                )
            );

        render(<StreamingPortability />);

        fireEvent.change(screen.getByTestId('portability-file-input'), {
            target: { files: [makeArchiveFile(archive)] },
        });

        await waitFor(() => {
            expect(screen.getByTestId('portability-selected-archive-summary')).toBeInTheDocument();
        });

        fireEvent.click(screen.getByTestId('portability-preview-btn'));

        await waitFor(() => {
            expect(screen.getByTestId('portability-preview-panel')).toBeInTheDocument();
        });

        fireEvent.click(screen.getByTestId('portability-approve-checkbox'));
        fireEvent.click(screen.getByTestId('portability-apply-restore-btn'));

        await waitFor(() => {
            expect(screen.getByTestId('portability-stale-conflict-banner')).toBeInTheDocument();
        });

        expect(screen.getByTestId('portability-stale-conflict-banner')).toHaveTextContent(
            'Streaming data changed after preview; create and approve a new preview'
        );
        expect(screen.queryByTestId('portability-preview-panel')).not.toBeInTheDocument();
        expect(screen.queryByTestId('portability-apply-restore-btn')).not.toBeInTheDocument();
        expect(screen.getByTestId('portability-preview-btn')).not.toBeDisabled();
    });

    it('rejects malformed JSON, unsupported archive versions, and files exceeding the 8 MiB bound before calling apiFetch', async () => {
        render(<StreamingPortability />);
        const fileInput = screen.getByTestId('portability-file-input');

        const oversizedFile = new File(['{}'], 'oversized.json', { type: 'application/json' });
        Object.defineProperty(oversizedFile, 'size', {
            value: MAX_STREAMING_ARCHIVE_BYTES + 1024,
        });

        fireEvent.change(fileInput, {
            target: { files: [oversizedFile] },
        });

        await waitFor(() => {
            expect(screen.getByTestId('portability-file-error')).toBeInTheDocument();
        });
        expect(screen.getByTestId('portability-file-error')).toHaveTextContent('8 MiB');
        expect(screen.getByTestId('portability-preview-btn')).toBeDisabled();

        const malformedFile = makeArchiveFile('{not-valid-json', 'broken.json');
        fireEvent.change(fileInput, {
            target: { files: [malformedFile] },
        });

        await waitFor(() => {
            expect(screen.getByTestId('portability-file-error')).toHaveTextContent(
                'not valid JSON'
            );
        });
        expect(screen.getByTestId('portability-preview-btn')).toBeDisabled();

        const badVersionArchive = makeArchive({
            manifest: {
                ...makeArchive().manifest,
                schemaVersion: 999,
            },
        });
        fireEvent.change(fileInput, {
            target: { files: [makeArchiveFile(badVersionArchive, 'bad-schema.json')] },
        });

        await waitFor(() => {
            expect(screen.getByTestId('portability-file-error')).toHaveTextContent(
                'Unsupported archive version metadata'
            );
        });
        expect(screen.getByTestId('portability-preview-btn')).toBeDisabled();
        expect(mockedApiFetch).not.toHaveBeenCalled();
    });
});
