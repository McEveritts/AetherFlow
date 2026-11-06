import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import StreamingHistoryAdmin, {
    STREAMING_ADMIN_IMPORT_STATUS_URL,
    STREAMING_ADMIN_IMPORT_EVENTS_URL,
    STREAMING_ADMIN_POLICIES_URL,
    STREAMING_ADMIN_USER_LINKS_URL,
    STREAMING_ADMIN_RECONCILIATION_PREVIEW_URL,
    STREAMING_ADMIN_RECONCILIATION_APPLY_URL,
    MAX_IMPORT_BATCH_BYTES,
    MAX_IMPORT_BATCH_EVENTS,
    parseImportBatchPayload,
    parsePolicyTargetsJson,
} from './StreamingHistoryAdmin';
import { apiFetch } from '@/lib/fetcher';

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

const mockAddToast = jest.fn();
jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
        toasts: [],
        removeToast: jest.fn(),
    }),
}));

type MockAuthState = {
    user: { id: number; username: string; role: string } | null;
    isAuthenticated: boolean;
    isLoading: boolean;
};

let currentAuthState: MockAuthState = {
    user: { id: 1, username: 'admin', role: 'admin' },
    isAuthenticated: true,
    isLoading: false,
};

jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => currentAuthState,
}));

const mockedApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;

function jsonResponse(body: unknown, status = 200): Response {
    return {
        ok: status >= 200 && status < 300,
        status,
        headers: { get: () => 'application/json' },
        json: async () => body,
        text: async () => JSON.stringify(body),
    } as unknown as Response;
}

const sampleStatusResponse = {
    maxBatchEvents: 500,
    checkpoints: [
        {
            provider: 'jellyfin',
            serverId: 'default',
            source: 'playback_reporting_export',
            checkpoint: 'cp-001',
            imported: 42,
            lastError: null,
            updatedAt: '2026-03-20T12:00:00Z',
        },
    ],
    capabilities: [
        {
            provider: 'jellyfin',
            serverId: 'default',
            realEventImportSupported: true,
            jsonBatchImportSupported: true,
            upstreamDirectFetchAvailable: false,
            upstreamEndpointClassification: 'item_user_data_summary_or_plugin_required',
            reason: 'Stock Jellyfin exposes active sessions and per-item UserData summaries; upload JSON batches.',
        },
    ],
};

const samplePolicyResponse = {
    minimumWatchSecs: 30,
    reconnectWindowSecs: 90,
    excludedUsers: [{ provider: 'jellyfin', serverId: 'default', id: 'u-kids', name: 'Kids Profile' }],
    excludedLibraries: [{ provider: 'jellyfin', serverId: 'default', id: 'lib-temp', name: 'Temp Clips' }],
    policyRevision: 3,
    historyRevision: 15,
    semantics: {
        minimumWatchSecsEffect: 'Marks short sessions as policyStatus=below_minimum_watch_time',
        excludedUsersEffect: 'Marks matching user sessions as policyStatus=excluded_user',
        excludedLibrariesEffect: 'Marks matching library sessions as policyStatus=excluded_library',
        reconnectWindowSecsEffect: 'Merges rapid reconnects within window',
        rawEvidencePreserved: true,
    },
};

const sampleLinksResponse = {
    links: [
        {
            afUserId: 7,
            afUsername: 'alice',
            provider: 'jellyfin',
            serverId: 'default',
            providerUserId: 'jf-user-77',
        },
    ],
    historyRevision: 15,
    identitySemantics: 'Explicit (afUserId, provider, serverId, providerUserId) mappings only.',
};

const samplePreviewResponse = {
    previewHash: 'sha256:9f86d081884c7d659a2feaa0c55ad015',
    approvalToken: '1.15.1774000000.sha256:9f86d081884c7d659a2feaa0c55ad015.sig123',
    actorId: 1,
    historyRevision: 15,
    issuedAt: '2026-03-20T12:00:00Z',
    expiresAt: '2026-03-20T12:15:00Z',
    totalAffectedRows: 1,
    countsBefore: {
        totalRecords: 10,
        confirmedPlays: 8,
        observedStreamSessions: 7,
        importedServerEvents: 1,
        legacyRecords: 2,
        itemSummaries: 1,
        excludedPolicyRecords: 0,
        deduplicatedRecords: 0,
        ambiguousOverlapRecords: 0,
        undatedRecords: 1,
        estimatedByteRecords: 2,
    },
    countsAfter: {
        totalRecords: 10,
        confirmedPlays: 8,
        observedStreamSessions: 7,
        importedServerEvents: 1,
        legacyRecords: 2,
        itemSummaries: 1,
        excludedPolicyRecords: 1,
        deduplicatedRecords: 0,
        ambiguousOverlapRecords: 0,
        undatedRecords: 1,
        estimatedByteRecords: 2,
    },
    affectedRows: [
        {
            id: 19,
            sessionKey: 'legacy:jf:19',
            classification: 'legacy_item_summary_quarantine',
            rowFingerprint: 'fp-19',
            before: {
                id: 19,
                sessionKey: 'legacy:jf:19',
                provider: 'jellyfin',
                serverId: 'default',
                sourceEventId: null,
                userId: 'u-1',
                userName: 'Alice',
                itemId: 'item-9',
                itemName: 'Blade Runner',
                itemType: 'Movie',
                playMethod: 'DirectPlay',
                clientName: 'Web',
                deviceName: 'Browser',
                deviceId: 'd-1',
                ipAddress: '10.0.0.2',
                durationSecs: 7000,
                watchedSecs: 7000,
                dataUsedBytes: 0,
                bitrateBps: 0,
                startedAt: '',
                lastSeenAt: '',
                endedAt: null,
                provenance: 'legacy_backfill_summary',
                timestampCertainty: 'undated_summary',
                byteAccuracy: 'none',
                policyStatus: 'included',
            },
            after: {
                id: 19,
                sessionKey: 'legacy:jf:19',
                provider: 'jellyfin',
                serverId: 'default',
                sourceEventId: null,
                userId: 'u-1',
                userName: 'Alice',
                itemId: 'item-9',
                itemName: 'Blade Runner',
                itemType: 'Movie',
                playMethod: 'DirectPlay',
                clientName: 'Web',
                deviceName: 'Browser',
                deviceId: 'd-1',
                ipAddress: '10.0.0.2',
                durationSecs: 7000,
                watchedSecs: 7000,
                dataUsedBytes: 0,
                bitrateBps: 0,
                startedAt: '',
                lastSeenAt: '',
                endedAt: null,
                provenance: 'legacy_item_user_data_summary',
                timestampCertainty: 'undated_summary',
                byteAccuracy: 'none',
                policyStatus: 'excluded_legacy_summary',
            },
            changes: [
                {
                    field: 'provenance',
                    before: 'legacy_backfill_summary',
                    after: 'legacy_item_user_data_summary',
                    reason: 'Normalize legacy item summary provenance',
                },
            ],
        },
    ],
};

function setupDefaultAdminMocks() {
    mockedApiFetch.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? 'GET').toUpperCase();
        if (url === STREAMING_ADMIN_IMPORT_STATUS_URL && method === 'GET') {
            return jsonResponse(sampleStatusResponse);
        }
        if (url === STREAMING_ADMIN_POLICIES_URL && method === 'GET') {
            return jsonResponse(samplePolicyResponse);
        }
        if (url === STREAMING_ADMIN_USER_LINKS_URL && method === 'GET') {
            return jsonResponse(sampleLinksResponse);
        }
        throw new Error(`Unexpected request: ${method} ${url}`);
    });
}

describe('StreamingHistoryAdmin', () => {
    it('preserves policy drafts through refresh, pending save, and independent link mutation', async () => {
        setupDefaultAdminMocks();
        render(<StreamingHistoryAdmin />);
        await screen.findByTestId('import-checkpoints-table');
        fireEvent.click(screen.getByTestId('admin-tab-policies'));
        fireEvent.change(screen.getByTestId('policy-min-watch-input'), { target: { value: '99' } });
        fireEvent.click(screen.getByTestId('admin-refresh-btn'));
        await waitFor(() => expect(screen.getByTestId('admin-refresh-btn')).not.toBeDisabled());
        expect(screen.getByTestId('policy-min-watch-input')).toHaveValue(99);
        let resolvePolicy!: (response: Response) => void;
        let policySignal: AbortSignal | undefined;
        mockedApiFetch.mockImplementation(async (input, init) => {
            if (String(input) === STREAMING_ADMIN_POLICIES_URL && init?.method === 'PUT') {
                policySignal = init.signal as AbortSignal;
                return new Promise<Response>(resolve => { resolvePolicy = resolve; });
            }
            if (String(input) === STREAMING_ADMIN_USER_LINKS_URL) return jsonResponse(sampleLinksResponse);
            if (String(input) === STREAMING_ADMIN_POLICIES_URL) return jsonResponse(samplePolicyResponse);
            return jsonResponse(sampleStatusResponse);
        });
        fireEvent.change(screen.getByTestId('policy-min-watch-input'), { target: { value: '40' } });
        fireEvent.click(screen.getByTestId('policy-save-btn'));
        await waitFor(() => expect(resolvePolicy).toBeDefined());
        fireEvent.change(screen.getByTestId('policy-min-watch-input'), { target: { value: '99' } });
        fireEvent.click(screen.getByTestId('admin-tab-links'));
        fireEvent.change(screen.getByTestId('link-af-user-id-input'), { target: { value: '9' } });
        fireEvent.change(screen.getByTestId('link-server-id-input'), { target: { value: 'default' } });
        fireEvent.change(screen.getByTestId('link-provider-user-id-input'), { target: { value: 'provider-9' } });
        fireEvent.click(screen.getByTestId('link-upsert-btn'));
        await waitFor(() => expect(screen.getByTestId('link-upsert-btn')).not.toBeDisabled());
        expect(policySignal?.aborted).toBe(false);
        await act(async () => resolvePolicy(jsonResponse({ ...samplePolicyResponse, minimumWatchSecs: 40, policyRevision: 4 })));
        fireEvent.click(screen.getByTestId('admin-tab-policies'));
        expect(screen.getByTestId('policy-min-watch-input')).toHaveValue(99);
        expect(screen.getByTestId('policy-save-btn')).not.toBeDisabled();
    });

    beforeEach(() => {
        jest.clearAllMocks();
        currentAuthState = {
            user: { id: 1, username: 'admin', role: 'admin' },
            isAuthenticated: true,
            isLoading: false,
        };
    });

    it('enforces the admin boundary and makes zero API calls for non-admin or unauthenticated users', () => {
        currentAuthState = {
            user: { id: 2, username: 'viewer', role: 'user' },
            isAuthenticated: true,
            isLoading: false,
        };

        render(<StreamingHistoryAdmin />);

        expect(screen.getByTestId('streaming-history-admin-boundary')).toBeInTheDocument();
        expect(screen.queryByTestId('streaming-history-admin')).not.toBeInTheDocument();
        expect(mockedApiFetch).not.toHaveBeenCalled();
    });

    it('loads initial status, tracking policy, and user links using /api/v1/admin/streaming endpoints', async () => {
        setupDefaultAdminMocks();
        render(<StreamingHistoryAdmin />);

        await waitFor(() => {
            expect(screen.getByTestId('import-checkpoints-table')).toBeInTheDocument();
        });

        const calledUrls = mockedApiFetch.mock.calls.map((c) => String(c[0]));
        expect(calledUrls).toEqual([
            STREAMING_ADMIN_IMPORT_STATUS_URL,
            STREAMING_ADMIN_POLICIES_URL,
            STREAMING_ADMIN_USER_LINKS_URL,
        ]);
        for (const url of calledUrls) {
            expect(url.startsWith('/api/v1/admin/streaming/')).toBe(true);
            expect(url.includes('/api/v1/auth/')).toBe(false);
        }
        expect(screen.getByText('cp-001')).toBeInTheDocument();
    });

    it('enforces bounded event batch limits (<=1 MiB and <=500 events), preserves expectedCheckpoint, and submits valid imports with ambiguous outcomes', async () => {
        setupDefaultAdminMocks();
        const onChanged = jest.fn();
        render(<StreamingHistoryAdmin onChanged={onChanged} />);

        await waitFor(() => {
            expect(screen.getByTestId('import-checkpoints-table')).toBeInTheDocument();
        });

        const parsedWithExplicitExpected = parseImportBatchPayload(
            JSON.stringify({
                provider: 'jellyfin',
                serverId: 'default',
                source: 'playback_reporting_export',
                checkpoint: 'batch-2',
                expectedCheckpoint: 'cp-001',
                events: [
                    {
                        sourceEventId: 'evt-1',
                        userId: 'u-1',
                        itemId: 'i-1',
                        itemName: 'Dune',
                        startedAt: '2026-03-01T20:00:00Z',
                    },
                ],
            }),
            {
                provider: 'jellyfin',
                serverId: 'default',
                serverName: '',
                source: 'playback_reporting_export',
                checkpoint: 'batch-1',
            }
        );
        expect(parsedWithExplicitExpected.ok).toBe(true);
        if (parsedWithExplicitExpected.ok) {
            expect(parsedWithExplicitExpected.request.expectedCheckpoint).toBe('cp-001');
        }

        const oversizedText = 'x'.repeat(MAX_IMPORT_BATCH_BYTES + 10);
        expect(
            parseImportBatchPayload(oversizedText, {
                provider: 'jellyfin',
                serverId: 'default',
                serverName: '',
                source: 'playback_reporting_export',
                checkpoint: 'batch-1',
            }).ok
        ).toBe(false);

        const tooManyEvents = Array.from({ length: MAX_IMPORT_BATCH_EVENTS + 1 }, (_, i) => ({
            sourceEventId: `evt-${i}`,
            userId: 'u-1',
            itemId: 'i-1',
            itemName: 'Dune',
            startedAt: '2026-03-01T20:00:00Z',
        }));

        fireEvent.change(screen.getByTestId('import-checkpoint-input'), {
            target: { value: 'batch-oversized' },
        });
        fireEvent.change(screen.getByTestId('import-json-textarea'), {
            target: { value: JSON.stringify(tooManyEvents) },
        });
        fireEvent.click(screen.getByTestId('import-submit-btn'));

        expect(await screen.findByTestId('import-error')).toHaveTextContent('between 1 and 500 events');
        expect(
            mockedApiFetch.mock.calls.some(([input]) => String(input) === STREAMING_ADMIN_IMPORT_EVENTS_URL)
        ).toBe(false);

        mockedApiFetch.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            const method = (init?.method ?? 'GET').toUpperCase();
            if (url === STREAMING_ADMIN_IMPORT_EVENTS_URL && method === 'POST') {
                return jsonResponse({
                    provider: 'jellyfin',
                    serverId: 'default',
                    source: 'playback_reporting_export',
                    checkpoint: 'batch-2',
                    batchSize: 3,
                    insertedIncluded: 1,
                    deduplicatedRetries: 1,
                    confirmedOverlapDuplicates: 0,
                    ambiguousOverlaps: 1,
                    cumulativeImported: 44,
                    revision: 16,
                    outcomes: [
                        {
                            sourceEventId: 'evt-ok',
                            historyId: 101,
                            disposition: 'inserted',
                            policyStatus: 'included',
                            matchedObservedIds: [],
                        },
                        {
                            sourceEventId: 'evt-ok',
                            historyId: 101,
                            disposition: 'deduplicated_retry',
                            policyStatus: 'included',
                            matchedObservedIds: [],
                        },
                        {
                            sourceEventId: 'evt-amb',
                            historyId: 102,
                            disposition: 'ambiguous_overlap',
                            policyStatus: 'ambiguous',
                            matchedObservedIds: [55, 56],
                        },
                    ],
                });
            }
            if (url === STREAMING_ADMIN_IMPORT_STATUS_URL) return jsonResponse(sampleStatusResponse);
            if (url === STREAMING_ADMIN_POLICIES_URL) return jsonResponse(samplePolicyResponse);
            if (url === STREAMING_ADMIN_USER_LINKS_URL) return jsonResponse(sampleLinksResponse);
            throw new Error(`Unexpected request: ${method} ${url}`);
        });

        fireEvent.change(screen.getByTestId('import-checkpoint-input'), {
            target: { value: 'batch-2' },
        });
        fireEvent.change(screen.getByTestId('import-json-textarea'), {
            target: {
                value: JSON.stringify([
                    {
                        sourceEventId: 'evt-ok',
                        userId: 'u-1',
                        itemId: 'i-1',
                        itemName: 'Dune',
                        startedAt: '2026-03-01T20:00:00Z',
                    },
                    {
                        sourceEventId: 'evt-amb',
                        userId: 'u-1',
                        itemId: 'i-1',
                        itemName: 'Dune',
                        startedAt: '2026-03-01T20:02:00Z',
                    },
                ]),
            },
        });
        fireEvent.click(screen.getByTestId('import-submit-btn'));

        await waitFor(() => {
            expect(screen.getByTestId('import-outcomes-panel')).toBeInTheDocument();
        });

        const postCall = mockedApiFetch.mock.calls.find(
            ([input, init]) => String(input) === STREAMING_ADMIN_IMPORT_EVENTS_URL && init?.method === 'POST'
        );
        expect(postCall).toBeDefined();
        expect(JSON.parse(String(postCall?.[1]?.body))).toEqual({
            provider: 'jellyfin',
            serverId: 'default',
            source: 'playback_reporting_export',
            checkpoint: 'batch-2',
            expectedCheckpoint: 'cp-001',
            events: [
                {
                    sourceEventId: 'evt-ok',
                    userId: 'u-1',
                    itemId: 'i-1',
                    itemName: 'Dune',
                    startedAt: '2026-03-01T20:00:00Z',
                },
                {
                    sourceEventId: 'evt-amb',
                    userId: 'u-1',
                    itemId: 'i-1',
                    itemName: 'Dune',
                    startedAt: '2026-03-01T20:02:00Z',
                },
            ],
        });
        expect(screen.getByTestId('import-ambiguous-count')).toHaveTextContent('1');
        expect(screen.getAllByTestId('import-outcome-evt-ok')).toHaveLength(2);
        expect(screen.getByTestId('import-outcome-evt-amb')).toHaveTextContent('ambiguous');
        expect(screen.getByTestId('import-next-checkpoint-notice')).toHaveTextContent(/enter a new opaque upstream checkpoint/i);
        expect(screen.getByTestId('import-checkpoint-input')).toHaveValue('');
        expect(onChanged).toHaveBeenCalledTimes(1);

        fireEvent.click(screen.getByTestId('import-submit-btn'));
        expect(await screen.findByTestId('import-error')).toHaveTextContent('serverId, source, and checkpoint are required.');
    });

    it('validates tracking policy JSON arrays as unknown and sends exact PUT /api/v1/admin/streaming/policies payload', async () => {
        setupDefaultAdminMocks();
        render(<StreamingHistoryAdmin />);

        await waitFor(() => {
            expect(screen.getByTestId('import-checkpoints-table')).toBeInTheDocument();
        });

        fireEvent.click(screen.getByTestId('admin-tab-policies'));

        expect(parsePolicyTargetsJson('{"not":"an-array"}', 'excludedUsers').ok).toBe(false);
        expect(
            parsePolicyTargetsJson(
                '[{"provider":"jellyfin","serverId":"default","id":"u1","extra":true}]',
                'excludedUsers'
            ).ok
        ).toBe(false);

        fireEvent.change(screen.getByTestId('policy-min-watch-input'), { target: { value: '999999' } });
        fireEvent.click(screen.getByTestId('policy-save-btn'));
        expect(await screen.findByTestId('policy-error')).toHaveTextContent('between 0 and 86400');

        mockedApiFetch.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            if (url === STREAMING_ADMIN_POLICIES_URL && init?.method === 'PUT') {
                return jsonResponse({
                    ...samplePolicyResponse,
                    minimumWatchSecs: 60,
                    reconnectWindowSecs: 120,
                    policyRevision: 4,
                });
            }
            return jsonResponse(sampleStatusResponse);
        });

        fireEvent.change(screen.getByTestId('policy-min-watch-input'), { target: { value: '60' } });
        fireEvent.change(screen.getByTestId('policy-reconnect-input'), { target: { value: '120' } });
        fireEvent.click(screen.getByTestId('policy-save-btn'));

        await waitFor(() => {
            const putCall = mockedApiFetch.mock.calls.find(
                ([input, init]) => String(input) === STREAMING_ADMIN_POLICIES_URL && init?.method === 'PUT'
            );
            expect(putCall).toBeDefined();
            expect(JSON.parse(String(putCall?.[1]?.body))).toEqual({
                minimumWatchSecs: 60,
                reconnectWindowSecs: 120,
                excludedUsers: samplePolicyResponse.excludedUsers,
                excludedLibraries: samplePolicyResponse.excludedLibraries,
            });
        });
    });

    it('sends explicit PUT and DELETE /api/v1/admin/streaming/user-links requests with stable IDs', async () => {
        setupDefaultAdminMocks();
        render(<StreamingHistoryAdmin />);

        await waitFor(() => {
            expect(screen.getByTestId('import-checkpoints-table')).toBeInTheDocument();
        });

        fireEvent.click(screen.getByTestId('admin-tab-links'));

        mockedApiFetch.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            if (url === STREAMING_ADMIN_USER_LINKS_URL && init?.method === 'PUT') {
                return jsonResponse({
                    ...sampleLinksResponse,
                    links: [
                        ...sampleLinksResponse.links,
                        {
                            afUserId: 9,
                            afUsername: 'bob',
                            provider: 'emby',
                            serverId: 'srv-2',
                            providerUserId: 'emby-u-9',
                        },
                    ],
                });
            }
            if (url === STREAMING_ADMIN_USER_LINKS_URL && init?.method === 'DELETE') {
                return jsonResponse({
                    ...sampleLinksResponse,
                    links: [],
                });
            }
            return jsonResponse(sampleLinksResponse);
        });

        fireEvent.change(screen.getByTestId('link-af-user-id-input'), { target: { value: '9' } });
        fireEvent.change(screen.getByTestId('link-provider-select'), { target: { value: 'emby' } });
        fireEvent.change(screen.getByTestId('link-server-id-input'), { target: { value: 'srv-2' } });
        fireEvent.change(screen.getByTestId('link-provider-user-id-input'), { target: { value: 'emby-u-9' } });
        fireEvent.click(screen.getByTestId('link-upsert-btn'));

        await waitFor(() => {
            const putCall = mockedApiFetch.mock.calls.find(
                ([input, init]) => String(input) === STREAMING_ADMIN_USER_LINKS_URL && init?.method === 'PUT'
            );
            expect(putCall).toBeDefined();
            expect(JSON.parse(String(putCall?.[1]?.body))).toEqual({
                afUserId: 9,
                provider: 'emby',
                serverId: 'srv-2',
                providerUserId: 'emby-u-9',
            });
        });

        fireEvent.click(screen.getByTestId('delete-link-7:jellyfin:default:jf-user-77'));

        await waitFor(() => {
            const deleteCall = mockedApiFetch.mock.calls.find(
                ([input, init]) => String(input) === STREAMING_ADMIN_USER_LINKS_URL && init?.method === 'DELETE'
            );
            expect(deleteCall).toBeDefined();
            expect(JSON.parse(String(deleteCall?.[1]?.body))).toEqual({
                afUserId: 7,
                provider: 'jellyfin',
                serverId: 'default',
                providerUserId: 'jf-user-77',
            });
        });
    });

    it('generates reconciliation preview without auto-applying, shows unverified proposal warning, requires checkbox approval, invalidates on input change or 409', async () => {
        setupDefaultAdminMocks();
        render(<StreamingHistoryAdmin />);

        await waitFor(() => {
            expect(screen.getByTestId('import-checkpoints-table')).toBeInTheDocument();
        });

        fireEvent.click(screen.getByTestId('admin-tab-reconciliation'));
        expect(screen.getByTestId('reconciliation-backup-warning')).toBeInTheDocument();

        mockedApiFetch.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            if (url === STREAMING_ADMIN_RECONCILIATION_PREVIEW_URL && init?.method === 'POST') {
                return jsonResponse(samplePreviewResponse);
            }
            if (url === STREAMING_ADMIN_RECONCILIATION_APPLY_URL && init?.method === 'POST') {
                return jsonResponse(
                    {
                        error: {
                            code: 'CONFLICT',
                            message: 'Streaming history changed since preview was generated (expected revision 15, current 16).',
                        },
                    },
                    409
                );
            }
            return jsonResponse(sampleStatusResponse);
        });

        fireEvent.change(screen.getByTestId('reconcile-candidate-ids-input'), {
            target: { value: '19' },
        });
        fireEvent.change(screen.getByTestId('reconcile-limit-input'), {
            target: { value: '250' },
        });
        fireEvent.click(screen.getByTestId('reconcile-preview-btn'));

        await waitFor(() => {
            expect(screen.getByTestId('reconcile-preview-panel')).toBeInTheDocument();
        });

        const previewCall = mockedApiFetch.mock.calls.find(
            ([input, init]) => String(input) === STREAMING_ADMIN_RECONCILIATION_PREVIEW_URL && init?.method === 'POST'
        );
        expect(previewCall).toBeDefined();
        expect(JSON.parse(String(previewCall?.[1]?.body))).toEqual({
            candidateIds: [19],
            limit: 250,
        });
        expect(
            mockedApiFetch.mock.calls.some(([input]) => String(input) === STREAMING_ADMIN_RECONCILIATION_APPLY_URL)
        ).toBe(false);

        expect(screen.getByTestId('reconcile-preview-hash')).toHaveTextContent(samplePreviewResponse.previewHash);
        const warningBanner = screen.getByTestId('reconcile-unverified-proposal-warning');
        expect(warningBanner).toHaveTextContent(
            /Suspected classifications and epoch\/undated matches are unverified proposals, not proof of fabricated data/i
        );
        expect(warningBanner.textContent).not.toMatch(/default server ID/i);
        const applyBtn = screen.getByTestId('reconcile-apply-btn');
        expect(applyBtn).toBeDisabled();

        const checkbox = screen.getByTestId('reconcile-approve-checkbox');
        fireEvent.click(checkbox);
        expect(applyBtn).not.toBeDisabled();

        fireEvent.click(applyBtn);

        await waitFor(() => {
            expect(screen.getByTestId('reconcile-stale-conflict')).toBeInTheDocument();
        });

        const applyCall = mockedApiFetch.mock.calls.find(
            ([input, init]) => String(input) === STREAMING_ADMIN_RECONCILIATION_APPLY_URL && init?.method === 'POST'
        );
        expect(applyCall).toBeDefined();
        expect(JSON.parse(String(applyCall?.[1]?.body))).toEqual({
            previewHash: samplePreviewResponse.previewHash,
            approvalToken: samplePreviewResponse.approvalToken,
        });
        expect(screen.queryByTestId('reconcile-preview-panel')).not.toBeInTheDocument();

        fireEvent.click(screen.getByTestId('reconcile-preview-btn'));
        await waitFor(() => {
            expect(screen.getByTestId('reconcile-preview-panel')).toBeInTheDocument();
        });
        fireEvent.click(screen.getByTestId('reconcile-approve-checkbox'));
        expect(screen.getByTestId('reconcile-apply-btn')).not.toBeDisabled();

        fireEvent.change(screen.getByTestId('reconcile-limit-input'), {
            target: { value: '100' },
        });
        expect(screen.queryByTestId('reconcile-preview-panel')).not.toBeInTheDocument();
    });
});
