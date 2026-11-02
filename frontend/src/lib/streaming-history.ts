export type HistoryProvenance = 'observed_session' | 'imported_event' | 'item_summary' | 'legacy_unverified';

export interface StreamingHistoryQuery {
    window?: 'all' | '7d' | '30d' | '90d' | '365d' | 'today' | 'month' | 'year' | 'custom';
    from?: string;
    until?: string;
    timezone?: string;
    provider?: string;
    serverId?: string;
    userId?: string;
    client?: string;
    device?: string;
    itemId?: string;
    libraryId?: string;
    genre?: string;
    mediaType?: string;
    playMethod?: string;
    provenance?: HistoryProvenance | 'all';
    search?: string;
    sort?: 'startedDesc' | 'startedAsc';
    pageSize?: number;
    includeExcluded?: boolean;
    cursor?: string;
    snapshot?: string;
}

export interface CanonicalStreamingHistoryItem {
    id: number;
    provider: string;
    serverId: string;
    sourceEventId: string | null;
    provenance: HistoryProvenance;
    timestampCertainty: 'observed' | 'source_event' | 'last_played' | 'unrecorded' | 'legacy_unverified';
    byteAccuracy: 'estimated' | 'unrecorded' | 'legacy_unverified';
    userId: string;
    userName: string;
    clientName: string | null;
    deviceName: string | null;
    deviceId?: string;
    ipAddress?: string;
    itemId: string;
    itemName: string;
    itemType: string | null;
    seriesName: string | null;
    playMethod: string | null;
    watchedSecs: number | null;
    durationSecs: number | null;
    estimatedBytes: number | null;
    startedAt: string | null;
    lastSeenAt: string | null;
    endedAt: string | null;
    isActive: boolean;
    included: boolean;
    policyStatus: string;
    libraryIds: string[];
    genres: string[];
}

export interface StreamingHistoryCounts {
    availableRecords: number;
    matchingRecords: number;
    undatedRecords: number;
    confirmedPlays: number;
    itemSummaries: number;
    legacyRecords: number;
    watchTimeSecs: number;
    estimatedBytes: number;
}

export interface StreamingHistoryPage {
    schemaVersion: 1;
    query: StreamingHistoryQuery;
    scope: {
        snapshotToken: string;
        watermark: number;
        revision: number;
        asOf: string;
        expiresAt: string;
        timezone: string;
        permissionScope: 'administrative' | 'linked_user';
        sampleRetentionDays: number;
        dateSemantics: string;
    };
    counts: StreamingHistoryCounts;
    items: CanonicalStreamingHistoryItem[];
    nextCursor: string | null;
}

export function streamingHistorySearchParams(query: StreamingHistoryQuery): URLSearchParams {
    const parameters = new URLSearchParams();
    for (const [name, value] of Object.entries(query)) {
        if (value !== undefined && value !== '') parameters.set(name, String(value));
    }
    return parameters;
}
