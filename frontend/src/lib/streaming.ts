import type {
    ActiveStreamSession,
    StreamingHistoryItem,
    StreamingLiveSummary,
} from '@/components/tabs/StreamingTab';

export interface SessionActionCapability {
    supported: boolean;
    reason: string;
}

export interface SessionCapabilitiesSummary {
    pause: SessionActionCapability;
    resume: SessionActionCapability;
    stop: SessionActionCapability;
    message: SessionActionCapability;
}

function hasSupportedCommand(commands: string[] | undefined, target: string): boolean {
    if (!Array.isArray(commands)) return false;
    const lower = target.toLowerCase();
    return commands.some((c) => c.trim().toLowerCase() === lower);
}

/**
 * Evaluates which session controls are genuinely supported for an active session
 * based on provider, remote-control/WebSocket flags, and advertised commands.
 */
export function evaluateSessionCapabilities(session: ActiveStreamSession): SessionCapabilitiesSummary {
    const provider = (session.provider || '').trim().toLowerCase();
    const isJellyfin = provider === 'jellyfin' || provider === 'demo' || session.sessionId.startsWith('demo-');

    if (!isJellyfin) {
        const reason = `Session control is not supported for provider "${session.provider || 'unknown'}"`;
        return {
            pause: { supported: false, reason },
            resume: { supported: false, reason },
            stop: { supported: false, reason },
            message: { supported: false, reason },
        };
    }

    const mediaCtrlSupported = session.supportsMediaControl === true;

    const pauseOrResumeSupported = mediaCtrlSupported;
    const pauseReason = pauseOrResumeSupported
        ? 'Pause Playback'
        : 'Client has no active remote-control WebSocket (SupportsMediaControl=false)';
    const resumeReason = pauseOrResumeSupported
        ? 'Resume Playback'
        : 'Client has no active remote-control WebSocket (SupportsMediaControl=false)';

    const stopSupported = mediaCtrlSupported;
    const stopReason = stopSupported
        ? 'Stop / Terminate Session'
        : 'Client does not advertise media control; fresh provider evidence is required';

    const explicitCanMessage =
        session.canSendMessage !== undefined
            ? session.canSendMessage
            : session.supportedCommands !== undefined
              ? hasSupportedCommand(session.supportedCommands, 'DisplayMessage')
              : false;

    const messageSupported = mediaCtrlSupported && explicitCanMessage;
    const messageReason = !mediaCtrlSupported
        ? 'Client has no active remote-control WebSocket (SupportsMediaControl=false)'
        : !explicitCanMessage
          ? 'Client does not advertise DisplayMessage remote-control capability'
          : 'Send On-Screen Message to Viewer';

    return {
        pause: { supported: pauseOrResumeSupported, reason: pauseReason },
        resume: { supported: pauseOrResumeSupported, reason: resumeReason },
        stop: { supported: stopSupported, reason: stopReason },
        message: { supported: messageSupported, reason: messageReason },
    };
}

/**
 * Recomputes liveSummary counters from an updated list of active sessions so optimistic
 * pause/resume/stop updates keep all summary counters and bandwidth figures consistent.
 */
export function recomputeLiveSummaryFromSessions(
    previous: StreamingLiveSummary,
    sessions: ActiveStreamSession[]
): StreamingLiveSummary {
    let directPlayCount = 0;
    let directStreamCount = 0;
    let transcodeCount = 0;
    let totalBitrateBps = 0;
    let activeSessionBytes = 0;
    let lanStreams = 0;
    let wanStreams = 0;

    for (const s of sessions) {
        if (s.playMethod === 'Transcode') {
            transcodeCount += 1;
        } else if (s.playMethod === 'DirectStream') {
            directStreamCount += 1;
        } else if (s.playMethod === 'DirectPlay') {
            directPlayCount += 1;
        }
        if (s.state === 'playing') {
            totalBitrateBps += Number.isFinite(s.bitrateBps) ? s.bitrateBps : 0;
        }
        activeSessionBytes += Number.isFinite(s.sessionDataBytes) ? s.sessionDataBytes : 0;
        if (s.isLan) {
            lanStreams += 1;
        } else {
            wanStreams += 1;
        }
    }

    const totalBandwidthMbps = Math.round((totalBitrateBps / 1_000_000) * 100) / 100;

    return {
        ...previous,
        activeStreams: sessions.length,
        directPlayCount,
        directStreamCount,
        transcodeCount,
        totalBitrateBps,
        totalBandwidthMbps,
        activeSessionBytes,
        lanStreams,
        wanStreams,
    };
}

/**
 * Determines whether a history record came from a Jellyfin historical item-level sync
 * rather than real-time session polling. Historical sync records only have item-level
 * played state and lack real-time play method, client/device, or measured byte telemetry.
 */
export function isHistoricalSyncEntry(item: Pick<StreamingHistoryItem, 'sessionKey' | 'playMethod'>): boolean {
    const key = (item.sessionKey || '').trim().toLowerCase();
    if (key.includes(':sync:')) return true;
    const method = (item.playMethod || '').trim().toLowerCase();
    return method === 'synced' || method === 'imported';
}

export function normalizePlayMethodKind(
    method?: string | null
): 'DirectPlay' | 'DirectStream' | 'Transcode' | 'Unknown' {
    const cleaned = (method || '').trim().toLowerCase();
    if (cleaned === 'transcode') return 'Transcode';
    if (cleaned === 'directstream' || cleaned === 'direct stream') return 'DirectStream';
    if (cleaned === 'directplay' || cleaned === 'direct play') return 'DirectPlay';
    return 'Unknown';
}

export function parseStreamingTimestamp(value: string): Date | null {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const normalized = trimmed.replace(' ', 'T');
    const withTime = /^\d{4}-\d{2}-\d{2}$/.test(normalized) ? `${normalized}T00:00:00` : normalized;
    const withZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(withTime) ? withTime : `${withTime}Z`;
    const parsed = new Date(withZone);
    return Number.isFinite(parsed.getTime()) ? parsed : null;
}

export function formatStreamingBucket(value: unknown, granularity: 'day' | 'month' | 'year' = 'day'): string {
    const label = String(value);
    if (granularity === 'month') return label.slice(0, 7);
    if (granularity === 'year') return label.split('-')[0];
    return label;
}

const FORMULA_INJECTION_PREFIX_RE = /^[\s]*[=+\-@\t\r]/;

/**
 * Neutralizes spreadsheet formula injection (CSV injection) and applies RFC 4180 quoting.
 * Cells starting with `=`, `+`, `-`, `@`, `\t`, or `\r` (including after leading whitespace)
 * are prefixed with a single quote `'` before RFC 4180 quoting.
 */
export function escapeStreamingCsvCell(value: unknown): string {
    if (value === null || value === undefined) return '';
    let str = String(value);
    if (FORMULA_INJECTION_PREFIX_RE.test(str)) {
        str = `'${str}`;
    }
    if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
        return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
}

export const STREAMING_HISTORY_CSV_HEADERS = [
    'ID',
    'Title',
    'Series',
    'MediaType',
    'Season',
    'Episode',
    'Year',
    'User',
    'Server',
    'Provider',
    'Client',
    'Device',
    'IPAddress',
    'PlayMethod',
    'DataAccuracy',
    'VideoResolution',
    'VideoCodec',
    'AudioCodec',
    'AudioChannels',
    'Container',
    'HardwareAcceleration',
    'BitrateBps',
    'BandwidthMbps',
    'DataUsedBytes',
    'WatchedSecs',
    'DurationSecs',
    'CompletionPct',
    'StartedAt',
    'LastSeenAt',
    'IsActive',
] as const;

/**
 * Serializes loaded playback history rows into an RFC 4180 CSV string with
 * spreadsheet formula-injection protection.
 */
export function buildStreamingHistoryCsv(items: StreamingHistoryItem[]): string {
    const headerRow = STREAMING_HISTORY_CSV_HEADERS.map(escapeStreamingCsvCell).join(',');
    const rows = items.map((item) => {
        const kind = normalizePlayMethodKind(item.playMethod);
        const playMethodLabel =
            kind === 'DirectPlay'
                ? 'Direct Play'
                : kind === 'DirectStream'
                  ? 'Direct Stream'
                  : kind === 'Transcode'
                    ? 'Transcode'
                    : 'Unknown';
        const dataAccuracy = isHistoricalSyncEntry(item)
            ? item.dataUsedBytes > 0 ? 'Estimated (Legacy Historical Sync)' : 'Unrecorded (Historical Sync)'
            : 'Estimated (Live Poll)';
        const cells: unknown[] = [
            item.id,
            item.itemName || '',
            item.seriesName || '',
            item.itemType || '',
            item.seasonNumber ?? '',
            item.episodeNumber ?? '',
            item.productionYear ?? '',
            item.userName || '',
            item.serverName || '',
            item.provider || '',
            item.clientName || '',
            item.deviceName || '',
            item.ipAddress || '',
            playMethodLabel,
            dataAccuracy,
            item.videoResolution || '',
            item.videoCodec || '',
            item.audioCodec || '',
            item.audioChannels ?? '',
            item.container || '',
            item.hwAccel || '',
            item.bitrateBps ?? 0,
            Number.isFinite(item.bandwidthMbps) ? item.bandwidthMbps : 0,
            item.dataUsedBytes ?? 0,
            item.watchedSecs ?? 0,
            item.durationSecs ?? 0,
            Number.isFinite(item.completionPct) ? item.completionPct : 0,
            item.startedAt || '',
            item.lastSeenAt || '',
            item.isActive ? 'true' : 'false',
        ];
        return cells.map(escapeStreamingCsvCell).join(',');
    });
    return [headerRow, ...rows].join('\r\n');
}

/**
 * Triggers a browser download of the CSV payload using a Blob URL and revokes the URL afterward.
 */
export function downloadStreamingHistoryCsv(items: StreamingHistoryItem[], filename?: string): void {
    const csvContent = buildStreamingHistoryCsv(items);
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    try {
        const link = document.createElement('a');
        link.href = url;
        link.download = filename || `aetherflow-streaming-history-${new Date().toISOString().slice(0, 10)}.csv`;
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    } finally {
        URL.revokeObjectURL(url);
    }
}
