import { apiFetch, fetcher } from '@/lib/fetcher';

export type WireGuardProviderState =
    | 'running'
    | 'stopped'
    | 'unconfigured'
    | 'not_installed'
    | 'error';

export type TailscaleProviderState =
    | 'running'
    | 'stopped'
    | 'needs_login'
    | 'needs_approval'
    | 'not_installed'
    | 'error';

export type NetworkServiceAction = 'start' | 'stop' | 'restart';
export type NetworkProviderId = 'wireguard' | 'tailscale';

export interface WireGuardPeer {
    name?: string;
    persistent?: boolean;
    public_key: string;
    allowed_ips: string;
    endpoint?: string;
    latest_handshake?: string;
    transfer_rx?: string;
    transfer_tx?: string;
    active?: boolean;
    persistent_keepalive?: number;
}

export interface WireGuardStatus {
    installed?: boolean;
    state?: WireGuardProviderState;
    error?: string;
    interface: string;
    public_key: string;
    listen_port: string;
    address?: string[];
    next_ip?: string;
    peers: WireGuardPeer[];
    service_state?: string;
    config_available?: boolean;
}

export interface TailscalePeer {
    id: string;
    hostname: string;
    dns_name: string;
    tailscale_ip: string;
    tailscale_ips?: string[];
    os: string;
    online: boolean;
    exit_node: boolean;
    exit_node_option?: boolean;
    rx_bytes?: number;
    tx_bytes?: number;
    last_seen?: string;
    tags?: string[];
}

export interface TailscaleStatus {
    installed?: boolean;
    state?: TailscaleProviderState;
    error?: string;
    backend_state: string;
    tailnet_name?: string;
    self?: TailscalePeer;
    peers: TailscalePeer[];
    magic_dns: boolean;
    health?: string[];
    auth_url?: string;
    advertised_routes?: string[];
    accept_routes?: boolean;
    advertise_exit_node?: boolean;
    exit_node?: string;
    exit_node_allow_lan_access?: boolean;
    route_approval?: 'managed_in_admin_console' | string;
    service_state?: string;
}

export interface NetworkStatusResponse {
    platform: string;
    runner_available?: boolean;
    checked_at?: string;
    wireguard_available: boolean;
    tailscale_available: boolean;
    wireguard?: WireGuardStatus;
    tailscale?: TailscaleStatus;
}

export interface WireGuardKeygenResponse {
    private_key: string;
    public_key: string;
}

export interface WireGuardPeerMutationPayload {
    public_key?: string;
    name: string;
    allowed_ips?: string;
    endpoint?: string;
    persistent_keepalive?: number;
}

export interface WireGuardPeerMutationResponse {
    message: string;
    peer: WireGuardPeer;
}

export interface TailscaleConnectResponse {
    message: string;
    auth_url?: string;
    backend_state?: string;
}

export interface TailscaleRoutesResponse {
    message: string;
    routes: string[];
}

export interface TailscaleSettingsPayload {
    accept_routes?: boolean;
    advertise_exit_node?: boolean;
    exit_node?: string;
    exit_node_allow_lan_access?: boolean;
}

export interface DiagnosticCheck {
    name?: string;
    check?: string;
    status?: string;
    ok?: boolean;
    passed?: boolean;
    detail?: string;
    message?: string;
}

export interface NetworkDiagnosticsResponse {
    provider: NetworkProviderId;
    service_state: string;
    logs: string;
    checks: DiagnosticCheck[];
}

export class NetworkRequestError extends Error {
    public readonly status: number;
    public readonly code: string;
    public readonly details?: unknown;

    constructor(status: number, code: string, message: string, details?: unknown) {
        super(message);
        this.name = 'NetworkRequestError';
        this.status = status;
        this.code = code;
        this.details = details;
    }
}

export const NETWORK_STATUS_ENDPOINT = '/api/v1/admin/network/status';
export const HANDSHAKE_RECENCY_WINDOW_SEC = 180;

/**
 * Shared SWR fetcher for the unified network status endpoint.
 * Throws on non-2xx responses and preserves backend `{ code, message }`.
 */
export async function fetchNetworkStatus(url: string = NETWORK_STATUS_ENDPOINT): Promise<NetworkStatusResponse> {
    return fetcher<NetworkStatusResponse>(url);
}

/**
 * Performs an authenticated network API request and throws a NetworkRequestError
 * with backend `{ code, message }` if the response is not 2xx.
 */
export async function networkApiRequest<T = { message?: string }>(
    url: string,
    init?: RequestInit
): Promise<T> {
    const headers = new Headers(init?.headers);
    if (init?.body && !headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
    }
    headers.set('Cache-Control', 'no-store');

    const res = await apiFetch(url, {
        ...init,
        headers,
    });

    let body: unknown = null;
    try {
        body = await res.json();
    } catch {
        body = null;
    }

    if (!res.ok) {
        const errObj = (body && typeof body === 'object' ? body : {}) as {
            code?: string;
            message?: string;
            error?: string;
            details?: unknown;
        };
        const code = typeof errObj.code === 'string' && errObj.code.trim()
            ? errObj.code.trim()
            : `HTTP_${res.status}`;
        const message =
            (typeof errObj.message === 'string' && errObj.message.trim()) ||
            (typeof errObj.error === 'string' && errObj.error.trim()) ||
            `Request failed (${res.status} ${res.statusText || 'Error'})`;
        throw new NetworkRequestError(res.status, code, message, errObj.details);
    }

    return (body ?? ({} as T)) as T;
}

export function extractErrorMessage(err: unknown, fallback = 'Operation failed.'): string {
    if (!err) return fallback;
    if (err instanceof NetworkRequestError) {
        return err.code && !err.code.startsWith('HTTP_')
            ? `${err.message} (${err.code})`
            : err.message;
    }
    if (typeof err === 'object') {
        const maybe = err as { code?: unknown; message?: unknown; error?: unknown };
        const msg =
            (typeof maybe.message === 'string' && maybe.message.trim()) ||
            (typeof maybe.error === 'string' && maybe.error.trim());
        const code = typeof maybe.code === 'string' && maybe.code.trim() ? maybe.code.trim() : '';
        if (msg) {
            return code && !code.startsWith('HTTP_') ? `${msg} (${code})` : msg;
        }
    }
    if (typeof err === 'string' && err.trim()) {
        return err.trim();
    }
    return fallback;
}

/**
 * Truthful WireGuard state resolution.
 * Never infers `running` from `wireguard_available` alone.
 */
export function resolveWireGuardState(status?: NetworkStatusResponse | null): WireGuardProviderState {
    if (!status) return 'stopped';
    const wg = status.wireguard;
    if (wg?.state) {
        return wg.state;
    }
    if (wg?.error) {
        return 'error';
    }
    if (wg?.installed === false || (!status.wireguard_available && !wg)) {
        return 'not_installed';
    }
    if (!wg) {
        // Binary may exist (wireguard_available=true), but no active interface/state object was returned.
        return 'stopped';
    }
    if (wg.config_available === false) {
        return 'unconfigured';
    }
    if (wg.service_state) {
        const svc = wg.service_state.toLowerCase();
        if (svc === 'running' || svc === 'active') return 'running';
        if (svc === 'failed' || svc === 'error') return 'error';
        if (svc === 'stopped' || svc === 'inactive') return 'stopped';
    }
    // Legacy compatibility only when public_key and interface are explicitly present without state
    if (wg.interface && wg.public_key && wg.installed === undefined && wg.service_state === undefined) {
        return 'running';
    }
    return 'stopped';
}

/**
 * Truthful Tailscale state resolution.
 * Never infers `running` from `tailscale_available` alone.
 */
export function resolveTailscaleState(status?: NetworkStatusResponse | null): TailscaleProviderState {
    if (!status) return 'stopped';
    const ts = status.tailscale;
    if (ts?.state) {
        return ts.state;
    }
    if (ts?.error) {
        return 'error';
    }
    if (ts?.installed === false || (!status.tailscale_available && !ts)) {
        return 'not_installed';
    }
    if (!ts) {
        return 'stopped';
    }
    const backend = (ts.backend_state || '').trim().toLowerCase();
    if (backend === 'running') return 'running';
    if (backend === 'needslogin' || backend === 'needs_login') return 'needs_login';
    if (backend === 'needsmachineauth' || backend === 'needs_approval') return 'needs_approval';
    if (backend === 'stopped' || backend === 'nostate' || backend === 'offline') return 'stopped';
    return 'stopped';
}

/**
 * Determines whether a WireGuard peer has an active recent handshake.
 * Rejects "0", "Never", empty, non-numeric, future-skewed, or stale epochs (>180s).
 */
export function isWireGuardPeerActive(
    peer: WireGuardPeer,
    nowEpochSec: number = Math.floor(Date.now() / 1000),
    maxAgeSec: number = HANDSHAKE_RECENCY_WINDOW_SEC
): boolean {
    const raw = (peer.latest_handshake ?? '').toString().trim();
    if (raw && raw !== '0' && raw.toLowerCase() !== 'never') {
        if (/^\d+$/.test(raw)) {
            const epoch = Number(raw);
            if (Number.isFinite(epoch) && epoch > 0) {
                const age = nowEpochSec - epoch;
                return age >= -30 && age <= maxAgeSec;
            }
        }
        const parsedMs = Date.parse(raw);
        if (!Number.isNaN(parsedMs) && parsedMs > 0) {
            const epoch = Math.floor(parsedMs / 1000);
            const age = nowEpochSec - epoch;
            return age >= -30 && age <= maxAgeSec;
        }
    }
    if (typeof peer.active === 'boolean' && (!raw || raw === '0' || raw.toLowerCase() === 'never')) {
        return raw === '0' || raw.toLowerCase() === 'never' ? false : peer.active;
    }
    return false;
}

export function formatHandshakeRelative(
    latestHandshake?: string,
    nowEpochSec: number = Math.floor(Date.now() / 1000)
): string {
    const raw = (latestHandshake ?? '').toString().trim();
    if (!raw || raw === '0' || raw.toLowerCase() === 'never') {
        return 'Never';
    }

    let epochSec: number | null = null;
    if (/^\d+$/.test(raw)) {
        const parsed = Number(raw);
        if (Number.isFinite(parsed) && parsed > 0) {
            epochSec = parsed;
        }
    } else {
        const parsedMs = Date.parse(raw);
        if (!Number.isNaN(parsedMs) && parsedMs > 0) {
            epochSec = Math.floor(parsedMs / 1000);
        }
    }

    if (epochSec === null) {
        return raw;
    }

    const diff = Math.max(0, nowEpochSec - epochSec);
    if (diff < 5) return 'Just now';
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) {
        const mins = Math.floor(diff / 60);
        const secs = diff % 60;
        return secs > 0 ? `${mins}m ${secs}s ago` : `${mins}m ago`;
    }
    if (diff < 86400) {
        const hours = Math.floor(diff / 3600);
        const mins = Math.floor((diff % 3600) / 60);
        return mins > 0 ? `${hours}h ${mins}m ago` : `${hours}h ago`;
    }
    const days = Math.floor(diff / 86400);
    return `${days}d ago`;
}

export function parseByteCount(value?: string | number | null): number {
    if (typeof value === 'number') {
        return Number.isFinite(value) && value >= 0 ? value : 0;
    }
    if (!value) return 0;
    const raw = String(value).trim();
    if (!raw) return 0;
    if (/^\d+(\.\d+)?$/.test(raw)) {
        const n = Number(raw);
        return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
    }
    const match = raw.match(/^([\d.]+)\s*(B|KB|KiB|MB|MiB|GB|GiB|TB|TiB)$/i);
    if (!match) return 0;
    const amount = Number(match[1]);
    if (!Number.isFinite(amount) || amount < 0) return 0;
    const unit = match[2].toUpperCase();
    const multipliers: Record<string, number> = {
        B: 1,
        KB: 1000,
        KIB: 1024,
        MB: 1000 ** 2,
        MIB: 1024 ** 2,
        GB: 1000 ** 3,
        GIB: 1024 ** 3,
        TB: 1000 ** 4,
        TIB: 1024 ** 4,
    };
    return Math.floor(amount * (multipliers[unit] || 1));
}

export function formatBytes(bytes?: number | string | null): string {
    const val = parseByteCount(bytes);
    if (val <= 0) return '0 B';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let idx = 0;
    let num = val;
    while (num >= 1024 && idx < units.length - 1) {
        num /= 1024;
        idx += 1;
    }
    return idx === 0 ? `${Math.round(num)} B` : `${num.toFixed(num >= 100 ? 0 : num >= 10 ? 1 : 2)} ${units[idx]}`;
}

export function formatByteRate(bytesPerSec?: number | null): string {
    if (bytesPerSec === null || bytesPerSec === undefined || !Number.isFinite(bytesPerSec) || bytesPerSec < 0) {
        return '—';
    }
    if (bytesPerSec === 0) {
        return '0 B/s';
    }
    return `${formatBytes(bytesPerSec)}/s`;
}

export interface TransferSampleSnapshot {
    timestampMs: number;
    rxBytes: number;
    txBytes: number;
}

export interface ComputedTransferRates {
    rxRateBytesPerSec: number | null;
    txRateBytesPerSec: number | null;
    counterReset: boolean;
}

/**
 * Computes true measured byte transfer rates across status polling snapshots.
 * Handles service/interface counter resets gracefully (returns 0 B/s with `counterReset=true`
 * rather than negative rates or fabricated counts).
 */
export function computeTransferRates(
    previous: TransferSampleSnapshot | null,
    current: TransferSampleSnapshot
): ComputedTransferRates {
    if (!previous) {
        return {
            rxRateBytesPerSec: null,
            txRateBytesPerSec: null,
            counterReset: false,
        };
    }

    const elapsedSec = (current.timestampMs - previous.timestampMs) / 1000;
    if (!Number.isFinite(elapsedSec) || elapsedSec <= 0.2) {
        return {
            rxRateBytesPerSec: null,
            txRateBytesPerSec: null,
            counterReset: false,
        };
    }

    const rxDelta = current.rxBytes - previous.rxBytes;
    const txDelta = current.txBytes - previous.txBytes;

    if (rxDelta < 0 || txDelta < 0) {
        return {
            rxRateBytesPerSec: 0,
            txRateBytesPerSec: 0,
            counterReset: true,
        };
    }

    return {
        rxRateBytesPerSec: rxDelta / elapsedSec,
        txRateBytesPerSec: txDelta / elapsedSec,
        counterReset: false,
    };
}

export type WireGuardTunnelMode = 'full_ipv4' | 'split';

export interface WireGuardClientConfigOptions {
    clientPrivateKey: string;
    clientAddress: string;
    serverPublicKey: string;
    serverEndpoint: string;
    dns?: string;
    tunnelMode: WireGuardTunnelMode;
    splitAllowedIps?: string;
    persistentKeepalive?: number;
}

export function deriveDefaultSplitSubnet(interfaceAddresses?: string[], peerAddress?: string): string {
    for (const address of interfaceAddresses ?? []) {
        const [ip, prefixText] = address.trim().split('/');
        const octets = ip.split('.').map(Number);
        const prefix = Number(prefixText);
        if (octets.length !== 4 || octets.some(n => !Number.isInteger(n) || n < 0 || n > 255)
            || !Number.isInteger(prefix) || prefix < 0 || prefix > 32 || !prefixText) continue;
        const value = octets.reduce((total, octet) => (total * 256) + octet, 0) >>> 0;
        const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
        const network = (value & mask) >>> 0;
        return [24, 16, 8, 0].map(shift => (network >>> shift) & 255).join('.') + '/' + prefix;
    }
    if (peerAddress) {
        const cleanIp = peerAddress.split(',')[0].trim().split('/')[0];
        const octets = cleanIp.split('.');
        if (octets.length === 4) return octets.slice(0, 3).join('.') + '.0/24';
    }
    return '10.66.66.0/24';
}

export function defaultServerEndpointHost(listenPort = '51820'): string {
    const port = listenPort.trim() || '51820';
    if (typeof window !== 'undefined' && window.location?.hostname) {
        return `${window.location.hostname}:${port}`;
    }
    return `vpn.example.com:${port}`;
}

/**
 * Builds a standard WireGuard `.conf` file purely in browser memory.
 * Never claims IPv6 (`::/0`) unless explicitly present in custom split CIDRs;
 * full-tunnel defaults strictly to IPv4 `0.0.0.0/0`.
 */
export function buildWireGuardClientConfig(options: WireGuardClientConfigOptions): string {
    const stripControl = (val: string) => Array.from(val)
        .filter(char => char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127).join('').trim();
    const address = stripControl(options.clientAddress);
    const dns = stripControl(options.dns ?? '');
    const endpoint = stripControl(options.serverEndpoint);
    const serverPubKey = stripControl(options.serverPublicKey);
    const clientPrivKey = stripControl(options.clientPrivateKey);
    const keepalive =
        typeof options.persistentKeepalive === 'number' &&
        Number.isFinite(options.persistentKeepalive) &&
        options.persistentKeepalive >= 0 && options.persistentKeepalive <= 65535
            ? Math.floor(options.persistentKeepalive)
            : 25;

    const allowedIps =
        options.tunnelMode === 'full_ipv4'
            ? '0.0.0.0/0'
            : stripControl(options.splitAllowedIps ?? '') || deriveDefaultSplitSubnet(undefined, address);

    const lines: string[] = [
        '[Interface]',
        `PrivateKey = ${clientPrivKey}`,
        `Address = ${address}`,
    ];

    if (dns) {
        lines.push(`DNS = ${dns}`);
    }

    lines.push(
        '',
        '[Peer]',
        `PublicKey = ${serverPubKey}`,
        `AllowedIPs = ${allowedIps}`,
    );

    if (endpoint) {
        lines.push(`Endpoint = ${endpoint}`);
    }

    if (keepalive >= 0) {
        lines.push(`PersistentKeepalive = ${keepalive}`);
    }

    return `${lines.join('\n')}\n`;
}

export function sanitizeConfigFilename(peerName?: string): string {
    const cleaned = (peerName || 'wg-peer')
        .toLowerCase()
        .replace(/[^a-z0-9-_]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 48);
    return `${cleaned || 'wg-peer'}.conf`;
}

export function parseRoutesList(input: string): string[] {
    return input
        .split(',')
        .map(r => r.trim())
        .filter(Boolean);
}

export function isValidSafeHttpsUrl(url?: string | null): boolean {
    if (!url) return false;
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'https:' && parsed.hostname === 'login.tailscale.com' &&
            !parsed.username && !parsed.password && (!parsed.port || parsed.port === '443') &&
            parsed.pathname.startsWith('/a/') && parsed.pathname.length > 3;
    } catch {
        return false;
    }
}
