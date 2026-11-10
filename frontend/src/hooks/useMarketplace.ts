import useSWR, { useSWRConfig } from 'swr';
import { useLifecyclePollRecovery } from './useLifecyclePollRecovery';
import { useState, useEffect, useRef, useCallback } from 'react';
import { apiFetch, fetcher as defaultFetcher } from '@/lib/fetcher';

export function useGithubDownloads() {
  const [downloads, setDownloads] = useState<number | null>(null);

  useEffect(() => {
    fetch('https://api.github.com/repos/mceveritts/aetherflow/releases')
      .then((res) => (res.ok ? res.json() : Promise.reject(new Error('Failed to fetch releases'))))
      .then((releases) => {
        if (!Array.isArray(releases)) {
          setDownloads(null);
          return;
        }
        let total = 0;
        releases.forEach((release: { assets?: { download_count?: number }[] }) => {
          release.assets?.forEach((asset) => {
            if (typeof asset.download_count === 'number' && asset.download_count > 0) {
              total += asset.download_count;
            }
          });
        });
        setDownloads(total > 0 ? total : null);
      })
      .catch(() => setDownloads(null));
  }, []);

  return downloads;
}

export interface App {
    id: string;
    name: string;
    desc: string;
    hits: number;
    category: string;
    status: string;
    installed?: boolean;
    default_port?: number;
    active_port?: number;
    port?: number;
    internal_domain?: string;
    public_domain?: string;
    external_access_enabled?: boolean;
    tls_enabled?: boolean;
    web_path?: string;
    web_scheme?: string;
    bind_scope?: 'loopback' | 'network' | string;
    control_scope?: 'shared-vhost' | 'service' | string;
    progress: number;
    started_at?: string;
    job_id?: string;
    log_line?: string;
    installed_version?: string;
    latest_version?: string;
    update_available: boolean;
    update_checked_at?: string;
    checked_at?: string;
    update_url?: string;
    update_error?: string;
    /** Public terminal outcome of the most recent lifecycle job. */
    last_job?: MarketplaceJobOutcome;
    inventory_known?: boolean;
    inventory_authenticated?: boolean;
    inventory_mode?: 'authenticated' | 'public_redacted' | string;
}

export interface MarketplaceJobOutcome {
    job_id?: string;
    message?: string;
    action: 'install' | 'reinstall' | 'update' | 'remove' | string;
    status: 'completed' | 'failed' | string;
    started_at: string;
    finished_at: string;
    expected_target_version?: string;
    achieved_version?: string;
    failed_stage?: string;
    exit_code?: number;
    sanitized_summary?: string;
    target_unconfirmed?: boolean;
    target_mismatch?: boolean;
}

export type PendingAction = 'installing' | 'reinstalling' | 'uninstalling' | 'updating';
export const LIFECYCLE_RECEIPT_TIMEOUT_MS = 120000;

export interface UseMarketplaceOptions {
    requireAuth?: boolean;
}

export interface MarketplaceResponseEnvelope {
    apps?: App[];
    packages?: App[];
    items?: App[];
    data?: App[] | MarketplaceResponseEnvelope;
    inventory_authenticated?: boolean;
    inventory_mode?: 'authenticated' | 'public_redacted';
    inventory_known?: boolean;
}

export async function dispatchPackageUpdate(appId: string, expectedTargetVersion?: string): Promise<Response> {
    const init: RequestInit = { method: 'POST' };
    if (expectedTargetVersion) {
        init.headers = { 'Content-Type': 'application/json' };
        init.body = JSON.stringify({ expected_target_version: expectedTargetVersion });
    }
    return apiFetch(`/api/v1/admin/packages/${encodeURIComponent(appId)}/update`, init);
}

export interface TransportAuthState {
    authenticated: boolean;
    mode: 'authenticated' | 'public_redacted';
    seq: number;
}

export type TransportAuthStateValue = TransportAuthState | 'public_redacted' | 'authenticated';
export const latestTransportAuthByEndpoint = new Map<string, TransportAuthStateValue>();
let transportAuthSeq = 0;

interface LifecyclePayloadMetadata {
    __settledSeq?: number;
    __requestSeq?: number;
    __staleRequest?: boolean;
    __stalePublicIgnored?: boolean;
    __resolvedInventoryAuth?: TransportAuthStateValue;
    inventory_mode?: string;
    inventoryMode?: string;
    inventory_authenticated?: boolean;
    inventoryAuthenticated?: boolean;
}

export const latestSettledPayloadByEndpoint = new Map<string, unknown>();

export let globalRequestSeq = 0;
export let latestSettledRequestSeq = 0;
export let latestRevokedRequestSeq = 0;
export let latestAuthoritativeAuthSeq = 0;
export let globalRevokedAuth = false;

export function getPayloadSeq(payload: unknown): number {
    if (!payload || typeof payload !== 'object') return -1;
    const metadata = payload as LifecyclePayloadMetadata;
    const seq = metadata.__settledSeq ?? metadata.__requestSeq;
    if (typeof seq === 'number') return seq;
    if (Array.isArray(payload) && payload.length > 0 && payload[0] && typeof payload[0] === 'object') {
        const itemSeq = payload[0].__settledSeq ?? payload[0].__requestSeq;
        if (typeof itemSeq === 'number') return itemSeq;
    }
    return 0;
}

export function recordSettledPayload(url: string, payload: unknown, requestSeq?: number): void {
    const seq = requestSeq ?? getPayloadSeq(payload) ?? latestSettledRequestSeq;
    if (payload && typeof payload === 'object') {
        try {
            Object.defineProperty(payload, '__settledSeq', {
                value: seq,
                enumerable: false,
                configurable: true,
                writable: true,
            });
        } catch {
            (payload as unknown as LifecyclePayloadMetadata).__settledSeq = seq;
        }
        if (Array.isArray(payload)) {
            for (const item of payload) {
                if (item && typeof item === 'object') {
                    try {
                        Object.defineProperty(item, '__settledSeq', {
                            value: seq,
                            enumerable: false,
                            configurable: true,
                            writable: true,
                        });
                    } catch {
                        (item as unknown as LifecyclePayloadMetadata).__settledSeq = seq;
                    }
                }
            }
        }
    }

    latestSettledPayloadByEndpoint.set(url, payload);
    const basePath = url.split('?')[0];
    const existingBase = latestSettledPayloadByEndpoint.get(basePath);
    if (!existingBase || seq >= getPayloadSeq(existingBase)) {
        latestSettledPayloadByEndpoint.set(basePath, payload);
    }
    if (url.includes('marketplace')) {
        const canonicalKeys = [
            '/v1/marketplace/packages',
            '/api/v1/marketplace/packages',
            '/api/v1/public/marketplace',
            '/api/marketplace/packages',
        ];
        if (seq >= latestSettledRequestSeq) {
            for (const key of canonicalKeys) {
                const existing = latestSettledPayloadByEndpoint.get(key);
                if (!existing || seq >= getPayloadSeq(existing)) {
                    latestSettledPayloadByEndpoint.set(key, payload);
                }
            }
        }
    }
}

export function getSettledPayload(url?: string): unknown {
    const candidateKeys = new Set<string>();
    if (url) {
        candidateKeys.add(url);
        candidateKeys.add(url.split('?')[0]);
    }
    candidateKeys.add('/v1/marketplace/packages');
    candidateKeys.add('/api/v1/marketplace/packages');
    candidateKeys.add('/api/v1/public/marketplace');
    candidateKeys.add('/api/marketplace/packages');

    let bestCandidate: unknown = undefined;
    let maxSeq = -1;

    for (const key of candidateKeys) {
        const payload = latestSettledPayloadByEndpoint.get(key);
        if (payload !== undefined) {
            const seq = getPayloadSeq(payload);
            if (seq > maxSeq) {
                maxSeq = seq;
                bestCandidate = payload;
            } else if (bestCandidate === undefined) {
                bestCandidate = payload;
            }
        }
    }

    if (!url || url.includes('marketplace')) {
        for (const [key, payload] of latestSettledPayloadByEndpoint.entries()) {
            if (payload !== undefined && (key.includes('marketplace') || key.startsWith('/v1/') || key.startsWith('/api/'))) {
                const seq = getPayloadSeq(payload);
                if (seq > maxSeq) {
                    maxSeq = seq;
                    bestCandidate = payload;
                }
            }
        }
    }

    return bestCandidate;
}

export function scrubAllSettledPayloads(): void {
    for (const cached of latestSettledPayloadByEndpoint.values()) {
        scrubMarketplacePayloadInPlace(cached);
    }
}

export function resetMarketplaceAuthSequence(): void {
    globalRequestSeq = 0;
    latestSettledRequestSeq = 0;
    latestRevokedRequestSeq = 0;
    latestAuthoritativeAuthSeq = 0;
    globalRevokedAuth = false;
    latestTransportAuthByEndpoint.clear();
    latestSettledPayloadByEndpoint.clear();
}

export function resetMarketplaceAuthTrackingForTests(): void {
    resetMarketplaceAuthSequence();
}

export function getCurrentSettledAuthMode(url?: string): 'authenticated' | 'public_redacted' {
    if (globalRevokedAuth) return 'public_redacted';
    if (!url) return 'public_redacted';
    const entry = latestTransportAuthByEndpoint.get(url) ??
        latestTransportAuthByEndpoint.get(url.split('?')[0]) ??
        latestTransportAuthByEndpoint.get('/api/marketplace/packages') ??
        latestTransportAuthByEndpoint.get('/api/v1/public/marketplace') ??
        latestTransportAuthByEndpoint.get('/v1/marketplace/packages');
    if (!entry) return 'public_redacted';
    if (entry === 'public_redacted') return 'public_redacted';
    if (entry === 'authenticated') return 'authenticated';
    return (entry.authenticated && entry.mode === 'authenticated') ? 'authenticated' : 'public_redacted';
}

const originalMapClear = latestTransportAuthByEndpoint.clear.bind(latestTransportAuthByEndpoint);
latestTransportAuthByEndpoint.clear = function (): void {
    globalRequestSeq = 0;
    latestSettledRequestSeq = 0;
    latestRevokedRequestSeq = 0;
    latestAuthoritativeAuthSeq = 0;
    globalRevokedAuth = false;
    latestSettledPayloadByEndpoint.clear();
    originalMapClear();
};

type AuthListener = (entry: TransportAuthState, url: string) => void;
const authListeners = new Set<AuthListener>();

export function subscribeAuthChange(listener: AuthListener): () => void {
    authListeners.add(listener);
    return () => {
        authListeners.delete(listener);
    };
}

export function notifyAuthListeners(url: string, entry: TransportAuthState): void {
    authListeners.forEach(listener => {
        try {
            listener(entry, url);
        } catch {
            // ignore listener error
        }
    });
}

export function isAuthFailureError(error: unknown): boolean {
    if (!error) return false;
    const anyErr = error as {
        status?: unknown;
        statusCode?: unknown;
        response?: { status?: unknown };
        message?: unknown;
    };
    const rawStatus = anyErr?.status ?? anyErr?.statusCode ?? anyErr?.response?.status;

    if (typeof rawStatus === 'number' && Number.isFinite(rawStatus)) {
        return rawStatus === 401 || rawStatus === 403;
    }

    if (typeof rawStatus === 'string' && /^\s*\d{3}\s*$/.test(rawStatus)) {
        const parsed = Number(rawStatus.trim());
        return parsed === 401 || parsed === 403;
    }

    const message = typeof anyErr?.message === 'string' ? anyErr.message : String(error);
    if (/\b(?:unauthorized|forbidden)\b/i.test(message)) {
        return true;
    }
    if (/(?:^\s*|\b(?:http|status(?:\s+code)?|error)\s*[:=]?\s*)(?:401|403)\b/i.test(message)) {
        return true;
    }
    return false;
}

export function recordTransportAuth(
    url: string,
    state: { authenticated: boolean; mode: 'authenticated' | 'public_redacted' } | 'public_redacted' | 'authenticated',
    explicitSeq?: number
): TransportAuthState {
    if (explicitSeq !== undefined && explicitSeq < latestAuthoritativeAuthSeq) {
        // Stale callback, ignore completely!
        const existing = latestTransportAuthByEndpoint.get(url);
        if (existing && typeof existing === 'object') {
            return existing;
        }
        return {
            authenticated: !globalRevokedAuth,
            mode: globalRevokedAuth ? 'public_redacted' : 'authenticated',
            seq: transportAuthSeq,
        };
    }

    const isPublic = state === 'public_redacted' ||
        (typeof state === 'object' && (!state.authenticated || state.mode === 'public_redacted'));

    if (explicitSeq !== undefined) {
        latestAuthoritativeAuthSeq = Math.max(latestAuthoritativeAuthSeq, explicitSeq);
        latestSettledRequestSeq = Math.max(latestSettledRequestSeq, explicitSeq);
        if (isPublic) {
            latestRevokedRequestSeq = Math.max(latestRevokedRequestSeq, explicitSeq);
            globalRevokedAuth = true;
            scrubAllSettledPayloads();
        } else {
            globalRevokedAuth = false;
        }
    } else {
        // External non-fetch event (no explicitSeq)
        // Use latestSettledRequestSeq (NOT globalRequestSeq) or only advance up to latestSettledRequestSeq
        if (isPublic) {
            latestRevokedRequestSeq = Math.max(latestRevokedRequestSeq, latestSettledRequestSeq);
            globalRevokedAuth = true;
            scrubAllSettledPayloads();
        } else {
            globalRevokedAuth = false;
        }
    }

    const transportEntry: TransportAuthState = {
        authenticated: !isPublic,
        mode: isPublic ? 'public_redacted' : 'authenticated',
        seq: ++transportAuthSeq,
    };
    latestTransportAuthByEndpoint.set(url, transportEntry);
    const basePath = url.split('?')[0];
    latestTransportAuthByEndpoint.set(basePath, transportEntry);
    if (url.includes('marketplace')) {
        latestTransportAuthByEndpoint.set('/api/marketplace/packages', transportEntry);
        latestTransportAuthByEndpoint.set('/api/v1/public/marketplace', transportEntry);
        latestTransportAuthByEndpoint.set('/v1/marketplace/packages', transportEntry);
    }
    notifyAuthListeners(url, transportEntry);
    return transportEntry;
}

export const PUBLIC_PACKAGE_ALLOWLIST = new Set<string>([
    'id',
    'name',
    'desc',
    'description',
    'category',
    'icon',
    'tags',
    'default_port',
    'website',
    'documentation_url',
    'retirement_status',
    'retired_reason',
    'author',
    'license',
    'screenshots',
    'features',
    'dependencies',
    'conflicts',
    'disclaimers',
    'hits',
]);

export function sanitizePublicPackage<T extends Record<string, unknown>>(item: T): T {
    if (!item || typeof item !== 'object') return item;

    // 1. In-place scrubbing of original object so any existing references lose secret/runtime fields
    const target = item as Record<string, unknown>;
    const keys = Object.keys(item);
    for (const key of keys) {
        if (!PUBLIC_PACKAGE_ALLOWLIST.has(key)) {
            delete target[key];
        }
    }
    target.installed = false;
    target.status = 'not_installed';
    target.update_available = false;
    target.inventory_known = false;
    target.inventory_mode = 'public_redacted';
    target.inventory_authenticated = false;
    target.inventoryKnown = false;
    target.inventoryMode = 'public_redacted';
    target.inventoryAuthenticated = false;

    // Explicitly delete any non-allowlisted properties that might be non-enumerable or inherited
    delete target.version;
    delete target.installed_version;
    delete target.latest_version;
    delete target.current_version;
    delete target.target_version;
    delete target.achieved_version;
    delete target.checked_at;
    delete target.last_checked_at;
    delete target.update_checked_at;
    delete target.update_error;
    delete target.last_error;
    delete target.error;
    delete target.update_url;
    delete target.source_key;
    delete target.port;
    delete target.active_port;
    delete target.assigned_port;
    delete target.domains;
    delete target.domain;
    delete target.local_domain;
    delete target.public_domain;
    delete target.internal_domain;
    delete target.external_access_enabled;
    delete target.tls_enabled;
    delete target.ingress;
    delete target.url;
    delete target.access_url;
    delete target.service_status;
    delete target.health;
    delete target.pid;
    delete target.memory_mb;
    delete target.cpu_percent;
    delete target.uptime;
    delete target.config_path;
    delete target.install_path;
    delete target.progress;
    delete target.log_line;
    delete target.job_id;
    delete target.active_job;
    delete target.last_job;
    delete target.last_job_outcome;
    delete target.started_at;

    // 2. Strict allowlist projection: build a clean fresh object with ONLY allowed keys
    const clean: Record<string, unknown> = {};
    for (const key of PUBLIC_PACKAGE_ALLOWLIST) {
        if (key in item && item[key] !== undefined) {
            clean[key] = item[key];
        }
    }
    clean.installed = false;
    clean.status = 'not_installed';
    clean.update_available = false;
    clean.inventory_known = false;
    clean.inventory_mode = 'public_redacted';
    clean.inventory_authenticated = false;
    clean.inventoryKnown = false;
    clean.inventoryMode = 'public_redacted';
    clean.inventoryAuthenticated = false;

    return clean as T;
}

export const PUBLIC_ENVELOPE_ALLOWLIST = new Set<string>([
    'apps',
    'packages',
    'items',
    'data',
    'inventory_known',
    'inventory_mode',
    'inventory_authenticated',
    'inventoryKnown',
    'inventoryMode',
    'inventoryAuthenticated',
    '__resolvedInventoryAuth',
    '__staleRequest',
    '__stalePublicIgnored',
    '__requestSeq',
    '__settledSeq',
]);

export function extractPackages<T = App>(payload: unknown): T[] | null {
    if (!payload || typeof payload !== 'object') return null;
    if (Array.isArray(payload)) return payload as T[];
    const env = payload as Record<string, unknown>;
    if (Array.isArray(env.apps)) return env.apps as T[];
    if (Array.isArray(env.packages)) return env.packages as T[];
    if (Array.isArray(env.items)) return env.items as T[];
    if (Array.isArray(env.data)) return env.data as T[];
    if (env.data && typeof env.data === 'object') {
        return extractPackages<T>(env.data);
    }
    return null;
}

export function scrubMarketplacePayloadInPlace(payload: unknown): unknown {
    if (!payload || typeof payload !== 'object') return payload;

    if (Array.isArray(payload)) {
        for (let i = 0; i < payload.length; i++) {
            const item = payload[i];
            if (item && typeof item === 'object') {
                payload[i] = sanitizePublicPackage(item as Record<string, unknown>);
            }
        }
        const arrObj = payload as unknown as Record<string, unknown>;
        arrObj.inventory_authenticated = false;
        arrObj.inventory_mode = 'public_redacted';
        arrObj.inventory_known = false;
        arrObj.inventoryAuthenticated = false;
        arrObj.inventoryMode = 'public_redacted';
        arrObj.inventoryKnown = false;
        try {
            Object.defineProperty(payload, '__resolvedInventoryAuth', {
                value: 'public_redacted',
                enumerable: false,
                configurable: true,
                writable: true,
            });
        } catch {
            (payload as unknown as LifecyclePayloadMetadata).__resolvedInventoryAuth = 'public_redacted';
        }
    } else {
        const obj = payload as Record<string, unknown>;

        // 1. Support all envelope collection arrays: apps, packages, items
        const collectionKeys = ['apps', 'packages', 'items'] as const;
        for (const key of collectionKeys) {
            const arr = obj[key];
            if (Array.isArray(arr)) {
                for (let i = 0; i < arr.length; i++) {
                    const item = arr[i];
                    if (item && typeof item === 'object') {
                        arr[i] = sanitizePublicPackage(item as Record<string, unknown>);
                    }
                }
                try {
                    Object.defineProperty(arr, '__resolvedInventoryAuth', {
                        value: 'public_redacted',
                        enumerable: false,
                        configurable: true,
                        writable: true,
                    });
                } catch {
                    (arr as unknown as LifecyclePayloadMetadata).__resolvedInventoryAuth = 'public_redacted';
                }
                const arrRec = arr as unknown as Record<string, unknown>;
                arrRec.inventory_known = false;
                arrRec.inventory_mode = 'public_redacted';
                arrRec.inventory_authenticated = false;
            }
        }

        // Nested data if payload.data is an array or envelope object!
        if (Array.isArray(obj.data)) {
            for (let i = 0; i < obj.data.length; i++) {
                const item = obj.data[i];
                if (item && typeof item === 'object') {
                    obj.data[i] = sanitizePublicPackage(item as Record<string, unknown>);
                }
            }
            try {
                Object.defineProperty(obj.data, '__resolvedInventoryAuth', {
                    value: 'public_redacted',
                    enumerable: false,
                    configurable: true,
                    writable: true,
                });
            } catch {
                (obj.data as unknown as LifecyclePayloadMetadata).__resolvedInventoryAuth = 'public_redacted';
            }
            const dataRec = obj.data as unknown as Record<string, unknown>;
            dataRec.inventory_known = false;
            dataRec.inventory_mode = 'public_redacted';
            dataRec.inventory_authenticated = false;
        } else if (obj.data && typeof obj.data === 'object') {
            scrubMarketplacePayloadInPlace(obj.data);
        }

        // 2. Restrict envelope-level properties on the envelope object itself!
        const keys = Object.keys(obj);
        for (const key of keys) {
            if (!PUBLIC_ENVELOPE_ALLOWLIST.has(key)) {
                delete obj[key];
            }
        }

        obj.inventory_known = false;
        obj.inventory_mode = 'public_redacted';
        obj.inventory_authenticated = false;
        try {
            Object.defineProperty(obj, '__resolvedInventoryAuth', {
                value: 'public_redacted',
                enumerable: false,
                configurable: true,
                writable: true,
            });
        } catch {
            obj.__resolvedInventoryAuth = 'public_redacted';
        }
    }
    return payload;
}

export const fetchMarketplaceData = async (url: string) => {
    const requestSeq = ++globalRequestSeq;
    let res: Response;
    try {
        res = await apiFetch(url);
    } catch (err: unknown) {
        try {
            (err as Record<string, unknown>).__requestSeq = requestSeq;
        } catch {
            // ignore if immutable
        }
        if (isAuthFailureError(err)) {
            if (requestSeq < latestAuthoritativeAuthSeq) {
                // Case A: Stale request error
                try {
                    (err as Record<string, unknown>).__staleRequest = true;
                } catch {
                    // ignore if immutable
                }
            } else {
                // Case B: Latest authoritative auth error
                latestAuthoritativeAuthSeq = requestSeq;
                latestSettledRequestSeq = Math.max(latestSettledRequestSeq, requestSeq);
                latestRevokedRequestSeq = requestSeq;
                globalRevokedAuth = true;
                recordTransportAuth(url, 'public_redacted', requestSeq);
                scrubAllSettledPayloads();
            }
        }
        // Non-authentication transport failure (network drop, timeout, etc.)
        // MUST NOT advance latestAuthoritativeAuthSeq or latestSettledRequestSeq!
        throw err;
    }
    if (!res.ok) {
        const error = new Error(`Request failed with status ${res.status}`);
        (error as unknown as { status: number }).status = res.status;
        try {
            (error as unknown as Record<string, unknown>).__requestSeq = requestSeq;
        } catch {
            // ignore if immutable
        }
        const isAuthFail = res.status === 401 || res.status === 403 || isAuthFailureError(error);

        if (isAuthFail) {
            if (requestSeq < latestAuthoritativeAuthSeq) {
                // Case A: Stale request error
                (error as unknown as Record<string, unknown>).__staleRequest = true;
            } else {
                // Case B: Latest authoritative auth error
                latestAuthoritativeAuthSeq = requestSeq;
                latestSettledRequestSeq = Math.max(latestSettledRequestSeq, requestSeq);
                latestRevokedRequestSeq = requestSeq;
                globalRevokedAuth = true;
                recordTransportAuth(url, 'public_redacted', requestSeq);
                scrubAllSettledPayloads();
            }
        }
        // Non-authentication HTTP failure (500, 502, 503, 504, etc.)
        // MUST NOT advance latestAuthoritativeAuthSeq or latestSettledRequestSeq!
        throw error;
    }

    const json = await res.json();
    if (json && typeof json === 'object') {
        try {
            Object.defineProperty(json, '__requestSeq', {
                value: requestSeq,
                enumerable: false,
                configurable: true,
                writable: true,
            });
        } catch {
            (json as Record<string, unknown>).__requestSeq = requestSeq;
        }

        const authState = resolveInventoryAuthState(json, res.headers);
        const isAuthResolved = authState.authenticated && authState.mode === 'authenticated';
        const resolvedAuthMode: 'authenticated' | 'public_redacted' = isAuthResolved ? 'authenticated' : 'public_redacted';

        let effectiveAuthMode: 'authenticated' | 'public_redacted';

        const isStale = requestSeq < latestAuthoritativeAuthSeq || requestSeq < latestSettledRequestSeq;

        if (isStale) {
            // Case A — Stale Request (requestSeq < latestAuthoritativeAuthSeq or requestSeq < latestSettledRequestSeq)
            // A newer request (seq > requestSeq) has ALREADY settled with an authoritative outcome!
            // Do NOT update latestSettledRequestSeq, latestRevokedRequestSeq, globalRevokedAuth, or latestTransportAuthByEndpoint!
            try {
                Object.defineProperty(json, '__staleRequest', {
                    value: true,
                    enumerable: false,
                    configurable: true,
                    writable: true,
                });
            } catch {
                (json as Record<string, unknown>).__staleRequest = true;
            }

            const currentSettledAuth = getCurrentSettledAuthMode(url);
            const isSettledAuthed = !globalRevokedAuth && currentSettledAuth === 'authenticated';

            if (isSettledAuthed) {
                // Regardless of whether stale response is 'public_redacted' OR 'authenticated',
                // ALWAYS return the newer settled payload from latestSettledPayloadByEndpoint when present!
                const cachedPayload = getSettledPayload(url);
                if (cachedPayload) {
                    return cachedPayload;
                }

                if (resolvedAuthMode === 'public_redacted') {
                    // Stale negative/public response, do NOT flip globalRevokedAuth or latestTransportAuthByEndpoint
                    // If latestSettledPayloadByEndpoint does not have an entry for endpointKey:
                    delete (json as Record<string, unknown>).inventory_authenticated;
                    delete (json as Record<string, unknown>).inventory_mode;
                    delete (json as Record<string, unknown>).inventory_known;
                    delete (json as Record<string, unknown>).inventoryAuthenticated;
                    delete (json as Record<string, unknown>).inventoryMode;
                    delete (json as Record<string, unknown>).inventoryKnown;
                    delete (json as Record<string, unknown>).__resolvedInventoryAuth;
                    try {
                        Object.defineProperty(json, '__stalePublicIgnored', {
                            value: true,
                            enumerable: false,
                            configurable: true,
                            writable: true,
                        });
                    } catch {
                        (json as Record<string, unknown>).__stalePublicIgnored = true;
                    }
                    const staleErr = new Error('Stale public response ignored');
                    (staleErr as unknown as Record<string, unknown>).__staleRequest = true;
                    try {
                        (staleErr as unknown as Record<string, unknown>).__requestSeq = requestSeq;
                    } catch {
                        // ignore if immutable
                    }
                    throw staleErr;
                } else {
                    effectiveAuthMode = 'authenticated';
                }
            } else {
                effectiveAuthMode = 'public_redacted';
                scrubMarketplacePayloadInPlace(json);
            }
        } else {
            // Case B — Latest Request (requestSeq >= latestSettledRequestSeq && requestSeq >= latestAuthoritativeAuthSeq)
            latestAuthoritativeAuthSeq = requestSeq;
            latestSettledRequestSeq = requestSeq;
            if (resolvedAuthMode === 'public_redacted') {
                latestRevokedRequestSeq = requestSeq;
                globalRevokedAuth = true;
                recordTransportAuth(url, 'public_redacted', requestSeq);
                scrubMarketplacePayloadInPlace(json);
                effectiveAuthMode = 'public_redacted';
                scrubAllSettledPayloads();
            } else {
                globalRevokedAuth = false;
                recordTransportAuth(url, 'authenticated', requestSeq);
                effectiveAuthMode = 'authenticated';
            }
        }

        const effectiveAuthState = {
            authenticated: effectiveAuthMode === 'authenticated',
            mode: effectiveAuthMode,
        };

        try {
            Object.defineProperty(json, '__resolvedInventoryAuth', {
                value: effectiveAuthMode === 'public_redacted' ? 'public_redacted' : effectiveAuthState,
                enumerable: false,
                configurable: true,
                writable: true,
            });
        } catch {
            (json as Record<string, unknown>).__resolvedInventoryAuth =
                effectiveAuthMode === 'public_redacted' ? 'public_redacted' : effectiveAuthState;
        }

        const rawInventoryMode = (json as Record<string, unknown>).inventory_mode ?? (json as Record<string, unknown>).inventoryMode;
        const preservedMode = (effectiveAuthState.authenticated && rawInventoryMode && typeof rawInventoryMode === 'string' && rawInventoryMode !== 'public_redacted')
            ? rawInventoryMode
            : effectiveAuthState.mode;

        (json as Record<string, unknown>).inventory_authenticated = effectiveAuthState.authenticated;
        (json as Record<string, unknown>).inventory_mode = preservedMode;
        (json as Record<string, unknown>).inventoryAuthenticated = effectiveAuthState.authenticated;
        (json as Record<string, unknown>).inventoryMode = preservedMode;
        (json as Record<string, unknown>).inventory_known = effectiveAuthState.authenticated;
        (json as Record<string, unknown>).inventoryKnown = effectiveAuthState.authenticated;

        const list = extractPackages<Record<string, unknown>>(json);
        if (list) {
            normalizeArrayWithInventoryAuth(list, effectiveAuthState);
            try {
                Object.defineProperty(list, '__requestSeq', {
                    value: requestSeq,
                    enumerable: false,
                    configurable: true,
                    writable: true,
                });
            } catch {
                (list as unknown as LifecyclePayloadMetadata).__requestSeq = requestSeq;
            }
            if (isStale) {
                try {
                    Object.defineProperty(list, '__staleRequest', {
                        value: true,
                        enumerable: false,
                        configurable: true,
                        writable: true,
                    });
                } catch {
                    (list as unknown as LifecyclePayloadMetadata).__staleRequest = true;
                }
            }
        }

        if (requestSeq >= latestSettledRequestSeq) {
            recordSettledPayload(url, json, requestSeq);
        }
    }
    return json;
};

export function normalizeArrayWithInventoryAuth<T extends Record<string, unknown>>(
    target: T[] | Record<string, unknown>,
    authState: { authenticated: boolean; mode: 'authenticated' | 'public_redacted' }
): T[] | Record<string, unknown> {
    if (Array.isArray(target)) {
        if (!authState.authenticated || authState.mode === 'public_redacted') {
            for (let i = 0; i < target.length; i++) {
                const item = target[i];
                if (item && typeof item === 'object') {
                    target[i] = sanitizePublicPackage(item as Record<string, unknown>) as T;
                }
            }
            try {
                Object.defineProperty(target, '__resolvedInventoryAuth', {
                    value: 'public_redacted',
                    enumerable: false,
                    configurable: true,
                    writable: true,
                });
            } catch {
                (target as unknown as LifecyclePayloadMetadata).__resolvedInventoryAuth = 'public_redacted';
            }
            const listRec = target as unknown as Record<string, unknown>;
            listRec.inventory_authenticated = false;
            listRec.inventory_mode = 'public_redacted';
            listRec.inventory_known = false;
        }
        return target;
    } else if (target && typeof target === 'object') {
        if (!authState.authenticated || authState.mode === 'public_redacted') {
            scrubMarketplacePayloadInPlace(target);
        }
        return target;
    }
    return target;
}

const PENDING_TO_JOB_ACTIONS: Record<PendingAction, readonly string[]> = {
    installing: ['install', 'reinstall'],
    reinstalling: ['reinstall', 'install'],
    updating: ['update'],
    uninstalling: ['remove'],
};

/** A receipt is authoritative only when its identity and action both match. */
export function lifecycleIdentity(job: { job_id?: string; started_at?: string } | undefined): string | undefined {
    return job?.job_id || job?.started_at || undefined;
}
export function matchingJobOutcome(app: Pick<App, 'last_job'>, action: PendingAction, identity?: string): MarketplaceJobOutcome | undefined {
    const job = app.last_job;
    const allowedActions = PENDING_TO_JOB_ACTIONS[action];
    return identity && lifecycleIdentity(job) === identity && job?.action && allowedActions?.includes(job.action)
        ? job : undefined;
}
export function lastJobFailed(app: Pick<App, 'last_job'>, pending: string | undefined): boolean {
    const allowedActions = pending ? PENDING_TO_JOB_ACTIONS[pending as PendingAction] : undefined;
    return Boolean(allowedActions && app.last_job?.status === 'failed' && allowedActions.includes(app.last_job.action));
}
/** Only a fresh observation of the accepted job and action renews its deadline. */
export function matchingActiveJob(job: { job_id?: string; started_at?: string; status?: string; job_status?: string }, action: PendingAction, identity?: string): boolean {
    const phase = isLifecycleStatus(job.job_status) ? job.job_status : job.status;
    const phaseMatches =
        action === 'installing' || action === 'reinstalling'
            ? phase === 'installing' || phase === 'reinstalling'
            : phase === action;
    return Boolean(identity && lifecycleIdentity(job) === identity && phaseMatches);
}
export function isLifecycleStatus(status?: string): status is PendingAction {
    return status === 'installing' || status === 'reinstalling' || status === 'updating' || status === 'uninstalling';
}

const MODE_HEADER_KEYS = new Set([
    'x-aetherflow-inventory-mode',
    'x-inventory-mode',
    'inventory-mode',
    'inventory_mode',
    'inventorymode',
    'mode',
]);

const AUTH_HEADER_KEYS = new Set([
    'x-aetherflow-inventory-auth',
    'x-inventory-auth',
    'inventory-auth',
    'inventory_auth',
    'inventoryauth',
    'x-aetherflow-inventory-authenticated',
    'x-inventory-authenticated',
    'inventory-authenticated',
    'inventory_authenticated',
    'inventoryauthenticated',
    'x-aetherflow-inventory-known',
    'x-inventory-known',
    'inventory-known',
    'inventory_known',
    'inventoryknown',
    'authenticated',
]);

const ALL_HEADER_LOOKUP_KEYS = [
    'x-aetherflow-inventory-mode',
    'x-inventory-mode',
    'inventory-mode',
    'inventory_mode',
    'inventoryMode',
    'mode',
    'x-aetherflow-inventory-auth',
    'x-inventory-auth',
    'inventory-auth',
    'inventory_auth',
    'inventoryAuth',
    'x-aetherflow-inventory-authenticated',
    'x-inventory-authenticated',
    'inventory-authenticated',
    'inventory_authenticated',
    'inventoryAuthenticated',
    'x-aetherflow-inventory-known',
    'x-inventory-known',
    'inventory-known',
    'inventory_known',
    'inventoryKnown',
    'authenticated',
];

function isNegativeModeValue(val: unknown): boolean {
    if (typeof val === 'string') {
        const parts = val.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
        return parts.some(s => s === 'public_redacted' || s === 'redacted' || s === 'unauthenticated' || s === 'public');
    }
    return false;
}

function isNegativeAuthValue(val: unknown): boolean {
    if (val === false) return true;
    if (val === 0) return true;
    if (typeof val === 'string') {
        const parts = val.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
        return parts.some(s => s === 'false' || s === '0' || s === 'no' || s === 'public_redacted' || s === 'redacted' || s === 'unauthenticated' || s === 'public');
    }
    return false;
}

function isAffirmativeModeValue(val: unknown): boolean {
    if (typeof val === 'string') {
        const parts = val.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
        return parts.some(s => s === 'authenticated' || s === 'full');
    }
    return false;
}

function isAffirmativeAuthValue(val: unknown): boolean {
    if (val === true) return true;
    if (val === 1) return true;
    if (typeof val === 'string') {
        const parts = val.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
        return parts.some(s => s === 'true' || s === '1' || s === 'yes' || s === 'authenticated' || s === 'full');
    }
    return false;
}

function hasAffirmativeItemMetadata(item: Record<string, unknown>): boolean {
    if (!item || typeof item !== 'object') return false;
    const meta = (item.meta && typeof item.meta === 'object') ? (item.meta as Record<string, unknown>) : null;
    const known = item.inventory_known ?? item.inventoryKnown ?? meta?.inventory_known ?? meta?.inventoryKnown;
    const auth = item.inventory_authenticated ?? item.inventoryAuthenticated ?? item.inventory_auth ?? item.inventoryAuth ?? item.authenticated ?? meta?.inventory_authenticated ?? meta?.inventoryAuthenticated ?? meta?.inventory_auth ?? meta?.inventoryAuth ?? meta?.authenticated;
    const mode = item.inventory_mode ?? item.inventoryMode ?? item.mode ?? meta?.inventory_mode ?? meta?.inventoryMode ?? meta?.mode;
    return (
        isAffirmativeAuthValue(known) ||
        isAffirmativeAuthValue(auth) ||
        isAffirmativeModeValue(mode)
    );
}

export function resolveInventoryAuthState(
    payload: unknown,
    headerMode?: unknown,
    headerAuth?: unknown
): { authenticated: boolean; mode: 'authenticated' | 'public_redacted' } {
    const collectedModes: unknown[] = [];
    const collectedAuths: unknown[] = [];

    const topLevelModes: unknown[] = [];
    const topLevelAuths: unknown[] = [];

    const recordMode = (val: unknown, isTopLevel = false) => {
        if (val !== undefined && val !== null) {
            if (typeof val === 'string') {
                const parts = val.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
                for (const part of parts) {
                    collectedModes.push(part);
                    if (isTopLevel) topLevelModes.push(part);
                }
            } else {
                collectedModes.push(val);
                if (isTopLevel) topLevelModes.push(val);
            }
        }
    };

    const recordAuth = (val: unknown, isTopLevel = false) => {
        if (val !== undefined && val !== null) {
            if (typeof val === 'string') {
                const parts = val.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
                for (const part of parts) {
                    collectedAuths.push(part);
                    if (isTopLevel) topLevelAuths.push(part);
                }
            } else {
                collectedAuths.push(val);
                if (isTopLevel) topLevelAuths.push(val);
            }
        }
    };

    const extractFromHeadersOrObject = (h: unknown, isTopLevel = false, allowShortKeys = true) => {
        if (!h || typeof h !== 'object') return;

        const visited = new Set<string>();

        if (!Array.isArray(h) && typeof (h as { forEach?: unknown }).forEach === 'function') {
            try {
                (h as { forEach: (cb: (v: unknown, k: unknown) => void) => void }).forEach((val: unknown, key: unknown) => {
                    if (typeof key === 'string') {
                        const kLower = key.toLowerCase().trim();
                        visited.add(kLower);
                        if (MODE_HEADER_KEYS.has(kLower) && (allowShortKeys || kLower !== 'mode')) {
                            recordMode(val, isTopLevel);
                        }
                        if (AUTH_HEADER_KEYS.has(kLower) && (allowShortKeys || kLower !== 'authenticated')) {
                            recordAuth(val, isTopLevel);
                        }
                    }
                });
            } catch {
                // fall through
            }
        }

        if (typeof (h as { get?: unknown }).get === 'function') {
            const gettable = h as { get: (k: string) => unknown };
            for (const key of ALL_HEADER_LOOKUP_KEYS) {
                const kLower = key.toLowerCase();
                if (!visited.has(kLower)) {
                    try {
                        const val = gettable.get(key);
                        if (val !== null && val !== undefined) {
                            if (MODE_HEADER_KEYS.has(kLower) && (allowShortKeys || kLower !== 'mode')) {
                                recordMode(val, isTopLevel);
                            }
                            if (AUTH_HEADER_KEYS.has(kLower) && (allowShortKeys || kLower !== 'authenticated')) {
                                recordAuth(val, isTopLevel);
                            }
                        }
                    } catch {
                        // ignore
                    }
                }
            }
        }

        for (const key of Object.keys(h as Record<string, unknown>)) {
            const kLower = key.toLowerCase().trim();
            const val = (h as Record<string, unknown>)[key];
            if (val !== undefined && val !== null) {
                if (MODE_HEADER_KEYS.has(kLower) && (allowShortKeys || kLower !== 'mode')) {
                    recordMode(val, isTopLevel);
                }
                if (AUTH_HEADER_KEYS.has(kLower) && (allowShortKeys || kLower !== 'authenticated')) {
                    recordAuth(val, isTopLevel);
                }
            }
        }
    };

    // 1. Process headerMode parameter
    if (typeof headerMode === 'string') {
        const parts = headerMode.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
        for (const part of parts) {
            recordMode(part, true);
            if (isNegativeAuthValue(part) || isAffirmativeAuthValue(part)) {
                recordAuth(part, true);
            }
        }
    } else if (typeof headerMode === 'boolean' || typeof headerMode === 'number') {
        recordAuth(headerMode, true);
    } else if (headerMode && typeof headerMode === 'object') {
        extractFromHeadersOrObject(headerMode, true, true);
    }

    // 2. Process headerAuth parameter
    if (typeof headerAuth === 'string') {
        const parts = headerAuth.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
        for (const part of parts) {
            recordAuth(part, true);
            if (isNegativeModeValue(part) || isAffirmativeModeValue(part)) {
                recordMode(part, true);
            }
        }
    } else if (typeof headerAuth === 'boolean' || typeof headerAuth === 'number') {
        recordAuth(headerAuth, true);
    } else if (headerAuth && typeof headerAuth === 'object') {
        extractFromHeadersOrObject(headerAuth, true, true);
    }

    // 3. Process payload / envelope
    let envelope: Record<string, unknown> | null = null;
    let items: Array<Record<string, unknown>> = [];

    if (payload && typeof payload === 'object') {
        const preResolved =
            (payload as Record<string, unknown>).__resolvedInventoryAuth as { authenticated?: boolean; mode?: 'authenticated' | 'public_redacted' } | undefined ||
            (payload as Record<string, unknown>).__inventoryAuthState as { authenticated?: boolean; mode?: 'authenticated' | 'public_redacted' } | undefined;
        if (preResolved) {
            if (preResolved.mode !== undefined) {
                recordMode(preResolved.mode, true);
            }
            if (preResolved.authenticated !== undefined) {
                recordAuth(preResolved.authenticated, true);
            }
        }

        const payloadObj = payload as Record<string, unknown>;
        if (payloadObj.inventory_mode !== undefined) recordMode(payloadObj.inventory_mode, true);
        if (payloadObj.inventoryMode !== undefined) recordMode(payloadObj.inventoryMode, true);
        if (payloadObj.inventory_authenticated !== undefined) recordAuth(payloadObj.inventory_authenticated, true);
        if (payloadObj.inventoryAuthenticated !== undefined) recordAuth(payloadObj.inventoryAuthenticated, true);
        if (payloadObj.inventory_auth !== undefined) recordAuth(payloadObj.inventory_auth, true);
        if (payloadObj.inventoryAuth !== undefined) recordAuth(payloadObj.inventoryAuth, true);
        if (payloadObj.inventory_known !== undefined) recordAuth(payloadObj.inventory_known, true);
        if (payloadObj.inventoryKnown !== undefined) recordAuth(payloadObj.inventoryKnown, true);
        if (payloadObj.authenticated !== undefined) recordAuth(payloadObj.authenticated, true);

        if (payloadObj.headers && typeof payloadObj.headers === 'object') {
            extractFromHeadersOrObject(payloadObj.headers, true, true);
        }

        if (payloadObj.meta && typeof payloadObj.meta === 'object') {
            const meta = payloadObj.meta as Record<string, unknown>;
            if (meta.inventory_mode !== undefined) recordMode(meta.inventory_mode, true);
            if (meta.inventoryMode !== undefined) recordMode(meta.inventoryMode, true);
            if (meta.inventory_authenticated !== undefined) recordAuth(meta.inventory_authenticated, true);
            if (meta.inventoryAuthenticated !== undefined) recordAuth(meta.inventoryAuthenticated, true);
            if (meta.inventory_auth !== undefined) recordAuth(meta.inventory_auth, true);
            if (meta.inventoryAuth !== undefined) recordAuth(meta.inventoryAuth, true);
            if (meta.inventory_known !== undefined) recordAuth(meta.inventory_known, true);
            if (meta.inventoryKnown !== undefined) recordAuth(meta.inventoryKnown, true);
            if (meta.mode !== undefined) recordMode(meta.mode, true);
            if (meta.authenticated !== undefined) recordAuth(meta.authenticated, true);
            if (meta.headers && typeof meta.headers === 'object') {
                extractFromHeadersOrObject(meta.headers, true, true);
            }
            extractFromHeadersOrObject(meta, true, true);
        }

        extractFromHeadersOrObject(payloadObj, true, false);

        if (Array.isArray(payload)) {
            items = payload as Array<Record<string, unknown>>;
        } else {
            envelope = payloadObj;
            if (Array.isArray(envelope.apps)) {
                items = envelope.apps as Array<Record<string, unknown>>;
            } else if (Array.isArray(envelope.packages)) {
                items = envelope.packages as Array<Record<string, unknown>>;
            } else if (Array.isArray(envelope.items)) {
                items = envelope.items as Array<Record<string, unknown>>;
            } else if (Array.isArray(envelope.data)) {
                items = envelope.data as Array<Record<string, unknown>>;
            } else if (envelope.data && typeof envelope.data === 'object') {
                const extracted = extractPackages<Record<string, unknown>>(envelope.data);
                if (extracted) {
                    items = extracted;
                }
            }
        }
    }

    // 4. Process items
    for (const item of items) {
        if (item && typeof item === 'object') {
            const itemObj = item as Record<string, unknown>;
            if (itemObj.inventory_mode !== undefined) recordMode(itemObj.inventory_mode, false);
            if (itemObj.inventoryMode !== undefined) recordMode(itemObj.inventoryMode, false);
            if (itemObj.inventory_authenticated !== undefined) recordAuth(itemObj.inventory_authenticated, false);
            if (itemObj.inventoryAuthenticated !== undefined) recordAuth(itemObj.inventoryAuthenticated, false);
            if (itemObj.inventory_auth !== undefined) recordAuth(itemObj.inventory_auth, false);
            if (itemObj.inventoryAuth !== undefined) recordAuth(itemObj.inventoryAuth, false);
            if (itemObj.inventory_known !== undefined) recordAuth(itemObj.inventory_known, false);
            if (itemObj.inventoryKnown !== undefined) recordAuth(itemObj.inventoryKnown, false);
            if (itemObj.authenticated !== undefined) recordAuth(itemObj.authenticated, false);

            if (itemObj.headers && typeof itemObj.headers === 'object') {
                extractFromHeadersOrObject(itemObj.headers, false, true);
            }

            if (itemObj.meta && typeof itemObj.meta === 'object') {
                const meta = itemObj.meta as Record<string, unknown>;
                if (meta.inventory_mode !== undefined) recordMode(meta.inventory_mode, false);
                if (meta.inventoryMode !== undefined) recordMode(meta.inventoryMode, false);
                if (meta.inventory_authenticated !== undefined) recordAuth(meta.inventory_authenticated, false);
                if (meta.inventoryAuthenticated !== undefined) recordAuth(meta.inventoryAuthenticated, false);
                if (meta.inventory_auth !== undefined) recordAuth(meta.inventory_auth, false);
                if (meta.inventoryAuth !== undefined) recordAuth(meta.inventoryAuth, false);
                if (meta.inventory_known !== undefined) recordAuth(meta.inventory_known, false);
                if (meta.inventoryKnown !== undefined) recordAuth(meta.inventoryKnown, false);
                if (meta.mode !== undefined) recordMode(meta.mode, false);
                if (meta.authenticated !== undefined) recordAuth(meta.authenticated, false);
                if (meta.headers && typeof meta.headers === 'object') {
                    extractFromHeadersOrObject(meta.headers, false, true);
                }
                extractFromHeadersOrObject(meta, false, true);
            }

            extractFromHeadersOrObject(itemObj, false, false);
        }
    }

    // Negative evaluation: IF ANY negative value exists, immediately return public_redacted
    const hasNegativeMode = collectedModes.some(isNegativeModeValue);
    const hasNegativeAuth = collectedAuths.some(isNegativeAuthValue);

    if (hasNegativeMode || hasNegativeAuth) {
        return { authenticated: false, mode: 'public_redacted' };
    }

    // Affirmative evaluation: Only if ZERO negative signals exist AND at least one affirmative signal exists
    const hasAffirmativeItems = items.length > 0 && items.every(hasAffirmativeItemMetadata);
    const hasAffirmativeEvidence =
        topLevelModes.some(isAffirmativeModeValue) ||
        topLevelAuths.some(isAffirmativeAuthValue) ||
        hasAffirmativeItems;

    if (hasAffirmativeEvidence) {
        return { authenticated: true, mode: 'authenticated' };
    }

    return { authenticated: false, mode: 'public_redacted' };
}

export function useMarketplace(options?: UseMarketplaceOptions) {
    // Map of appId -> action type so we know if it's an install, uninstall, or update
    const pendingRef = useRef<Map<string, PendingAction>>(new Map());
    const expectedRef = useRef<Map<string, string>>(new Map());
    const deadlineRef = useRef<Map<string, number>>(new Map());
    const [unconfirmedJobs, setUnconfirmedJobs] = useState<Map<string, string>>(new Map());
    const [receiptRevision, setReceiptRevision] = useState(0);
    const [pendingJobs, setPendingJobs] = useState<Map<string, PendingAction>>(new Map());
    const [transportAuthState, setTransportAuthState] = useState<{ authenticated: boolean; mode: 'authenticated' | 'public_redacted' } | null>(null);
    const [lastError, setLastError] = useState<unknown>(undefined);

    const renewActiveJobs = useCallback((apps?: App[]) => {
        apps?.forEach(app => {
            const action = pendingRef.current.get(app.id);
            if (action && matchingActiveJob(app, action, expectedRef.current.get(app.id))) {
                deadlineRef.current.set(app.id, Date.now() + LIFECYCLE_RECEIPT_TIMEOUT_MS);
            }
        });
    }, []);

    const swrKey = options?.requireAuth
        ? '/api/v1/public/marketplace?require_auth=1'
        : '/api/v1/public/marketplace';

    const { fetcher: configFetcher, compare: configCompare } = useSWRConfig();
    const swrFetcher = configFetcher && configFetcher !== defaultFetcher
        ? configFetcher
        : fetchMarketplaceData;

    useEffect(() => {
        const unsubscribe = subscribeAuthChange((entry, url) => {
            const basePath = swrKey.split('?')[0];
            const matchesKey = url === swrKey ||
                url === basePath ||
                url.split('?')[0] === basePath ||
                (url.includes('marketplace') && swrKey.includes('marketplace'));
            if (matchesKey || !entry.authenticated || entry.mode === 'public_redacted') {
                setTransportAuthState({
                    authenticated: entry.authenticated,
                    mode: entry.mode,
                });
            }
        });
        return unsubscribe;
    }, [swrKey]);

    const { data, error, isLoading, isValidating, mutate } = useSWR<App[] | MarketplaceResponseEnvelope>(
        swrKey,
        {
            fetcher: swrFetcher as (url: string) => Promise<App[] | MarketplaceResponseEnvelope>,
            compare: (a, b) => {
                const getAuth = (val: unknown) => {
                    if (!val) return { authenticated: undefined, mode: undefined };
                    if (typeof val === 'string') {
                        return { authenticated: val === 'authenticated', mode: val };
                    }
                    const obj = val as { authenticated?: boolean; mode?: string };
                    return { authenticated: obj.authenticated, mode: obj.mode };
                };
                const authA = (a as Record<string, unknown> | null | undefined)?.__resolvedInventoryAuth;
                const authB = (b as Record<string, unknown> | null | undefined)?.__resolvedInventoryAuth;
                const resolvedA = getAuth(authA);
                const resolvedB = getAuth(authB);
                if (authA || authB) {
                    if (resolvedA.authenticated !== resolvedB.authenticated || resolvedA.mode !== resolvedB.mode) {
                        return false;
                    }
                }
                const modeA = (a as Record<string, unknown> | null | undefined)?.inventory_mode ?? (a as Record<string, unknown> | null | undefined)?.inventoryMode;
                const modeB = (b as Record<string, unknown> | null | undefined)?.inventory_mode ?? (b as Record<string, unknown> | null | undefined)?.inventoryMode;
                if (modeA !== modeB) return false;

                const authedA = (a as Record<string, unknown> | null | undefined)?.inventory_authenticated ?? (a as Record<string, unknown> | null | undefined)?.inventoryAuthenticated;
                const authedB = (b as Record<string, unknown> | null | undefined)?.inventory_authenticated ?? (b as Record<string, unknown> | null | undefined)?.inventoryAuthenticated;
                if (authedA !== authedB) return false;

                if (typeof configCompare === 'function') {
                    return configCompare(a, b);
                }
                return a === b;
            },
            refreshInterval: (currentData) => {
                // Fast-poll while we have locally pending actions waiting for server pickup
                if (pendingRef.current.size > 0) return 1000;
                if (!currentData) return 15000;
                const appsArray = extractPackages<App>(currentData);
                if (!Array.isArray(appsArray)) return 15000;
                // Keep polling while ANY app is in a transient state
                const hasActiveJobs = appsArray.some(
                    app => isLifecycleStatus(app.status)
                );
                return hasActiveJobs ? 2000 : 15000;
            },
            // SWR can retain the same data reference after equal successful polls.
            // This heartbeat must not be renewed by stale cache on fetch failures.
            onSuccess: (newData) => {
                setLastError(undefined);
                const dataSeq = (newData as unknown as LifecyclePayloadMetadata)?.__requestSeq;
                if (newData && typeof newData === 'object') {
                    const resolved = (newData as Record<string, unknown>).__resolvedInventoryAuth;
                    if (resolved) {
                        const isResPublic = resolved === 'public_redacted' ||
                            (typeof resolved === 'object' && resolved !== null && (!(resolved as { authenticated?: boolean }).authenticated || (resolved as { mode?: string }).mode === 'public_redacted'));
                        const currentAuth = getCurrentSettledAuthMode(swrKey);
                        if (isResPublic && currentAuth === 'authenticated') {
                            // Suppress stale public_redacted payload from overriding authenticated state
                        } else {
                            const targetState = (typeof resolved === 'string')
                                ? (resolved === 'public_redacted' ? 'public_redacted' : 'authenticated')
                                : (resolved as { authenticated: boolean; mode: 'authenticated' | 'public_redacted' });
                            recordTransportAuth(swrKey, targetState, dataSeq);
                            if (typeof resolved === 'string') {
                                setTransportAuthState({
                                    authenticated: resolved === 'authenticated',
                                    mode: resolved === 'public_redacted' ? 'public_redacted' : 'authenticated',
                                });
                            } else {
                                setTransportAuthState(resolved as { authenticated: boolean; mode: 'authenticated' | 'public_redacted' });
                            }
                        }
                    }
                }
                const appsArray = extractPackages<App>(newData);
                if (Array.isArray(appsArray)) {
                    renewActiveJobs(appsArray);
                }
            },
            onError: (err) => {
                if ((err as unknown as LifecyclePayloadMetadata)?.__staleRequest) {
                    return;
                }
                const errSeq = (err as unknown as LifecyclePayloadMetadata)?.__requestSeq;
                if (typeof errSeq === 'number' && errSeq < latestAuthoritativeAuthSeq) {
                    return;
                }
                setLastError(err);
                if (isAuthFailureError(err)) {
                    const effectiveSeq = typeof errSeq === 'number' ? errSeq : latestSettledRequestSeq;
                    latestAuthoritativeAuthSeq = Math.max(latestAuthoritativeAuthSeq, effectiveSeq);
                    latestSettledRequestSeq = Math.max(latestSettledRequestSeq, effectiveSeq);
                    latestRevokedRequestSeq = Math.max(latestRevokedRequestSeq, effectiveSeq);
                    globalRevokedAuth = true;
                    recordTransportAuth(swrKey, 'public_redacted', errSeq);
                    setTransportAuthState({ authenticated: false, mode: 'public_redacted' });
                }
            },
            shouldRetryOnError: false,
        }
    );

    useLifecyclePollRecovery(swrKey, error, () => mutate());

    useEffect(() => {
        if (data && typeof data === 'object') {
            const dataSeq = (data as unknown as LifecyclePayloadMetadata)?.__requestSeq;
            const resolved = (data as Record<string, unknown>).__resolvedInventoryAuth;
            if (resolved) {
                const isResPublic = resolved === 'public_redacted' ||
                    (typeof resolved === 'object' && resolved !== null && (!(resolved as { authenticated?: boolean }).authenticated || (resolved as { mode?: string }).mode === 'public_redacted'));
                const currentAuth = getCurrentSettledAuthMode(swrKey);
                if (isResPublic && currentAuth === 'authenticated') {
                    // Stale payload, don't overwrite authenticated state
                } else {
                    const targetState = (typeof resolved === 'string')
                        ? (resolved === 'public_redacted' ? 'public_redacted' : 'authenticated')
                        : (resolved as { authenticated: boolean; mode: 'authenticated' | 'public_redacted' });
                    recordTransportAuth(swrKey, targetState, dataSeq);
                    if (typeof resolved === 'string') {
                        setTransportAuthState({
                            authenticated: resolved === 'authenticated',
                            mode: resolved === 'public_redacted' ? 'public_redacted' : 'authenticated',
                        });
                    } else {
                        setTransportAuthState(resolved as { authenticated: boolean; mode: 'authenticated' | 'public_redacted' });
                    }
                }
            }
        }
    }, [data, swrKey]);

    useEffect(() => {
        if ((error as unknown as LifecyclePayloadMetadata)?.__staleRequest) {
            return;
        }
        if (error) {
            setLastError(error);
        }
        if (error && isAuthFailureError(error)) {
            const errSeq = (error as unknown as LifecyclePayloadMetadata)?.__requestSeq;
            if (typeof errSeq === 'number' && errSeq < latestAuthoritativeAuthSeq) {
                return;
            }
            const effectiveSeq = typeof errSeq === 'number' ? errSeq : latestSettledRequestSeq;
            latestAuthoritativeAuthSeq = Math.max(latestAuthoritativeAuthSeq, effectiveSeq);
            latestSettledRequestSeq = Math.max(latestSettledRequestSeq, effectiveSeq);
            latestRevokedRequestSeq = Math.max(latestRevokedRequestSeq, effectiveSeq);
            globalRevokedAuth = true;
            recordTransportAuth(swrKey, 'public_redacted', errSeq);
            setTransportAuthState({ authenticated: false, mode: 'public_redacted' });
        }
    }, [error, swrKey]);

    // A deduplicated request initiated by another subscriber still changes
    // isValidating, even when SWR preserves deeply equal cached data.
    useEffect(() => {
        if (!error && !isValidating) {
            const appsArray = extractPackages<App>(data);
            if (Array.isArray(appsArray)) {
                renewActiveJobs(appsArray);
            }
        }
    }, [data, error, isValidating, renewActiveJobs]);

    useEffect(() => {
        let changed = false;
        const appsArray = extractPackages<App>(data);
        appsArray?.forEach(app => {
            const action = pendingRef.current.get(app.id);
            if (action && matchingJobOutcome(app, action, expectedRef.current.get(app.id))) {
                pendingRef.current.delete(app.id);
                expectedRef.current.delete(app.id);
                deadlineRef.current.delete(app.id);
                changed = true;
            }
        });
        if (changed) setPendingJobs(new Map(pendingRef.current));
    }, [data, receiptRevision]);

    useEffect(() => {
        if (!deadlineRef.current.size) return;
        let timeout: ReturnType<typeof setTimeout>;
        const schedule = () => {
            if (deadlineRef.current.size) timeout = setTimeout(checkDeadlines, Math.max(0, Math.min(...deadlineRef.current.values()) - Date.now()));
        };
        const checkDeadlines = () => {
            const expired = new Map<string, string>();
            deadlineRef.current.forEach((deadline, appId) => {
                if (deadline > Date.now()) return;
                expired.set(appId, expectedRef.current.get(appId) || `unconfirmed-${deadline}`);
                pendingRef.current.delete(appId);
                expectedRef.current.delete(appId);
                deadlineRef.current.delete(appId);
            });
            if (expired.size) {
                setUnconfirmedJobs(current => new Map([...current, ...expired]));
                setPendingJobs(new Map(pendingRef.current));
            }
            // A heartbeat may have extended the earliest deadline without a render.
            schedule();
        };
        schedule();
        return () => clearTimeout(timeout);
    }, [pendingJobs, receiptRevision]);

    const registerJob = (appId: string, receipt: { job_id?: string; started_at?: string }) => {
        const identity = lifecycleIdentity(receipt);
        if (!identity) throw new Error('The server did not return a job identity. Refresh status and check logs before retrying.');
        if (!pendingRef.current.has(appId)) throw new Error('Acceptance arrived after status tracking expired. Check application state and logs before retrying.');
        expectedRef.current.set(appId, identity);
        setReceiptRevision(value => value + 1);
        setPendingJobs(new Map(pendingRef.current));
        return identity;
    };

    const markPending = (appId: string, action: PendingAction) => {
        expectedRef.current.delete(appId);
        pendingRef.current.set(appId, action);
        deadlineRef.current.set(appId, Date.now() + LIFECYCLE_RECEIPT_TIMEOUT_MS);
        setUnconfirmedJobs(current => { const next = new Map(current); next.delete(appId); return next; });
        setPendingJobs(new Map(pendingRef.current));
    };

    const clearPending = (appId: string) => {
        expectedRef.current.delete(appId);
        pendingRef.current.delete(appId);
        deadlineRef.current.delete(appId);
        setPendingJobs(new Map(pendingRef.current));
    };

    // Determine inventory authentication status and mode
    let rawData = data as unknown;

    const getTransportAuth = (endpoint: string): TransportAuthState | undefined => {
        const raw = latestTransportAuthByEndpoint.get(endpoint);
        if (!raw) return undefined;
        if (typeof raw === 'string') {
            const isPub = raw === 'public_redacted';
            return {
                authenticated: !isPub,
                mode: isPub ? 'public_redacted' : 'authenticated',
                seq: ++transportAuthSeq,
            };
        }
        return raw as TransportAuthState;
    };

    const latestAuth = getTransportAuth(swrKey) ??
        getTransportAuth(swrKey.split('?')[0]) ??
        getTransportAuth('/api/marketplace/packages') ??
        getTransportAuth('/api/v1/public/marketplace') ??
        getTransportAuth('/v1/marketplace/packages');

    const isNegativeAuth = (auth?: unknown): boolean => {
        if (!auth) return false;
        if (typeof auth === 'string') return auth === 'public_redacted';
        const obj = auth as { authenticated?: boolean; mode?: string };
        return !obj.authenticated || obj.mode === 'public_redacted';
    };

    const isSettledAuthed = !globalRevokedAuth && Boolean(
        (latestAuth && !isNegativeAuth(latestAuth)) ||
        getCurrentSettledAuthMode(swrKey) === 'authenticated'
    );

    const rawRequestSeq = (rawData as LifecyclePayloadMetadata)?.__requestSeq;
    const isStalePayload = Boolean(
        (rawData as unknown as LifecyclePayloadMetadata)?.__staleRequest === true ||
        (rawData as unknown as LifecyclePayloadMetadata)?.__stalePublicIgnored === true ||
        (typeof rawRequestSeq === 'number' && rawRequestSeq < latestSettledRequestSeq)
    );

    const rawInitialAuth = rawData && typeof rawData === 'object'
        ? (rawData as Record<string, unknown>).__resolvedInventoryAuth
        : undefined;

    const isRawPublic = Boolean(
        isNegativeAuth(rawInitialAuth) ||
        (rawData && typeof rawData === 'object' && (
            (rawData as unknown as LifecyclePayloadMetadata).inventory_mode === 'public_redacted' ||
            (rawData as unknown as LifecyclePayloadMetadata).inventoryMode === 'public_redacted' ||
            (rawData as unknown as LifecyclePayloadMetadata).inventory_authenticated === false ||
            (rawData as unknown as LifecyclePayloadMetadata).inventoryAuthenticated === false
        ))
    );

    if (isStalePayload) {
        const fallbackPayload = getSettledPayload(swrKey);
        if (fallbackPayload) {
            rawData = fallbackPayload;
        }
    }

    let appsList: App[] | undefined = extractPackages<App>(rawData) ?? undefined;

    const rawAttachedAuth = rawData && typeof rawData === 'object'
        ? (rawData as Record<string, unknown>).__resolvedInventoryAuth
        : undefined;

    const attachedAuth: { authenticated: boolean; mode: 'authenticated' | 'public_redacted' } | undefined =
        typeof rawAttachedAuth === 'string'
            ? {
                  authenticated: rawAttachedAuth === 'authenticated',
                  mode: rawAttachedAuth === 'public_redacted' ? 'public_redacted' : 'authenticated',
              }
            : (rawAttachedAuth as { authenticated: boolean; mode: 'authenticated' | 'public_redacted' } | undefined);

    const isMockedOrExternalData = Boolean(
        rawData &&
        typeof rawData === 'object' &&
        !('__resolvedInventoryAuth' in (rawData as Record<string, unknown>))
    );

    const isStaleError = (err: unknown): boolean => Boolean((err as unknown as LifecyclePayloadMetadata)?.__staleRequest);
    const isAuthRevokingError = (err: unknown): boolean => Boolean(err) && !isStaleError(err) && isAuthFailureError(err);
    const effectiveError = isStaleError(error) ? undefined : (error ?? (isStaleError(lastError) ? undefined : lastError));

    const isTransportNegative =
        globalRevokedAuth ||
        isNegativeAuth(latestTransportAuthByEndpoint.get(swrKey)) ||
        isNegativeAuth(latestTransportAuthByEndpoint.get(swrKey.split('?')[0])) ||
        isNegativeAuth(latestTransportAuthByEndpoint.get('/api/marketplace/packages')) ||
        isNegativeAuth(latestTransportAuthByEndpoint.get('/api/v1/public/marketplace')) ||
        isNegativeAuth(latestTransportAuthByEndpoint.get('/v1/marketplace/packages')) ||
        isNegativeAuth(latestAuth) ||
        isNegativeAuth(transportAuthState) ||
        (!isStalePayload && isNegativeAuth(rawAttachedAuth)) ||
        (!isStalePayload && isNegativeAuth(attachedAuth)) ||
        isAuthRevokingError(effectiveError) ||
        isAuthRevokingError(error);

    let authState: { authenticated: boolean; mode: 'authenticated' | 'public_redacted' };

    if (!rawData || isTransportNegative) {
        authState = { authenticated: false, mode: 'public_redacted' };
    } else if (isMockedOrExternalData) {
        authState = resolveInventoryAuthState(rawData);
    } else {
        const currentTransportAuth = latestAuth ?? transportAuthState;

        if (currentTransportAuth) {
            authState = resolveInventoryAuthState(rawData, currentTransportAuth.mode, currentTransportAuth.authenticated);
            if (isNegativeAuth(authState)) {
                authState = { authenticated: false, mode: 'public_redacted' };
            }
        } else if (attachedAuth) {
            authState = resolveInventoryAuthState(rawData, attachedAuth.mode, attachedAuth.authenticated);
        } else {
            authState = resolveInventoryAuthState(rawData);
        }
    }
    let isInventoryAuthenticated = authState.authenticated;
    let currentInventoryMode: 'authenticated' | 'public_redacted' | string = authState.mode;

    if (isAuthRevokingError(effectiveError) || isAuthRevokingError(error)) {
        isInventoryAuthenticated = false;
        currentInventoryMode = 'public_redacted';
    }
    if (isTransportNegative) {
        isInventoryAuthenticated = false;
        currentInventoryMode = 'public_redacted';
    }

    const isPublicRedacted = !isInventoryAuthenticated || currentInventoryMode === 'public_redacted';

    const lastScrubbedDataRef = useRef<unknown>(null);
    useEffect(() => {
        if (isPublicRedacted) {
            pendingRef.current.clear();
            expectedRef.current.clear();
            deadlineRef.current.clear();
            setPendingJobs(current => (current.size > 0 ? new Map() : current));
            setUnconfirmedJobs(current => (current.size > 0 ? new Map() : current));
            scrubAllSettledPayloads();
            if (data && lastScrubbedDataRef.current !== data) {
                lastScrubbedDataRef.current = data;
                scrubMarketplacePayloadInPlace(data);
                mutate(data, false);
            }
        } else {
            lastScrubbedDataRef.current = null;
        }
    }, [isPublicRedacted, data, mutate]);

    if (appsList && isPublicRedacted) {
        scrubMarketplacePayloadInPlace(rawData);
        appsList = appsList.map(app => sanitizePublicPackage(app as unknown as Record<string, unknown>) as unknown as App);
    }

    const rawMode = (rawData as Record<string, unknown> | null | undefined)?.inventory_mode ??
                    (rawData as Record<string, unknown> | null | undefined)?.inventoryMode;
    const finalInventoryMode: string = isPublicRedacted
        ? 'public_redacted'
        : (typeof rawMode === 'string' && rawMode !== 'public_redacted' ? rawMode : currentInventoryMode);

    const isInventoryKnown = !isPublicRedacted && Boolean(
        (rawData as Record<string, unknown> | null | undefined)?.inventory_known ??
        (rawData as Record<string, unknown> | null | undefined)?.inventoryKnown ??
        isInventoryAuthenticated
    );

    return {
        apps: appsList,
        packages: appsList,
        isLoading,
        isError: Boolean(effectiveError),
        error: effectiveError,
        mutate,
        pendingJobs: isPublicRedacted ? new Map<string, PendingAction>() : pendingJobs,
        pendingActions: isPublicRedacted
            ? {}
            : Object.fromEntries(pendingJobs),
        unconfirmedJobs: isPublicRedacted ? new Map<string, string>() : unconfirmedJobs,
        markPending,
        registerJob,
        clearPending,
        inventoryAuthenticated: isInventoryAuthenticated,
        inventoryMode: finalInventoryMode,
        inventoryKnown: isInventoryKnown,
    };
}
