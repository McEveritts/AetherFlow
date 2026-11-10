import React, { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import { useMarketplace, useGithubDownloads, App, PendingAction, isLifecycleStatus, lifecycleIdentity, matchingJobOutcome, dispatchPackageUpdate } from '@/hooks/useMarketplace';
import { Search, Package, Download, RefreshCw, XCircle, AlertCircle, Filter, Globe, Puzzle, ShieldCheck, Play, Square, ExternalLink } from 'lucide-react';
import { useToast } from '@/contexts/ToastContext';
import { ProgressRing } from '@/components/ui/ProgressRing';
import { apiFetch } from '@/lib/fetcher';
import { getSVGLCatalog, matchSVGLLogo } from '@/lib/svgl';
import { ExternalAccessCard } from '@/components/ingress/ExternalAccessCard';
import { DeploymentStatus } from '@/components/deploy/DeploymentStatus';
import { Modal } from '@/components/ui/Modal';

function isShaCandidate(s: string): boolean {
    return /^[0-9a-f]{7,40}$/i.test(s);
}

function isUnambiguousGitSha(s: string): boolean {
    return /^[0-9a-f]{7,40}$/i.test(s) && (s.length === 40 || /[a-f]/i.test(s));
}

export function isDebianPlusRevision(suffix: string): boolean {
    return /^(?:deb\d+|dfsg(?:\.\d+|\d+|-|$)|ds(?:\.\d+|\d+|-|$)|really[0-9.]|nmu\d+|b\d+$|u\d+$)/i.test(suffix);
}

export function normalizeVersion(raw: string): string {
    let v = raw.trim();
    const prefixRe = /^(?:release[-_]?|rel[-_]?|version[-_]?|ver[-_]?|v)+(?=\d)/i;
    v = v.replace(prefixRe, '').trim();
    return v;
}

export function singleVersionMatch(achieved: string, expected: string, knownGitContext = false): boolean {
    const a = normalizeVersion(achieved);
    const e = normalizeVersion(expected);
    if (!a || !e) return false;

    const bothAreShaCandidates = isShaCandidate(a) && isShaCandidate(e);
    if (bothAreShaCandidates && a.toLowerCase() === e.toLowerCase()) {
        return true;
    }
    if (a === e) return true;

    const aLower = a.toLowerCase();
    const eLower = e.toLowerCase();

    if (knownGitContext) {
        if (bothAreShaCandidates) {
            return aLower.startsWith(eLower) || eLower.startsWith(aLower);
        }
        return false;
    }

    const aUnambiguous = isUnambiguousGitSha(a);
    const eUnambiguous = isUnambiguousGitSha(e);

    if (aUnambiguous && eUnambiguous) {
        return aLower.startsWith(eLower) || eLower.startsWith(aLower);
    }
    if (aUnambiguous && isShaCandidate(e)) {
        return aLower.startsWith(eLower) || eLower.startsWith(aLower);
    }
    if (eUnambiguous && isShaCandidate(a)) {
        return aLower.startsWith(eLower) || eLower.startsWith(aLower);
    }

    return false;
}

function parseComponentManifest(raw: string): Map<string, string> | null {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    const parts = trimmed.split(',');
    const map = new Map<string, string>();
    for (const part of parts) {
        const p = part.trim();
        const sepMatch = p.match(/[:=]/);
        if (!sepMatch || sepMatch.index === undefined || sepMatch.index <= 0 || sepMatch.index === p.length - 1) {
            return null;
        }
        const sepIndex = sepMatch.index;
        const key = p.slice(0, sepIndex).trim().toLowerCase();
        const value = p.slice(sepIndex + 1).trim();
        if (!key || !value) return null;
        if (map.has(key)) {
            return null;
        }
        map.set(key, normalizeVersion(value));
    }
    return map;
}

const GIT_MANIFEST_KEYS = ['frontend', 'backend', 'proxy'] as const;

function isPipedGitManifest(map: Map<string, string>): boolean {
    if (map.size !== 3) return false;
    for (const key of GIT_MANIFEST_KEYS) {
        const val = map.get(key);
        if (!val) return false;
        const normVal = normalizeVersion(val);
        if (!isShaCandidate(normVal)) return false;
    }
    return true;
}

export function versionsMatchTarget(achieved?: string | null, expected?: string | null): boolean {
    if (!achieved || !expected) return false;
    const ach = achieved.trim();
    const exp = expected.trim();
    if (!ach || !exp) return false;

    const isManifest = (s: string) => s.includes(',') && (s.includes(':') || s.includes('='));
    if (isManifest(ach) || isManifest(exp)) {
        const achievedMap = parseComponentManifest(ach);
        const expectedMap = parseComponentManifest(exp);
        if (!achievedMap || !expectedMap) return false;
        if (expectedMap.size < 2 || expectedMap.size !== achievedMap.size) return false;

        const isPiped =
            Array.from(expectedMap.keys()).some(k => (GIT_MANIFEST_KEYS as readonly string[]).includes(k)) ||
            Array.from(achievedMap.keys()).some(k => (GIT_MANIFEST_KEYS as readonly string[]).includes(k));

        if (isPiped) {
            if (expectedMap.size !== 3 || achievedMap.size !== 3) return false;
            for (const key of GIT_MANIFEST_KEYS) {
                if (!expectedMap.has(key) || !achievedMap.has(key)) return false;
            }
        }

        const knownGitContext = isPipedGitManifest(expectedMap) && isPipedGitManifest(achievedMap);

        for (const [key, expVal] of expectedMap.entries()) {
            const achVal = achievedMap.get(key);
            if (!achVal) return false;
            if (!singleVersionMatch(achVal, expVal, knownGitContext)) return false;
        }
        return true;
    }

    return singleVersionMatch(ach, exp, false);
}

function formatCheckedAt(timestamp?: string): string {
    if (!timestamp) return '';
    try {
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) return timestamp;
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
        return timestamp;
    }
}

export interface PluginScopeRule {
    method: string;
    route: string;
}

export interface PluginRuntimeView {
    id: string;
    name: string;
    version: string;
    sdk: string;
    contract_version: string;
    runtime_status: string;
    description: string;
    author: string;
    permissions: string[];
    granted_scopes: PluginScopeRule[];
    enabled: boolean;
    status: string;
    healthy: boolean;
    allocated_port: number;
    health_path: string;
    ui_url: string;
    proxy_base_url: string;
    slot: string;
    capabilities: string[];
    last_health_at?: string | null;
    last_error?: string;
}

const AppIcon = ({ app }: { app: App }) => {
    const [failedAppId, setFailedAppId] = useState<string | null>(null);
    const [svglState, setSvglState] = useState<{ appId: string; url: string | null; error: boolean } | null>(null);
    const localFailed = failedAppId === app.id;
    const svglUrl = svglState?.appId === app.id ? svglState.url : null;
    const iconError = svglState?.appId === app.id ? svglState.error : false;
    const localIconPath = `/img/${app.id.toLowerCase()}.png`;
    const primaryIconPath = localFailed ? svglUrl : localIconPath;

    useEffect(() => {
        if (!localFailed) return;
        let cancelled = false;
        getSVGLCatalog().then(catalog => {
            if (cancelled) return;
            const match = matchSVGLLogo(catalog, app.id, app.name);
            if (match) {
                setSvglState({ appId: app.id, url: match, error: false });
            } else {
                setSvglState({ appId: app.id, url: null, error: true });
            }
        });
        return () => {
            cancelled = true;
        };
    }, [localFailed, app.id, app.name]);

    if (iconError || (localFailed && !svglUrl)) {
        return (
            <div className="flex flex-col items-center justify-center h-full w-full bg-slate-900/20 text-slate-500">
                <Package size={24} />
                <span className="text-[8px] mt-1 font-bold uppercase opacity-50">{app.id.substring(0, 3)}</span>
            </div>
        );
    }

    return (
        <div className="relative w-full h-full flex items-center justify-center">
             <img
                src={primaryIconPath || localIconPath}
                onError={() => {
                    if (!localFailed) {
                        setFailedAppId(app.id);
                    } else {
                        setSvglState({ appId: app.id, url: null, error: true });
                    }
                }}
                className="w-full h-full object-contain p-2 drop-shadow-sm"
                alt={app.name}
                loading="lazy"
            />
        </div>
    );
};

const APP_CATALOGUE_GRID =
    'min-w-0 rounded-none shadow-none bg-transparent border-y border-white/[0.07] grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 divide-y divide-white/[0.07] md:divide-y-0 md:[&>*]:border-t md:[&>*]:border-white/[0.07] md:[&>*:nth-child(-n+2)]:border-t-0 md:max-xl:[&>*:nth-child(even)]:border-l xl:[&>*:nth-child(-n+3)]:border-t-0 xl:[&>*:not(:nth-child(3n+1))]:border-l';

const PLUGIN_CATALOGUE_GRID =
    'min-w-0 rounded-none shadow-none bg-transparent border-y border-white/[0.07] grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 divide-y divide-white/[0.07] md:divide-y-0 md:[&>*]:border-t md:[&>*]:border-white/[0.07] md:[&>*:nth-child(-n+2)]:border-t-0 md:max-xl:[&>*:nth-child(even)]:border-l xl:[&>*:nth-child(-n+3)]:border-t-0 xl:[&>*:not(:nth-child(3n+1))]:border-l';

function checkMessageMatchesAuth(message: string): boolean {
    if (/\b(?:unauthorized|forbidden)\b/i.test(message)) {
        return true;
    }
    if (/(?:^\s*|\b(?:http|status(?:\s+code)?|error)\s*[:=]?\s*)(?:401|403)\b/i.test(message)) {
        return true;
    }
    return false;
}

export function checkIsAuthError(err: unknown): boolean {
    if (!err) return false;
    if (typeof err === 'string') {
        return checkMessageMatchesAuth(err);
    }
    if (typeof err !== 'object') return false;
    const anyErr = err as Record<string, unknown>;
    const rawStatus =
        typeof anyErr.status === 'number'
            ? anyErr.status
            : typeof anyErr.statusCode === 'number'
              ? anyErr.statusCode
              : typeof (anyErr.response as Record<string, unknown> | undefined)?.status === 'number'
                ? ((anyErr.response as Record<string, unknown>).status as number)
                : undefined;
    if (typeof rawStatus === 'number' && Number.isFinite(rawStatus)) {
        return rawStatus === 401 || rawStatus === 403;
    }
    if (typeof anyErr.message === 'string') {
        return checkMessageMatchesAuth(anyErr.message);
    }
    return false;
}

export default function MarketplaceTab() {
    const {
        apps,
        isLoading,
        isError,
        error,
        mutate,
        pendingJobs,
        unconfirmedJobs,
        markPending,
        clearPending,
        registerJob,
        inventoryAuthenticated = false,
        inventoryMode = 'public_redacted',
    } = useMarketplace();
    const totalGithubDownloads = useGithubDownloads();
    const { addToast } = useToast();
    const [searchQuery, setSearchQuery] = useState('');
    const [categoryFilter, setCategoryFilter] = useState('All');
    const [operatingApp, setOperatingApp] = useState<string | null>(null);
    const [checkingUpdateApp, setCheckingUpdateApp] = useState<string | null>(null);
    const [ingressModalApp, setIngressModalApp] = useState<string | null>(null);
    const [deployTriggeredApp, setDeployTriggeredApp] = useState<string | null>(null);
    const [removeAppId, setRemoveAppId] = useState<string | null>(null);
    const [purgeData, setPurgeData] = useState(false);
    const [purgeConfirmation, setPurgeConfirmation] = useState('');
    const [reinstallAppId, setReinstallAppId] = useState<string | null>(null);

    const isPublicRedactedMode = !inventoryAuthenticated || inventoryMode === 'public_redacted';
    const isAuthError = checkIsAuthError(error);
    const hasCachedInventory = Boolean(apps && apps.length > 0);
    const hasUsableAuthenticatedInventory = !isPublicRedactedMode && !isAuthError && hasCachedInventory;
    const isBlockingError = (Boolean(isError) || Boolean(error)) && !hasUsableAuthenticatedInventory;
    const isTransientBackgroundError = (Boolean(isError) || Boolean(error)) && hasUsableAuthenticatedInventory;

    const shouldCloseModals = isPublicRedactedMode || isAuthError || isBlockingError;
    const canRenderModals = !shouldCloseModals;

    useEffect(() => {
        if (shouldCloseModals) {
            setRemoveAppId(null);
            setPurgeData(false);
            setPurgeConfirmation('');
            setReinstallAppId(null);
            setIngressModalApp(null);
            setDeployTriggeredApp(null);
            setOperatingApp(null);
            setCheckingUpdateApp(null);
        }
    }, [shouldCloseModals]);

    // Installed Plugins & Sandboxed Capability Bridge State
    const [plugins, setPlugins] = useState<PluginRuntimeView[]>([]);
    const [rejectedPlugins, setRejectedPlugins] = useState<Array<{ id: string; error: string }>>([]);
    const [operatingPlugin, setOperatingPlugin] = useState<string | null>(null);
    const [mountedPlugin, setMountedPlugin] = useState<PluginRuntimeView | null>(null);
    const pluginIframeRef = useRef<HTMLIFrameElement | null>(null);

    const fetchPlugins = useCallback(async () => {
        try {
            const res = await apiFetch('/api/v1/auth/plugins');
            if (!res.ok) return;
            const data = await res.json();
            if (Array.isArray(data?.plugins)) {
                setPlugins(data.plugins);
            }
            if (Array.isArray(data?.rejected)) {
                setRejectedPlugins(data.rejected);
            }
        } catch {
            // Silently ignore when unauthenticated or offline
        }
    }, []);

    useEffect(() => {
        if (isPublicRedactedMode) return;
        unconfirmedJobs?.forEach((identity, appId) => {
            if (unconfirmedNotifiedRef.current.has(identity)) return;
            unconfirmedNotifiedRef.current.add(identity);
            addToast(`${apps?.find(app => app.id === appId)?.name || appId}: operation outcome could not be confirmed. Its receipt may have been superseded. Check application state and logs before retrying.`, 'error');
        });
    }, [unconfirmedJobs, apps, addToast, isPublicRedactedMode]);

    useEffect(() => {
        if (isPublicRedactedMode) return;
        let active = true;
        apiFetch('/api/v1/auth/plugins')
            .then(async (response) => (response.ok ? response.json() : null))
            .then((payload) => {
                if (!active || !payload) return;
                if (Array.isArray(payload.plugins)) {
                    setPlugins(payload.plugins);
                }
                if (Array.isArray(payload.rejected)) {
                    setRejectedPlugins(payload.rejected);
                }
            })
            .catch(() => {});
        return () => {
            active = false;
        };
    }, [isPublicRedactedMode]);

    // Sandboxed iframe postMessage capability bridge
    useEffect(() => {
        if (!mountedPlugin) return;

        const handlePluginMessage = async (event: MessageEvent) => {
            const iframeWin = pluginIframeRef.current?.contentWindow;
            if (!iframeWin || event.source !== iframeWin) return;
            const msg = event.data;
            if (!msg || typeof msg !== 'object') return;

            if (msg.type === 'AF_PLUGIN_READY' && msg.pluginId === mountedPlugin.id) {
                iframeWin.postMessage(
                    {
                        type: 'AF_PLUGIN_INIT',
                        pluginId: mountedPlugin.id,
                        capabilities: mountedPlugin.capabilities,
                        scopes: mountedPlugin.granted_scopes,
                    },
                    '*'
                );
                return;
            }

            if (msg.type === 'AF_PLUGIN_PROXY_REQUEST' && msg.pluginId === mountedPlugin.id) {
                const rawPath = String(msg.path || '').replace(/^\/+/, '');
                if (rawPath.includes('..') || rawPath.includes('\\')) {
                    iframeWin.postMessage(
                        {
                            type: 'AF_PLUGIN_PROXY_RESPONSE',
                            pluginId: mountedPlugin.id,
                            error: 'Path traversal is forbidden',
                        },
                        '*'
                    );
                    return;
                }
                const method = String(msg.method || 'GET').toUpperCase();
                if (!['GET', 'POST', 'PUT', 'DELETE'].includes(method)) {
                    iframeWin.postMessage(
                        {
                            type: 'AF_PLUGIN_PROXY_RESPONSE',
                            pluginId: mountedPlugin.id,
                            error: 'Unsupported HTTP method',
                        },
                        '*'
                    );
                    return;
                }
                const proxyUrl = rawPath
                    ? `${mountedPlugin.proxy_base_url}/${rawPath}`
                    : mountedPlugin.proxy_base_url;
                try {
                    const resp = await apiFetch(proxyUrl, { method });
                    const payload = await resp.json().catch(() => ({ status: resp.status }));
                    iframeWin.postMessage(
                        {
                            type: 'AF_PLUGIN_PROXY_RESPONSE',
                            pluginId: mountedPlugin.id,
                            status: resp.status,
                            payload,
                        },
                        '*'
                    );
                } catch (err: unknown) {
                    iframeWin.postMessage(
                        {
                            type: 'AF_PLUGIN_PROXY_RESPONSE',
                            pluginId: mountedPlugin.id,
                            error: err instanceof Error ? err.message : 'Proxy request failed',
                        },
                        '*'
                    );
                }
            }
        };

        window.addEventListener('message', handlePluginMessage);
        return () => window.removeEventListener('message', handlePluginMessage);
    }, [mountedPlugin]);

    const handlePluginControl = async (plugin: PluginRuntimeView, action: 'start' | 'stop' | 'restart' | 'revoke_tokens') => {
        setOperatingPlugin(plugin.id);
        try {
            const res = await apiFetch(`/api/v1/admin/plugins/${encodeURIComponent(plugin.id)}/control`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                throw new Error(data.message || `Plugin ${action} failed`);
            }
            addToast(data.message || `Plugin ${plugin.name} (${action}) completed`, 'success');
            if (data.plugin) {
                setPlugins((prev) => prev.map((p) => (p.id === plugin.id ? data.plugin : p)));
                if (mountedPlugin?.id === plugin.id && (action === 'stop' || !data.plugin.enabled)) {
                    setMountedPlugin(null);
                }
            } else {
                await fetchPlugins();
            }
        } catch (err: unknown) {
            addToast(err instanceof Error ? err.message : 'Plugin control error', 'error');
        } finally {
            setOperatingPlugin(null);
        }
    };

    // Job Completion Monitoring
    const observedJobsRef = useRef<Map<string, { action: PendingAction; identity: string }>>(new Map());
    const notifiedRef = useRef<Set<string>>(new Set());
    const unconfirmedNotifiedRef = useRef<Set<string>>(new Set());
    // Keep accepted identity/action after an observation timeout: a later receipt
    // can still confirm the real result, independently of the unknown notice.
    const acceptedJobsRef = useRef<Map<string, { action: PendingAction; identity: string }>>(new Map());
    const rememberJob = async (appId: string, res: Response, action: PendingAction) => {
        const body = await res.json() as { job_id?: string; started_at?: string };
        acceptedJobsRef.current.set(appId, { action, identity: registerJob(appId, body) });
    };

    useEffect(() => {
        if (!apps || isPublicRedactedMode) return;
        apps.forEach(app => {
            if (isLifecycleStatus(app.status)) {
                const identity = lifecycleIdentity(app);
                if (identity && (!pendingJobs.has(app.id) || identity === acceptedJobsRef.current.get(app.id)?.identity)) observedJobsRef.current.set(app.id, { action: app.status, identity });
            }
            const observed = observedJobsRef.current.get(app.id);
            const localAction = pendingJobs.get(app.id);
            const accepted = acceptedJobsRef.current.get(app.id);
            const action = localAction || accepted?.action || observed?.action;
            const expected = localAction ? accepted?.identity : accepted?.identity || observed?.identity;
            if (!action) return;
            const outcome = matchingJobOutcome(app, action, expected);
            const identity = lifecycleIdentity(outcome);
            if (!outcome || !identity || notifiedRef.current.has(identity)) return;
            notifiedRef.current.add(identity);
            acceptedJobsRef.current.delete(app.id);
            observedJobsRef.current.delete(app.id);
            if (outcome.status === 'completed') {
                if (outcome.action === 'update') {
                    const expected = outcome.expected_target_version?.trim();
                    const achieved = outcome.achieved_version?.trim();
                    const targetMismatch =
                        outcome.action === 'update' &&
                        (!expected || !achieved || !versionsMatchTarget(expected, achieved));

                    if (targetMismatch || outcome.target_unconfirmed || outcome.target_mismatch) {
                        addToast(
                            `${app.name}: update target version (${expected || 'target'}) could not be verified (observed: ${achieved || 'unknown'}).`,
                            'error'
                        );
                        return;
                    }

                    const versionSuffix = achieved ? ` to v${achieved.replace(/^v/i, '')}` : '';
                    addToast(`${app.name} has been successfully updated${versionSuffix}.`, 'success');
                } else {
                    const verb = outcome.action === 'remove' ? 'removed' : outcome.action === 'reinstall' ? 'reinstalled' : 'installed';
                    addToast(`${app.name} has been successfully ${verb}.`, 'success');
                }
            } else {
                const failureDetails: string[] = [];
                if (outcome.failed_stage) failureDetails.push(`stage: ${outcome.failed_stage}`);
                if (typeof outcome.exit_code === 'number') failureDetails.push(`exit code: ${outcome.exit_code}`);
                if (outcome.sanitized_summary) failureDetails.push(outcome.sanitized_summary);

                const detailsText = failureDetails.length > 0 ? ` (${failureDetails.join(', ')})` : '';
                const fallbackAdvice = failureDetails.length > 0 ? '' : ' Check application state and system logs.';
                addToast(
                    `${app.name}: ${outcome.action} ${outcome.status === 'failed' ? 'failed' : 'could not be confirmed'}.${detailsText}${fallbackAdvice}`,
                    'error'
                );
            }
        });
    }, [apps, addToast, pendingJobs, isPublicRedactedMode]);

    const categories = useMemo(() => {
        if (!apps) return ['All'];
        const cats = Array.from(new Set(apps.map((app) => app.category)));
        return ['All', ...cats];
    }, [apps]);

    const filteredApps = useMemo(() => {
        if (!apps) return [];
        return apps.filter((app) => {
            const matchesSearch = app.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                                app.desc.toLowerCase().includes(searchQuery.toLowerCase());
            const matchesCategory = categoryFilter === 'All' || app.category === categoryFilter;
            return matchesSearch && matchesCategory;
        }).sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }));
    }, [apps, searchQuery, categoryFilter]);

    const isAppBusy = (app: App): boolean => {
        if (isPublicRedactedMode) return false;
        return isLifecycleStatus(app.status) || operatingApp === app.id || pendingJobs.has(app.id);
    };

    const getEffectiveStatus = (app: App): string => {
        if (isPublicRedactedMode) return 'not_installed';
        if (isLifecycleStatus(app.status)) return app.status === 'reinstalling' ? 'installing' : app.status;
        if (pendingJobs.has(app.id)) {
            const pending = pendingJobs.get(app.id) as string;
            return pending === 'reinstalling' ? 'installing' : pending;
        }
        if (operatingApp === app.id) return 'installing';
        return app.status;
    };

    const selectedRemoveApp = canRenderModals ? apps?.find(app => app.id === removeAppId) : null;
    const selectedReinstallApp = canRenderModals ? apps?.find(app => app.id === reinstallAppId) : null;

    const handleInstall = async (app: App, isReinstall = false) => {
        if (isPublicRedactedMode) return;
        const pendingAction = isReinstall ? 'reinstalling' : 'installing';
        acceptedJobsRef.current.delete(app.id);
        setOperatingApp(app.id);
        markPending(app.id, pendingAction);
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(app.id)}/install`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                clearPending(app.id);
                throw new Error(data.message || 'Installation request failed');
            }
            await rememberJob(app.id, res, pendingAction);
            addToast(`${isReinstall ? 'Reinstall' : 'Installation'} started for ${app.name}`, 'info');
            setOperatingApp(null);
            mutate();
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Network error.', 'error');
            clearPending(app.id);
            setOperatingApp(null);
        }
    };

    const handleRecheck = async (app: App) => {
        if (isPublicRedactedMode) return;
        setCheckingUpdateApp(app.id);
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(app.id)}/check-update`, {
                method: 'POST',
            });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.message || 'Update check failed');
            }
            addToast(`Checked for updates for ${app.name}`, 'info');
            mutate();
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Update check failed.', 'error');
        } finally {
            setCheckingUpdateApp(null);
        }
    };

    const handleUpdate = async (app: App) => {
        if (isPublicRedactedMode) return;
        acceptedJobsRef.current.delete(app.id);
        setOperatingApp(app.id);
        markPending(app.id, 'updating');
        try {
            const res = await dispatchPackageUpdate(app.id, app.latest_version);
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                clearPending(app.id);
                throw new Error(data.message || 'Update request failed');
            }
            await rememberJob(app.id, res, 'updating');
            addToast(`Updating ${app.name}${app.latest_version ? ` to v${app.latest_version.replace(/^v/i, '')}` : ''}...`, 'info');
            setOperatingApp(null);
            mutate();
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Network error.', 'error');
            clearPending(app.id);
            setOperatingApp(null);
        }
    };

    const handleUninstall = async (app: App, purge = false) => {
        if (isPublicRedactedMode) return;
        acceptedJobsRef.current.delete(app.id);
        setOperatingApp(app.id);
        markPending(app.id, 'uninstalling');
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(app.id)}/uninstall${purge ? "?purge=true" : ""}`, { method: 'POST' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                clearPending(app.id);
                throw new Error(data.message || 'Uninstallation request failed');
            }
            await rememberJob(app.id, res, 'uninstalling');
            addToast(`Uninstalling ${app.name}...`, 'info');
            setOperatingApp(null);
            mutate();
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Network error.', 'error');
            clearPending(app.id);
            setOperatingApp(null);
        }
    };

    return (
        <div className="space-y-6 min-w-0 max-w-full">
            <div className="flex flex-col sm:flex-row gap-4 justify-between items-start sm:items-center pb-2 min-w-0">
                <div className="space-y-1 min-w-0">
                    <h2 className="text-2xl sm:text-3xl font-black text-white tracking-tight flex items-center gap-3">
                        AetherMarketplace
                        <span className="text-xs font-semibold px-2.5 py-0.5 bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 rounded-full uppercase tracking-wider">Beta</span>
                    </h2>
                    <p className="text-slate-400 text-xs sm:text-sm font-medium">Extend your system with high-performance native modules.</p>
                </div>

                <div className="relative w-full sm:w-72 md:w-80 min-w-0 shrink-0">
                    <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" size={16} />
                    <input
                        type="text"
                        placeholder="Find apps and services..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full h-11 min-h-[44px] pl-10 pr-9 bg-white/[0.03] border border-white/[0.08] rounded-xl text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                    />
                    {searchQuery.length > 0 && (
                        <button
                            type="button"
                            onClick={() => setSearchQuery('')}
                            title="Clear search"
                            aria-label="Clear search"
                            className="obs-touch-target-standard absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 p-1.5 rounded min-h-[40px] min-w-[40px] flex items-center justify-center"
                        >
                            <XCircle size={14} />
                        </button>
                    )}
                </div>
            </div>

            <div role="group" aria-label="Application categories" className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none obs-touch-pills min-w-0 border-b border-white/[0.07]">
                <Filter size={15} className="text-slate-500 shrink-0 mr-1" />
                {categories.map((cat) => (
                    <button
                        key={cat}
                        type="button"
                        onClick={() => setCategoryFilter(cat)}
                        className={`obs-touch-target-standard px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors whitespace-nowrap min-h-[40px] flex items-center ${categoryFilter === cat ? 'bg-indigo-600 text-white shadow-sm' : 'bg-white/[0.03] text-slate-400 hover:text-slate-200 border border-white/[0.08]'}`}
                    >
                        {cat}
                    </button>
                ))}
            </div>

            {isPublicRedactedMode && (
                <div
                    role="alert"
                    data-testid="unauthenticated-catalog-banner"
                    className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 flex items-start gap-3"
                >
                    <AlertCircle className="text-amber-400 shrink-0 mt-0.5" size={20} />
                    <div className="space-y-1">
                        <h4 className="text-sm font-bold text-amber-300">Public Catalog Mode</h4>
                        <p className="text-xs sm:text-sm text-amber-200/90 leading-relaxed font-medium">
                            Session verification required — showing public catalog only. Installed status, versions, and lifecycle actions are hidden until you re-authenticate.
                        </p>
                    </div>
                </div>
            )}

            {isLoading && (
                <div className={APP_CATALOGUE_GRID}>
                    {[1, 2, 3, 4, 5, 6].map((i) => (
                        <div key={i} className="h-64 p-6 bg-white/[0.01] animate-pulse" />
                    ))}
                </div>
            )}

            {isBlockingError && (
                <div role="alert" className="flex flex-col items-center justify-center py-16 px-4 bg-rose-500/[0.05] border-y border-rose-500/20 space-y-4">
                    <AlertCircle className="text-red-400" size={40} />
                    <div className="text-center">
                        <h3 className="text-lg font-bold text-white">Marketplace Unreachable</h3>
                        <p className="text-red-400/80 text-xs sm:text-sm mt-1">Check your API connection or server status.</p>
                    </div>
                    <button
                        type="button"
                        onClick={() => mutate()}
                        className="obs-touch-target-standard px-5 py-2 bg-red-500/15 text-red-300 hover:bg-red-500/25 border border-red-500/30 rounded-lg transition-colors text-xs font-semibold min-h-[40px]"
                    >
                        Retry Connection
                    </button>
                </div>
            )}

            {isTransientBackgroundError && (
                <div
                    role="alert"
                    data-testid="marketplace-transient-error-banner"
                    className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-200 flex items-center justify-between gap-3 text-xs"
                >
                    <div className="flex items-center gap-2">
                        <AlertCircle className="text-amber-400 shrink-0" size={16} />
                        <span>Unable to refresh live marketplace data. Displaying cached inventory.</span>
                    </div>
                    <button
                        type="button"
                        onClick={() => mutate()}
                        className="obs-touch-target-standard px-3 py-1 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 rounded border border-amber-500/30 font-semibold"
                    >
                        Retry Connection
                    </button>
                </div>
            )}

            {!isLoading && !isBlockingError && apps && filteredApps.length === 0 && (
                <div className="text-center text-slate-400 py-12 px-4 border-y border-white/[0.07] text-xs sm:text-sm font-medium">
                    No applications found matching your criteria.
                </div>
            )}

            {!isLoading && !isBlockingError && apps && filteredApps.length > 0 && (
                <div className={APP_CATALOGUE_GRID}>
                    {filteredApps.map((app) => {
                        const effectiveStatus = getEffectiveStatus(app);
                        const busy = isAppBusy(app);

                        return (
                            <div
                                key={app.id}
                                role="article"
                                aria-label={`${app.name} application`}
                                className="relative min-w-0 p-5 sm:p-6 bg-transparent hover:bg-white/[0.02] transition-colors group flex flex-col justify-between overflow-hidden"
                            >
                                <div className={`absolute top-0 left-0 w-1 h-full ${busy ? 'bg-amber-400 animate-pulse' : ((!isPublicRedactedMode && effectiveStatus === 'installed') ? 'bg-emerald-500' : 'bg-slate-600')} transition-colors z-20`} />

                                {!isPublicRedactedMode && busy && (
                                    <div className="absolute inset-0 bg-slate-950/85 backdrop-blur-sm z-20 flex items-center justify-center p-6 text-center">
                                        <ProgressRing
                                            progress={app.progress || 0}
                                            status={effectiveStatus}
                                            logLine={app.log_line}
                                            startedAt={app.started_at}
                                        />
                                    </div>
                                )}

                                <div className="space-y-4 min-w-0">
                                    <div className="flex items-start justify-between gap-3 min-w-0">
                                        <div className="h-16 w-16 sm:h-18 sm:w-18 bg-white/[0.04] rounded-2xl border border-white/[0.08] flex items-center justify-center shadow-inner overflow-hidden relative shrink-0">
                                            <AppIcon app={app} />
                                        </div>
                                        <span className="text-xs font-bold uppercase tracking-widest text-indigo-400 bg-indigo-500/10 px-2.5 py-1 rounded-full border border-indigo-500/20 shrink-0">
                                            {app.category}
                                        </span>
                                    </div>

                                    <div className="space-y-1.5 min-w-0">
                                        <h3 className="text-base sm:text-lg font-bold text-slate-100 tracking-tight line-clamp-1 break-words">
                                            {app.name}
                                        </h3>
                                        <p className="text-xs sm:text-sm text-slate-400 line-clamp-2 leading-relaxed font-normal">{app.desc}</p>
                                    </div>

                                    <div className="flex flex-wrap gap-1.5 min-w-0">
                                        {!isPublicRedactedMode && app.status === 'installed' && !pendingJobs.has(app.id) && (
                                            <span className="inline-flex items-center gap-1.5 text-xs bg-emerald-500/10 text-emerald-400 px-2.5 py-0.5 rounded-full border border-emerald-500/20 font-bold uppercase tracking-tight">
                                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                                                Active
                                            </span>
                                        )}
                                        {!isPublicRedactedMode && app.status === 'installed' && app.public_domain && (
                                            <a
                                                href={`${app.tls_enabled === false ? 'http:' : 'https:'}//${app.public_domain}${app.web_path ? (app.web_path.startsWith('/') ? app.web_path : `/${app.web_path}`) : ''}`}
                                                target="_blank"
                                                rel="noopener noreferrer"
                                                className="inline-flex items-center gap-1.5 text-xs bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 px-2.5 py-0.5 rounded-full border border-indigo-500/20 font-mono transition-colors"
                                                title={`Open ${app.tls_enabled === false ? 'http' : 'https'}://${app.public_domain}`}
                                            >
                                                <Globe size={10} className="text-indigo-400 shrink-0" />
                                                <span className="truncate max-w-[150px]">{app.public_domain}</span>
                                            </a>
                                        )}
                                        {!isPublicRedactedMode && effectiveStatus === 'installed' && app.update_available && (
                                            <span
                                                className="inline-flex items-center gap-1.5 text-xs bg-amber-500/10 text-amber-400 px-2.5 py-0.5 rounded-full border border-amber-500/20 font-bold uppercase tracking-tight"
                                            >
                                                <RefreshCw size={10} className="animate-spin-slow shrink-0" />
                                                v{app.latest_version ? app.latest_version.replace(/^v/i, '') : 'Update'}{app.update_error ? ' (last confirmed)' : ''}
                                            </span>
                                        )}
                                        {!isPublicRedactedMode && app.update_error && (
                                            <span
                                                className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-0.5 rounded-full border font-bold uppercase tracking-tight ${app.update_available ? 'bg-amber-500/10 text-amber-300 border-amber-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}
                                                title={app.update_available ? `Check stale: ${app.update_error}` : `Update check failed: ${app.update_error}`}
                                            >
                                                <AlertCircle size={10} className="shrink-0" />
                                                {app.update_available ? `Check stale: ${app.update_error}` : 'Check failed'}
                                            </span>
                                        )}
                                        {!isPublicRedactedMode && (app.update_checked_at || app.checked_at) && (
                                            <span
                                                className="inline-flex items-center gap-1 text-xs text-slate-400 font-mono"
                                                title={`Last checked: ${app.update_checked_at || app.checked_at}`}
                                            >
                                                Checked {formatCheckedAt(app.update_checked_at || app.checked_at)}
                                            </span>
                                        )}
                                        {isPublicRedactedMode && (
                                            <span className="inline-flex items-center gap-1.5 text-xs bg-slate-800 text-slate-400 px-2.5 py-0.5 rounded-full border border-white/10 font-bold uppercase tracking-tight">
                                                Status Hidden
                                            </span>
                                        )}
                                    </div>
                                </div>

                                {(() => {
                                    const measuredDownloads = typeof totalGithubDownloads === 'number' && totalGithubDownloads > 0
                                        ? totalGithubDownloads
                                        : null;
                                    const displayDownloads = measuredDownloads !== null
                                        ? (measuredDownloads >= 1000
                                            ? (measuredDownloads / 1000).toFixed(1) + 'k'
                                            : measuredDownloads.toString())
                                        : null;

                                    return (
                                        <div className="mt-6 pt-4 border-t border-white/[0.07] flex items-center justify-between gap-2 min-w-0">
                                            {displayDownloads !== null ? (
                                                <div className="flex items-center gap-1.5 text-slate-500 text-xs font-semibold uppercase tracking-wider shrink-0">
                                                    <Download size={13} className="text-indigo-400/70" />
                                                    <span>{displayDownloads}</span> <span className="text-xs font-medium lowercase tracking-normal opacity-60">downloads</span>
                                                </div>
                                            ) : (
                                                <div />
                                            )}
                                            <div className="flex items-center justify-end flex-wrap gap-2 min-w-0">
                                                {isPublicRedactedMode ? (
                                                    <button
                                                        type="button"
                                                        disabled
                                                        title="Sign in to view status"
                                                        className="obs-touch-target-standard px-4 py-2 rounded-lg text-xs font-semibold min-h-[40px] bg-slate-800/80 text-slate-400 border border-white/10 cursor-not-allowed flex items-center gap-1.5"
                                                    >
                                                        Inventory Locked
                                                    </button>
                                                ) : (
                                                    <>
                                                        {app.status === 'installed' && (
                                                            <button
                                                                type="button"
                                                                onClick={() => setIngressModalApp(app.id)}
                                                                className="obs-touch-target-standard p-2 text-slate-400 hover:text-indigo-300 rounded-lg hover:bg-white/5 transition-colors border border-white/10 flex items-center justify-center min-h-[40px] min-w-[40px]"
                                                                title="Ingress & Deployment"
                                                                aria-label={`${app.name} Ingress and Deployment`}
                                                            >
                                                                <Globe size={14} />
                                                            </button>
                                                        )}
                                                        {effectiveStatus === 'installed' && app.update_available && (
                                                            <>
                                                                {app.update_error && (
                                                                    <button
                                                                        type="button"
                                                                        onClick={() => busy || checkingUpdateApp === app.id ? null : handleRecheck(app)}
                                                                        disabled={busy || checkingUpdateApp === app.id}
                                                                        className="obs-touch-target-standard px-3 py-2 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 min-h-[40px] bg-slate-800 hover:bg-slate-700 text-slate-300 border border-white/10 disabled:opacity-50"
                                                                        title={`Recheck update for ${app.name}: ${app.update_error}`}
                                                                        aria-label={`Recheck update for ${app.name}`}
                                                                    >
                                                                        <RefreshCw size={12} className={checkingUpdateApp === app.id ? 'animate-spin' : ''} />
                                                                        Recheck
                                                                    </button>
                                                                )}
                                                                <button
                                                                    type="button"
                                                                    onClick={() => (busy || !app.latest_version) ? null : handleUpdate(app)}
                                                                    disabled={busy || !app.latest_version}
                                                                    className={`obs-touch-target-standard px-3.5 py-2 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 min-h-[40px] ${(busy || !app.latest_version) ? 'bg-slate-900 text-slate-600 cursor-not-allowed border border-white/5' : 'bg-amber-500/15 text-amber-300 hover:bg-amber-500 hover:text-slate-950 border border-amber-500/30'}`}
                                                                    title={app.latest_version ? (app.update_error ? `Update to v${app.latest_version.replace(/^v/i, '')} (last confirmed)` : `Update to v${app.latest_version.replace(/^v/i, '')}`) : (app.update_error ? 'Update (last confirmed)' : 'Update available')}
                                                                >
                                                                    <RefreshCw size={12} className={busy ? 'animate-spin' : ''} />
                                                                    Update
                                                                </button>
                                                            </>
                                                        )}
                                                        {app.last_job && app.last_job.status !== 'completed' && !busy && (
                                                            <span role="status" className="text-xs text-red-300">
                                                                Last {app.last_job.action}: {app.last_job.status}
                                                                {app.last_job.failed_stage ? ` (${app.last_job.failed_stage}${typeof app.last_job.exit_code === 'number' ? `:${app.last_job.exit_code}` : ''})` : ''}
                                                                {app.last_job.sanitized_summary ? ` — ${app.last_job.sanitized_summary}` : '. Check logs.'}
                                                            </span>
                                                        )}
                                                        {effectiveStatus === 'installed' && (
                                                            <button
                                                                type="button"
                                                                disabled={busy}
                                                                onClick={() => setReinstallAppId(app.id)}
                                                                className="obs-touch-target-standard px-3 py-2 text-xs font-medium text-slate-300 hover:text-white rounded-lg border border-white/10 hover:bg-white/5 disabled:opacity-50 min-h-[40px]"
                                                            >
                                                                Reinstall
                                                            </button>
                                                        )}
                                                        <button
                                                            type="button"
                                                            onClick={() => busy ? null : (effectiveStatus === 'installed' ? setRemoveAppId(app.id) : handleInstall(app))}
                                                            disabled={busy}
                                                            className={`obs-touch-target-standard px-4 py-2 rounded-lg text-xs font-semibold transition-all min-h-[40px] ${busy ? 'bg-slate-900 text-slate-600 cursor-not-allowed border border-white/10' : (effectiveStatus === 'installed' ? 'bg-white/5 text-slate-300 hover:bg-red-500/15 hover:text-red-300 border border-white/10' : 'bg-indigo-600 text-white hover:bg-indigo-500 border border-indigo-500/30 shadow-sm')}`}
                                                        >
                                                            {effectiveStatus === 'installed' ? 'Uninstall' : (effectiveStatus === 'installing' || effectiveStatus === 'reinstalling' ? 'Deploying...' : (effectiveStatus === 'updating' ? 'Updating...' : (effectiveStatus === 'uninstalling' ? 'Removing...' : 'Provision')))}
                                                        </button>
                                                    </>
                                                )}
                                            </div>
                                        </div>
                                    );
                                })()}
                            </div>
                        );
                    })}
                </div>
            )}

            {canRenderModals && selectedRemoveApp && (
                <Modal isOpen title={`Uninstall ${selectedRemoveApp.name}`} onClose={() => { setRemoveAppId(null); setPurgeData(false); setPurgeConfirmation(''); }}>
                    <div className="min-w-0 space-y-4">
                        <p className="text-sm text-slate-300">Ordinary uninstall retains application data, configuration, secrets, and the allocated port for a later reinstall.</p>
                        <label className="flex gap-2 text-sm"><input type="checkbox" checked={purgeData} onChange={event => setPurgeData(event.target.checked)} /> Permanently delete application data and configuration</label>
                        {purgeData && <><p className="text-sm text-red-300">Purge asks the remover to delete {selectedRemoveApp.name}&apos;s managed databases, configuration, credentials, and data. Existing backups may remain. This cannot be undone.</p><label className="block text-sm">Type {selectedRemoveApp.id} to confirm<input aria-label="Purge confirmation" value={purgeConfirmation} onChange={event => setPurgeConfirmation(event.target.value)} className="block w-full mt-2 bg-slate-950 rounded p-2" /></label></>}
                        <div className="flex flex-wrap justify-end gap-3"><button type="button" className="glass-button obs-touch-target-standard px-4 py-2" onClick={() => { setRemoveAppId(null); setPurgeData(false); setPurgeConfirmation(''); }}>Cancel</button><button type="button" disabled={isAppBusy(selectedRemoveApp) || (purgeData && purgeConfirmation !== selectedRemoveApp.id)} onClick={() => { void handleUninstall(selectedRemoveApp, purgeData); setRemoveAppId(null); setPurgeData(false); setPurgeConfirmation(''); }} className="obs-touch-target-standard bg-red-600 text-white disabled:opacity-40 rounded-xl px-4 py-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-rose-400">{purgeData ? 'Permanently purge' : 'Uninstall and keep data'}</button></div>
                    </div>
                </Modal>
            )}
            {canRenderModals && selectedReinstallApp && (
                <Modal isOpen title={`Reinstall ${selectedReinstallApp.name}`} onClose={() => setReinstallAppId(null)}>
                    <div className="min-w-0 space-y-4">
                        <p className="text-sm text-slate-300">Reapply the installer in place using the existing configuration, data, secrets, and allocated port. The application may restart.</p>
                        <div className="flex flex-wrap justify-end gap-3"><button type="button" className="glass-button obs-touch-target-standard px-4 py-2" onClick={() => setReinstallAppId(null)}>Cancel</button><button type="button" disabled={isAppBusy(selectedReinstallApp)} onClick={() => { void handleInstall(selectedReinstallApp, true); setReinstallAppId(null); }} className="obs-touch-target-standard bg-indigo-600 text-white rounded-xl px-4 py-2 disabled:opacity-40 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-400">Reinstall and keep data</button></div>
                    </div>
                </Modal>
            )}

            {/* Installed Plugins & Runtime Extensions Section */}
            <div className="pt-6 border-t border-white/[0.07] space-y-4" data-testid="installed-plugins-section">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="space-y-1">
                        <h3 className="text-lg sm:text-xl font-black text-white tracking-tight flex items-center gap-2.5">
                            <Puzzle size={18} className="text-indigo-400" />
                            Installed Plugins &amp; Runtime Extensions
                            <span className="text-xs font-bold px-2.5 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded-full uppercase tracking-wider">
                                Scoped Sandbox v1
                            </span>
                        </h3>
                        <p className="text-slate-400 text-xs font-medium">
                            Isolated loopback companion plugins with manifest-bound short-lived tokens and opaque sandboxed UI origins.
                        </p>
                    </div>
                    <button
                        type="button"
                        onClick={() => fetchPlugins()}
                        className="obs-touch-target-standard px-3.5 py-2 rounded-lg bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.08] text-xs font-semibold text-slate-300 flex items-center gap-2 transition-colors self-start sm:self-auto min-h-[40px]"
                    >
                        <RefreshCw size={13} />
                        Refresh Plugins
                    </button>
                </div>

                {rejectedPlugins.length > 0 && (
                    <div className="border-y border-amber-500/20 bg-amber-500/5 p-4 space-y-1" data-testid="rejected-plugins-banner">
                        <p className="text-xs font-bold text-amber-300 uppercase tracking-wider">Rejected Plugin Manifests</p>
                        {rejectedPlugins.map((item) => (
                            <p key={item.id} className="text-xs text-amber-200/80 font-mono">
                                {item.id}: {item.error}
                            </p>
                        ))}
                    </div>
                )}

                {plugins.length === 0 ? (
                    <div className="border-y border-white/[0.07] py-8 text-center text-slate-400 text-xs">
                        No validated plugins discovered in <code className="text-indigo-300">plugins/</code>. Scaffold one with <code className="text-indigo-300">bash scripts/create-plugin-sdk.sh my-plugin &quot;My Plugin&quot; plugins/my-plugin rust</code>.
                    </div>
                ) : (
                    <div className={PLUGIN_CATALOGUE_GRID}>
                        {plugins.map((plugin) => {
                            const isBusy = operatingPlugin === plugin.id;
                            return (
                                <div
                                    key={plugin.id}
                                    data-testid={`plugin-card-${plugin.id}`}
                                    role="article"
                                    aria-label={`${plugin.name} plugin`}
                                    className="relative min-w-0 p-5 sm:p-6 bg-transparent hover:bg-white/[0.02] transition-colors flex flex-col justify-between group overflow-hidden gap-5"
                                >
                                    <div className="space-y-4 min-w-0">
                                        <div className="flex items-start justify-between gap-3 min-w-0">
                                            <div className="min-w-0">
                                                <div className="flex items-center gap-2 flex-wrap">
                                                    <h4 className="text-base sm:text-lg font-bold text-white tracking-tight">{plugin.name}</h4>
                                                    <span className="text-xs font-mono text-slate-400 bg-white/5 px-2 py-0.5 rounded-md">
                                                        v{plugin.version}
                                                    </span>
                                                </div>
                                                <p className="text-xs font-mono text-indigo-400 mt-0.5 truncate">
                                                    id: {plugin.id} · sdk: {plugin.sdk}
                                                </p>
                                            </div>
                                            <span
                                                className={`text-xs font-bold uppercase tracking-wider px-2.5 py-1 rounded-full border shrink-0 ${
                                                    plugin.enabled
                                                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                                                        : 'bg-white/5 text-slate-400 border-white/10'
                                                }`}
                                            >
                                                {plugin.enabled ? (plugin.healthy ? 'Healthy' : 'Enabled') : 'Stopped'}
                                            </span>
                                        </div>

                                        <p className="text-xs text-slate-400 leading-relaxed font-normal">
                                            {plugin.description || 'Sandboxed AetherFlow runtime extension.'}
                                        </p>

                                        <div className="space-y-1.5 min-w-0">
                                            <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-slate-400">
                                                <ShieldCheck size={12} className="text-indigo-400 shrink-0" />
                                                Granted Scopes
                                            </div>
                                            <div className="flex flex-wrap gap-1.5 min-w-0">
                                                {plugin.granted_scopes.length === 0 ? (
                                                    <span className="text-xs font-mono text-slate-500 bg-white/[0.03] px-2 py-0.5 rounded">
                                                        default-deny (no host API scopes)
                                                    </span>
                                                ) : (
                                                    plugin.granted_scopes.map((s, idx) => (
                                                        <span
                                                            key={`${s.method}-${s.route}-${idx}`}
                                                            className="text-xs font-mono text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 px-2 py-0.5 rounded"
                                                        >
                                                            {s.method} {s.route}
                                                        </span>
                                                    ))
                                                )}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="pt-4 border-t border-white/[0.07] flex items-center justify-between gap-2 min-w-0">
                                        <span className="text-xs font-mono text-slate-500 shrink-0">
                                            {plugin.allocated_port > 0 ? `127.0.0.1:${plugin.allocated_port}` : 'Loopback dynamic'}
                                        </span>
                                        <div className="flex items-center gap-2 flex-wrap justify-end min-w-0">
                                            {plugin.enabled && (
                                                <button
                                                    type="button"
                                                    onClick={() => setMountedPlugin(plugin)}
                                                    data-testid={`open-plugin-ui-${plugin.id}`}
                                                    className="obs-touch-target-standard px-3 py-2 rounded-lg text-xs font-semibold bg-indigo-500/15 text-indigo-300 hover:bg-indigo-500/25 border border-indigo-500/30 flex items-center gap-1.5 transition-all min-h-[40px]"
                                                >
                                                    <ExternalLink size={12} />
                                                    Open Sandboxed UI
                                                </button>
                                            )}
                                            <button
                                                type="button"
                                                disabled={isBusy}
                                                onClick={() => handlePluginControl(plugin, plugin.enabled ? 'stop' : 'start')}
                                                data-testid={`toggle-plugin-${plugin.id}`}
                                                className={`obs-touch-target-standard px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all min-h-[40px] ${
                                                    plugin.enabled
                                                        ? 'bg-white/5 text-slate-300 hover:bg-red-500/15 hover:text-red-300 border border-white/10'
                                                        : 'bg-indigo-600 text-white hover:bg-indigo-500 border border-indigo-500/30'
                                                }`}
                                            >
                                                {plugin.enabled ? <Square size={11} /> : <Play size={11} />}
                                                {plugin.enabled ? 'Disable' : 'Enable'}
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            {mountedPlugin && (
                <Modal
                    isOpen
                    title={`${mountedPlugin.name} Plugin Sandbox`}
                    onClose={() => setMountedPlugin(null)}
                    className="max-w-3xl"
                    data-testid="plugin-sandbox-modal"
                >
                    <div className="min-w-0 space-y-4">
                        <div className="flex items-center justify-between pb-3 border-b border-white/10">
                            <div className="flex items-center gap-2.5">
                                <ShieldCheck className="text-emerald-400" size={20} />
                                <div>
                                    <h3 className="text-base font-bold text-white">
                                        {mountedPlugin.name} <span className="text-xs font-mono text-slate-400">({mountedPlugin.id})</span>
                                    </h3>
                                    <p className="text-xs text-slate-400">
                                        Isolated Opaque Origin Sandbox (<code className="text-emerald-300">sandbox=&quot;allow-scripts&quot;</code>) · Loopback Proxy <code className="text-indigo-300">127.0.0.1:{mountedPlugin.allocated_port}</code>
                                    </p>
                                </div>
                            </div>
                        </div>
                        <div className="rounded-2xl overflow-hidden border border-white/10 bg-slate-950 h-[360px]">
                            <iframe
                                ref={pluginIframeRef}
                                title={`Plugin Sandbox: ${mountedPlugin.name}`}
                                src={mountedPlugin.ui_url}
                                sandbox="allow-scripts"
                                referrerPolicy="no-referrer"
                                data-testid="plugin-sandbox-iframe"
                                className="w-full h-full border-0"
                            />
                        </div>
                        <div className="flex justify-end">
                            <button type="button" onClick={() => setMountedPlugin(null)} data-testid="close-plugin-sandbox" className="glass-button obs-touch-target-standard px-4 py-2">Close plugin</button>
                        </div>
                    </div>
                </Modal>
            )}

            {canRenderModals && ingressModalApp && (
                <Modal isOpen title={`${ingressModalApp} Ingress & Deploy`} className="max-w-xl" onClose={() => { setIngressModalApp(null); setDeployTriggeredApp(null); }}>
                        <div className="space-y-4">
                            <ExternalAccessCard appName={ingressModalApp} />
                            <DeploymentStatus
                                appName={ingressModalApp}
                                isTriggered={
                                    deployTriggeredApp === ingressModalApp ||
                                    operatingApp === ingressModalApp ||
                                    pendingJobs.has(ingressModalApp)
                                }
                            />
                        </div>
                </Modal>
            )}
        </div>
    );
}
