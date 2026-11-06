'use client';

import { RefreshCw, Box, Settings, Globe, RotateCcw, Square, Play, Server, Cpu, X, Network, ArrowUpCircle, ExternalLink, Key, Eye, EyeOff, Copy, Check, AlertCircle } from 'lucide-react';
import { useState, useEffect, useRef, useCallback } from 'react';
import { useCoreRestart } from '@/hooks/useCoreRestart';
import { useLifecyclePollRecovery } from '@/hooks/useLifecyclePollRecovery';
import useSWR, { useSWRConfig } from 'swr';
import { useToast } from '@/contexts/ToastContext';
import { useAuth } from '@/contexts/AuthContext';
import { ServicesSkeleton } from '@/components/layout/SkeletonBox';
import { apiFetch } from '@/lib/fetcher';
import RequireClaim from '@/components/auth/RequireClaim';
import ServiceLogsModal from '@/components/tabs/ServiceLogsModal';
import { Terminal } from 'lucide-react';
import { useSystemStore } from '@/store/useSystemStore';
import { ExternalAccessCard } from '@/components/ingress/ExternalAccessCard';
import { DeploymentStatus } from '@/components/deploy/DeploymentStatus';
import { ProgressRing } from '@/components/ui/ProgressRing';
import { isLifecycleStatus, lifecycleIdentity, matchingActiveJob, matchingJobOutcome, MarketplaceJobOutcome, PendingAction, LIFECYCLE_RECEIPT_TIMEOUT_MS } from '@/hooks/useMarketplace';

// Fallback map when default_port is not provided by backend
const SERVICE_WEB_PORTS: Record<string, number | string> = {
    'plexmediaserver': 32400,
    'jellyfin': 8096,
    'emby-server': 8097,
    'sonarr': 8989,
    'radarr': 7878,
    'lidarr': 8686,
    'readarr': 8787,
    'prowlarr': 9696,
    'bazarr': 6767,
    'jellyseerr': 5055,
    'overseerr': 5056,
    'ombi': 5000,
    'tautulli': 8181,
    'af-maintainerr': 6246,
    'jackett': 9117,
    'flaresolverr': 8191,
    'navidrome': 4533,
    'threadfin': 34400,
    'qbittorrent': 8180,
    'deluged': 8112,
    'transmission-daemon': 9091,
    'sabnzbd': 8085,
    'nzbget': 6789,
    'flood': 3001,
    'autobrr': 7474,
    'qui': 7476,
    'nextcloud': 8088,
    'syncthing': 8384,
    'filebrowser': 8095,
    'pihole-FTL': 8089,
    'vaultwarden': 8343,
    'grafana-server': 3000,
    'prometheus': 9090,
    'netdata': 19999,
    'uptime-kuma': 3004,
    'home-assistant@homeassistant': 8123,
    'adguardhome': 3080,
    'rutorrent': 8087,
    'rclone': 5572,
    'autoscan': 3030,
    'audiobookshelf': 13378,
    'kavita': 5002,
    'calibreweb': 8083,
    'librespeed': 8988,
    'thelounge': 9000,
    'znc': 6501,
    'scrutiny': 8098,
    'paperless-ngx': 8010,
    'paperless-webserver': 8010,
    'n8n': 5678,
    'gitea': 3002,
    'organizr': 8086,
    'dispatcharr': 9191,
    'duplicati': 8200,
    'filebot': 5452,
    'listenarr': 4546,
    'notifiarr': 5454,
    'novnc': 6080,
    'pyload': 8000,
    'requestrr': 4545,
    'seedcross': 8019,
    'unmanic': 8888,
    'palate': 28014,
    'af-palate': 28014,
    'kasmvnc': 6081,
    'af-kasmvnc': 6081,
    'mcvnc': 6900,
    'af-mcvnc': 6900,
    'apache2': 443,
    'aetherflow-frontend': '/',
    'aetherflow-api': '/api/v1/admin/services',
};

export interface ServiceComponentInfo {
    unit: string;
    role?: string;
    status?: string;
    configured?: boolean;
}

export interface ServiceInfo {
    status: string;
    version: string;
    installed_version?: string;
    latest_version?: string;
    update_available?: boolean;
    update_checked_at?: string;
    update_url?: string;
    update_error?: string;
    job_status?: string;
    job_id?: string;
    last_job?: MarketplaceJobOutcome;
    progress?: number;
    log_line?: string;
    started_at?: string;
    uptime: string;
    managed_by?: string;
    process?: string;
    id?: string;
    default_port?: number;
    active_port?: number;
    api_key?: string;
    internal_domain?: string;
    public_domain?: string;
    external_access_enabled?: boolean;
    tls_enabled?: boolean;
    web_path?: string;
    web_scheme?: string;
    bind_scope?: 'loopback' | 'network' | string;
    control_scope?: 'shared-vhost' | 'service' | string;
    units?: string[];
    components?: ServiceComponentInfo[];
}

interface NormalizedUpdateCheckRecord {
    updateAvailable: boolean;
    installedVersion: string;
    latestVersion: string;
    updateUrl: string;
    checkedAt: string;
    error: string;
}

const LOOPBACK_IDENTIFIERS = new Set([
    'maintainerr',
    'af-maintainerr',
    'af-maintainerr.service',
    'palate',
    'af-palate',
    'af-palate.service',
    'kasmvnc',
    'af-kasmvnc',
    'af-kasmvnc.service',
    'mcvnc',
    'af-mcvnc',
    'af-mcvnc.service',
]);

const SHARED_VHOST_APP_IDS = new Set([
    'nextcloud',
    'rutorrent',
    'organizr',
]);

function normalizeUpdateRecord(raw: unknown): NormalizedUpdateCheckRecord {
    const top = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
    const nested = (top.update && typeof top.update === 'object' ? top.update : {}) as Record<string, unknown>;

    const pickString = (...vals: unknown[]): string => {
        for (const v of vals) {
            if (typeof v === 'string' && v.trim()) {
                return v.trim();
            }
        }
        return '';
    };

    const error = pickString(
        nested.error,
        nested.last_error,
        nested.update_error,
        top.last_error,
        top.update_error,
        top.error
    );
    const rawAvailable =
        typeof nested.update_available === 'boolean'
            ? nested.update_available
            : typeof top.update_available === 'boolean'
                ? top.update_available
                : false;

    return {
        updateAvailable: !error && rawAvailable,
        installedVersion: pickString(nested.installed_version, top.installed_version),
        latestVersion: pickString(nested.latest_version, top.latest_version),
        updateUrl: pickString(nested.release_url, nested.update_url, top.update_url, top.release_url),
        checkedAt: pickString(nested.checked_at, nested.update_checked_at, top.checked_at, top.update_checked_at),
        error,
    };
}

interface ServicesTabProps {
    browserOrigin?: {
        protocol: string;
        hostname: string;
    };
}

export default function ServicesTab({ browserOrigin }: ServicesTabProps = {}) {
    const { addToast } = useToast();
    const { restarts, trackRestart } = useCoreRestart(addToast);
    const { user } = useAuth();
    const { mutate: globalMutate } = useSWRConfig();
    const [serviceControl, setServiceControl] = useState<{ name: string; status: string } | null>(null);
    const [updatingServices, setUpdatingServices] = useState<Set<string>>(new Set());
    const [checkingUpdates, setCheckingUpdates] = useState(false);
    const [checkingSingleService, setCheckingSingleService] = useState<string | null>(null);
    const [logsModalService, setLogsModalService] = useState<string | null>(null);
    const [logsModalUnits, setLogsModalUnits] = useState<string[] | undefined>(undefined);
    const [ingressModalApp, setIngressModalApp] = useState<string | null>(null);
    const [revealedKeys, setRevealedKeys] = useState<Set<string>>(new Set());
    const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    useEffect(() => () => { if (copyTimerRef.current) clearTimeout(copyTimerRef.current); }, []);
    const [copiedKeyService, setCopiedKeyService] = useState<string | null>(null);
    const canControlServices = user?.role === 'admin';
    const { setActiveTab } = useSystemStore();

    const observedJobsRef = useRef<Map<string, { action: PendingAction; identity: string }>>(new Map());
    const notifiedUpdateRef = useRef<Set<string>>(new Set());
    const expectedJobsRef = useRef<Map<string, string>>(new Map());
    const updateDeadlinesRef = useRef<Map<string, number>>(new Map());

    useEffect(() => {
        if (!updatingServices.size || !updateDeadlinesRef.current.size) return;
        let timer: ReturnType<typeof setTimeout>;
        const schedule = () => {
            if (updateDeadlinesRef.current.size) timer = setTimeout(checkDeadlines, Math.max(0, Math.min(...updateDeadlinesRef.current.values()) - Date.now()));
        };
        const checkDeadlines = () => {
            const expired: string[] = [];
            updateDeadlinesRef.current.forEach((deadline, appId) => {
                if (deadline > Date.now()) return;
                expired.push(appId);
                // Retain accepted identity so a late terminal receipt still resolves.
                updateDeadlinesRef.current.delete(appId);
                addToast(`${appId}: update outcome could not be confirmed; its receipt may have been superseded. Check service state and logs before retrying.`, 'error');
            });
            if (expired.length) setUpdatingServices(current => new Set([...current].filter(appId => !expired.includes(appId))));
            schedule();
        };
        schedule();
        return () => clearTimeout(timer);
    }, [updatingServices, addToast]);

    const renewActiveUpdates = useCallback((snapshot?: Record<string, ServiceInfo>) => {
        Object.entries(snapshot || {}).forEach(([name, info]) => {
            const appId = info.id || name;
            if (updateDeadlinesRef.current.has(appId) && matchingActiveJob(info, 'updating', expectedJobsRef.current.get(appId))) {
                updateDeadlinesRef.current.set(appId, Date.now() + LIFECYCLE_RECEIPT_TIMEOUT_MS);
            }
        });
    }, []);

    const { data: services, error: servicesError, mutate, isLoading, isValidating } = useSWR<Record<string, ServiceInfo>>(
        '/api/v1/auth/services',
        {
            refreshInterval: (currentData) => {
                if (updatingServices.size > 0) return 1500;
                if (!currentData) return 15000;
                const hasActiveJob = Object.values(currentData).some(
                    (s) => s.status === 'updating' || s.job_status === 'updating' || s.job_status === 'installing' || s.job_status === 'uninstalling'
                );
                return hasActiveJob ? 1500 : 15000;
            },
            onSuccess: renewActiveUpdates,
            shouldRetryOnError: false,
        }
    );

    useLifecyclePollRecovery('/api/v1/auth/services', servicesError, () => mutate());

    useEffect(() => {
        if (!servicesError && !isValidating) renewActiveUpdates(services);
    }, [services, servicesError, isValidating, renewActiveUpdates]);

    useEffect(() => {
        if (!services) return;
        Object.entries(services).forEach(([name, info]) => {
            const appId = info.id || name;
            const activeAction = isLifecycleStatus(info.job_status) ? info.job_status : isLifecycleStatus(info.status) ? info.status : undefined;
            const activeIdentity = lifecycleIdentity(info);
            if (activeAction && activeIdentity && (!updatingServices.has(appId) || activeIdentity === expectedJobsRef.current.get(appId))) observedJobsRef.current.set(appId, { action: activeAction, identity: activeIdentity });
            const observed = observedJobsRef.current.get(appId);
            const localPending = updatingServices.has(appId);
            const acceptedIdentity = expectedJobsRef.current.get(appId);
            const action: PendingAction | undefined = localPending || acceptedIdentity ? 'updating' : observed?.action;
            const identity = localPending ? acceptedIdentity : acceptedIdentity || observed?.identity;
            if (!action) return;
            const outcome = matchingJobOutcome(info, action, identity);
            const outcomeId = lifecycleIdentity(outcome);
            if (!outcome || !outcomeId || notifiedUpdateRef.current.has(outcomeId)) return;
            notifiedUpdateRef.current.add(outcomeId);
            expectedJobsRef.current.delete(appId);
            updateDeadlinesRef.current.delete(appId);
            observedJobsRef.current.delete(appId);
            setUpdatingServices(curr => { const next = new Set(curr); next.delete(appId); return next; });
            if (outcome.status === 'completed') {
                addToast(`${name}: ${outcome.action} completed.`, 'success');
            } else {
                addToast(`${name}: ${outcome.action} ${outcome.status === 'failed' ? 'failed' : 'could not be confirmed'}. ${outcome.message || 'Check application state and logs.'}`, 'error');
            }
            void globalMutate('/api/v1/public/marketplace');
        });

    }, [services, updatingServices, addToast, globalMutate]);

    const handleCheckAllUpdates = async () => {
        setCheckingUpdates(true);
        try {
            if (canControlServices) {
                const res = await apiFetch('/api/v1/admin/packages/updates/check', { method: 'POST' });
                if (!res.ok) throw new Error('Application update inventory unavailable');
                if (res.ok) {
                    const payload = await res.json().catch(() => null);
                    await mutate();
                    globalMutate('/api/v1/public/marketplace');
                    const records = Array.isArray(payload?.updates)
                        ? (payload.updates as unknown[]).map((item) => normalizeUpdateRecord(item))
                        : [];
                    const failedRecords = records.filter((rec) => Boolean(rec.error));
                    const availableCount =
                        typeof payload?.updates_available === 'number'
                            ? payload.updates_available
                            : records.filter((rec) => rec.updateAvailable).length;
                    if (failedRecords.length > 0) {
                        if (availableCount > 0) {
                            addToast(
                                `${availableCount} update${availableCount === 1 ? '' : 's'} available; ${failedRecords.length} update check${failedRecords.length === 1 ? '' : 's'} failed.`,
                                'info'
                            );
                        } else {
                            addToast(
                                `Update check failed for ${failedRecords.length} application${failedRecords.length === 1 ? '' : 's'}.`,
                                'error'
                            );
                        }
                        return;
                    }
                    if (payload && typeof payload.updates_available === 'number') {
                        if (payload.updates_available > 0) {
                            addToast(`${payload.updates_available} application update${payload.updates_available === 1 ? '' : 's'} available.`, 'info');
                        } else {
                            addToast('All installed applications are up to date.', 'success');
                        }
                    } else {
                        addToast('Synchronized service states and update metadata.', 'success');
                    }
                    return;
                }
            }
            await mutate();
            addToast('Synchronized service states.', 'info');
        } catch {
            addToast('Failed to check remote updates; try again shortly.', 'error');
        } finally {
            setCheckingUpdates(false);
        }
    };

    const handleCheckSingleUpdate = async (name: string, data: ServiceInfo) => {
        if (!canControlServices || !data.id) return;
        setCheckingSingleService(name);
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(data.id)}/check-update`, {
                method: 'POST',
            });
            if (!res.ok) {
                const d = await res.json().catch(() => ({}));
                throw new Error(d.message || d.error || 'Update check failed.');
            }
            const result = await res.json().catch(() => ({}));
            const normalized = normalizeUpdateRecord(result);
            await mutate();
            globalMutate('/api/v1/public/marketplace');
            if (normalized.error) {
                addToast(`Update check failed for ${name}: ${normalized.error}`, 'error');
            } else if (normalized.updateAvailable) {
                addToast(`Update available for ${name}: v${(normalized.latestVersion || '').replace(/^v/i, '')}`, 'info');
            } else if (!normalized.installedVersion && !normalized.latestVersion && !normalized.checkedAt) {
                addToast(`Update status for ${name} is unknown.`, 'error');
            } else {
                addToast(`${name} is up to date${normalized.installedVersion ? ` (v${normalized.installedVersion.replace(/^v/i, '')})` : ''}.`, 'success');
            }
        } catch (err: unknown) {
            addToast(err instanceof Error ? err.message : 'Unable to check for updates.', 'error');
        } finally {
            setCheckingSingleService(null);
        }
    };

    const handleUpdateService = async (name: string, data: ServiceInfo) => {
        if (!canControlServices) {
            addToast('Authorization constraint: Admin privileges required to update applications.', 'error');
            return;
        }
        const appId = data.id;
        if (!appId) {
            addToast(`Cannot resolve package identifier for ${name}.`, 'error');
            return;
        }

        expectedJobsRef.current.delete(appId);
        observedJobsRef.current.delete(appId);
        updateDeadlinesRef.current.set(appId, Date.now() + LIFECYCLE_RECEIPT_TIMEOUT_MS);
        setUpdatingServices(curr => new Set(curr).add(appId));
        try {
            const res = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(appId)}/update`, {
                method: 'POST',
            });
            if (!res.ok) {
                const d = await res.json().catch(() => ({}));
                throw new Error(d.message || d.error || 'Package update request rejected.');
            }
            const receipt = await res.json() as { job_id?: string; started_at?: string };
            const identity = lifecycleIdentity(receipt);
            if (!identity) throw new Error('The server did not return a job identity. Refresh status and check logs before retrying.');
            if (!updateDeadlinesRef.current.has(appId)) throw new Error('Acceptance arrived after status tracking expired. Check service state and logs before retrying.');
            expectedJobsRef.current.set(appId, identity);
            setUpdatingServices(curr => new Set(curr).add(appId));
            const targetVer = data.latest_version ? ` to v${data.latest_version.replace(/^v/i, '')}` : '';
            addToast(`Updating ${name}${targetVer}...`, 'info');
            mutate();
            globalMutate('/api/v1/public/marketplace');
        } catch (err: unknown) {
            expectedJobsRef.current.delete(appId);
            updateDeadlinesRef.current.delete(appId);
            observedJobsRef.current.delete(appId);
            setUpdatingServices((curr) => {
                const next = new Set(curr);
                next.delete(appId);
                return next;
            });
            mutate();
            addToast(err instanceof Error ? err.message : 'Update failed to start.', 'error');
        }
    };

    const handleServiceControl = async (name: string, data: ServiceInfo, action: 'start' | 'stop' | 'restart') => {
        if (!canControlServices) {
            addToast('Authorization constraint: Admin privileges required for daemon control.', 'error');
            return;
        }
        if (isSharedVhostService(name, data)) {
            addToast(
                `${name} runs as a shared Apache VirtualHost. Stopping or restarting it from this card is disabled to avoid interrupting other sites and the gateway.`,
                'info'
            );
            return;
        }

        // Keep optimistic feedback local: SWR mutate(data) clears its error and
        // would make a cached lifecycle receipt look like a fresh server poll.
        const optimisticStatus = action === 'stop' ? 'stopping' : action === 'start' ? 'starting' : 'restarting';
        setServiceControl({ name, status: optimisticStatus });

        const canonicalTarget = (data.id || data.process || name).trim();
        const processTarget = (data.id || data.process || name).trim();
        try {
            const res = await apiFetch(`/api/v1/admin/services/${encodeURIComponent(canonicalTarget)}/control`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action,
                    managed_by: data.managed_by || 'systemd',
                    process: processTarget,
                })
            });
            if (!res.ok) {
                const d = await res.json().catch(() => ({}));
                throw new Error(d.message || d.error || 'Daemon control operation rejected.');
            }
            const receipt = await res.json().catch(() => ({}));
            if (receipt.status === 'accepted') trackRestart(name, receipt);
            else addToast(`Successfully executed '${action}' on ${name}.`, 'success');
            void mutate();
        } catch (err: unknown) {
            void mutate();
            addToast(err instanceof Error ? err.message : 'Undefined system exception encountered.', 'error');
        } finally {
            setServiceControl(null);
        }
    };

    const allEntries = Object.entries(services || {});

    const corePlatformProcesses = ['aetherflow-api', 'aetherflow-frontend', 'apache2', 'nginx'];
    const isCorePlatformService = (info: ServiceInfo) =>
        corePlatformProcesses.includes(info.id || info.process || '');

    const hasWebUI = (info: ServiceInfo) => {
        if (typeof info.default_port === 'number') {
            return info.default_port > 0;
        }
        return (
            (info.id ? SERVICE_WEB_PORTS[info.id] != null : false) ||
            (info.process ? SERVICE_WEB_PORTS[info.process] != null : false)
        );
    };

    const coreServices = allEntries.filter(([, d]) => isCorePlatformService(d as ServiceInfo));
    const appServices = allEntries.filter(([, d]) => !isCorePlatformService(d as ServiceInfo));

    const runningCount = allEntries.filter(([, d]) => (d as ServiceInfo).status === 'running').length;
    const updatesAvailableCount = appServices.filter(([, d]) => Boolean((d as ServiceInfo).update_available && !(d as ServiceInfo).update_error)).length;

    const formatVersion = (ver?: string) => {
        if (!ver || ver === '-') return '-';
        return ver.startsWith('v') || ver.startsWith('V') ? ver : `v${ver}`;
    };

    const resolveServicePort = (name: string, data: ServiceInfo): { port: number | null; defaultPort: number | null; reassigned: boolean } => {
        const activePort = typeof data.active_port === 'number' && data.active_port > 0 ? data.active_port : null;
        const defaultPort = typeof data.default_port === 'number' && data.default_port > 0 ? data.default_port : null;
        if (activePort != null) {
            return {
                port: activePort,
                defaultPort,
                reassigned: defaultPort != null && activePort !== defaultPort,
            };
        }
        if (defaultPort != null) {
            return { port: defaultPort, defaultPort, reassigned: false };
        }
        const process = data.process || name;
        const fallback = (data.id ? SERVICE_WEB_PORTS[data.id] : undefined) ?? SERVICE_WEB_PORTS[process];
        if (typeof fallback === 'number' && fallback > 0) {
            return { port: fallback, defaultPort: fallback, reassigned: false };
        }
        return { port: null, defaultPort: null, reassigned: false };
    };

    const toggleRevealKey = (serviceKey: string) => {
        setRevealedKeys((prev) => {
            const next = new Set(prev);
            if (next.has(serviceKey)) {
                next.delete(serviceKey);
            } else {
                next.add(serviceKey);
            }
            return next;
        });
    };

    const handleCopyApiKey = async (name: string, apiKey: string) => {
        try {
            await navigator.clipboard.writeText(apiKey);
            setCopiedKeyService(name);
            addToast(`Copied ${name} API key to clipboard.`, 'success');
            if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
            copyTimerRef.current = setTimeout(() => {
                setCopiedKeyService((curr) => (curr === name ? null : curr));
            }, 2000);
        } catch {
            addToast('Unable to copy API key to clipboard.', 'error');
        }
    };

    const formatMaskedApiKey = (apiKey: string) => {
        const trimmed = apiKey.trim();
        if (trimmed.length <= 6) {
            return '••••••••';
        }
        return `${'•'.repeat(12)}${trimmed.slice(-4)}`;
    };

    const isLoopbackService = (name: string, data: ServiceInfo) => {
        const scope = (data.bind_scope || '').trim().toLowerCase();
        if (scope === 'loopback') return true;
        if (scope === 'network') return false;
        const identifiers = [data.id, data.process, name]
            .filter((value): value is string => Boolean(value))
            .map((value) => value.trim().toLowerCase());
        return identifiers.some((value) => LOOPBACK_IDENTIFIERS.has(value));
    };

    const isSharedVhostService = (name: string, data: ServiceInfo) => {
        if (isCorePlatformService(data)) return false;
        const scope = (data.control_scope || '').trim().toLowerCase();
        if (scope === 'shared-vhost') return true;
        if (scope === 'service') return false;
        const id = (data.id || '').trim().toLowerCase();
        if (SHARED_VHOST_APP_IDS.has(id)) return true;
        const process = (data.process || '').trim().toLowerCase().replace(/\.service$/i, '');
        const normalizedName = name.trim().toLowerCase();
        if (SHARED_VHOST_APP_IDS.has(normalizedName)) return true;
        return process === 'apache2' && id !== 'apache2';
    };

    const isExemptComponent = (comp: ServiceComponentInfo) => {
        const unit = (comp.unit || '').trim().toLowerCase();
        const role = (comp.role || '').trim().toLowerCase();
        const status = (comp.status || '').trim().toLowerCase();
        if (role === 'required' || role === 'timer' || unit.endsWith('.timer')) return false;
        const optional = role === 'optional' || role === 'optional-mount' || (!role && (unit === 'rclone-vfs' || unit === 'rclone-vfs.service'));
        if (optional && comp.configured !== true) return true;
        const oneshot = role === 'oneshot' || role === 'scheduled-job' || (!role && (unit === 'recyclarr' || unit === 'recyclarr.service' || unit === 'scrutiny-collector' || unit === 'scrutiny-collector.service'));
        if (oneshot) return status === 'stopped' || status === 'inactive' || status === 'completed' || status === 'success';
        return false;
    };

    const isComponentHealthy = (comp: ServiceComponentInfo) => {
        if (isExemptComponent(comp)) return true;
        const status = (comp.status || '').trim().toLowerCase();
        return status === 'running' || status === 'active' || status === 'listening' || status === 'exited';
    };

    const getDegradedSummary = (data: ServiceInfo): { degraded: boolean; unhealthyUnits: string[] } => {
        const explicitDegraded = (data.status || '').trim().toLowerCase() === 'degraded';
        const components = Array.isArray(data.components) ? data.components : [];
        const requiredComponents = components.filter((c) => !isExemptComponent(c));
        const unhealthyUnits = requiredComponents
            .filter((c) => !isComponentHealthy(c))
            .map((c) => c.unit);
        const healthyCount = requiredComponents.length - unhealthyUnits.length;
        const hasFailedComponent = requiredComponents.some((component) => ['failed', 'error'].includes((component.status || '').toLowerCase()));
        const componentDegraded = requiredComponents.length > 0 && unhealthyUnits.length > 0 && (healthyCount > 0 || data.status === 'running' || explicitDegraded || hasFailedComponent);
        return {
            degraded: explicitDegraded || componentDegraded,
            unhealthyUnits,
        };
    };

    const resolveServiceLogUnits = (name: string, data: ServiceInfo): string[] => {
        const fromComponents = Array.isArray(data.components)
            ? data.components.map((c) => (c.unit || '').trim()).filter(Boolean)
            : [];
        const fromUnits = Array.isArray(data.units)
            ? data.units.map((u) => (u || '').trim()).filter(Boolean)
            : [];
        const merged = Array.from(new Set([...fromComponents, ...fromUnits]));
        if (merged.length > 0) return merged;
        return [data.process || name];
    };

    const isLocalBrowserHost = (hostname: string) => {
        const normalized = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '');
        return normalized === 'localhost' || normalized === '127.0.0.1' || normalized === '::1';
    };

    const resolveBrowserProtocol = () => {
        if (browserOrigin?.protocol) {
            return browserOrigin.protocol;
        }
        return typeof window !== 'undefined' ? window.location.protocol : 'http:';
    };

    const resolveBrowserHostname = () => {
        if (browserOrigin?.hostname !== undefined) {
            return browserOrigin.hostname;
        }
        return typeof window !== 'undefined' ? window.location.hostname || '' : '';
    };

    const resolveDirectAppProtocol = (data: ServiceInfo) => {
        const rawScheme = (data.web_scheme || '').trim().toLowerCase().replace(/:$/, '');
        if (rawScheme === 'https' || rawScheme === 'http') {
            return `${rawScheme}:`;
        }
        if (isCorePlatformService(data)) {
            const idOrProc = (data.id || data.process || '').trim().toLowerCase();
            if (idOrProc === 'apache2') {
                return 'https:';
            }
            return resolveBrowserProtocol();
        }
        return 'http:';
    };

    const isRemoteLoopbackRestricted = (name: string, data: ServiceInfo) => {
        if (!isLoopbackService(name, data)) {
            return false;
        }
        if (data.external_access_enabled && Boolean(data.public_domain?.trim())) {
            return false;
        }
        const hostname = resolveBrowserHostname();
        if (!hostname) {
            return false;
        }
        return !isLocalBrowserHost(hostname);
    };

    const buildRemoteLoopbackMessage = (name: string) =>
        `${name} binds strictly to 127.0.0.1. Enable External Access with a public domain in Ingress & Deployment to open its Web UI remotely.`;

    const handleOpenWebUI = (name: string, data: ServiceInfo) => {
        const pathSuffix = data.web_path ? (data.web_path.startsWith('/') ? data.web_path : `/${data.web_path}`) : '';
        const publicDomain = data.public_domain?.trim();
        if (data.external_access_enabled && publicDomain) {
            const proto = data.tls_enabled === false ? 'http:' : 'https:';
            window.open(`${proto}//${publicDomain}${pathSuffix}`, '_blank');
            return;
        }
        if (isRemoteLoopbackRestricted(name, data)) {
            addToast(
                buildRemoteLoopbackMessage(name),
                'info'
            );
            return;
        }
        const browserHostname = resolveBrowserHostname();
        const useLoopbackHost = isLoopbackService(name, data) && isLocalBrowserHost(browserHostname);
        const host = useLoopbackHost ? '127.0.0.1' : browserHostname;
        const protocol = resolveDirectAppProtocol(data);
        const effectivePort = data.active_port || data.default_port;
        if (effectivePort && effectivePort > 0) {
            window.open(`${protocol}//${host}:${effectivePort}${pathSuffix}`, '_blank');
            return;
        }
        const process = data.process || name;
        const portOrPath = (data.id ? SERVICE_WEB_PORTS[data.id] : undefined) ?? SERVICE_WEB_PORTS[process];
        if (portOrPath != null) {
            const url = typeof portOrPath === 'string'
                ? portOrPath.startsWith('/') ? `${resolveBrowserProtocol()}//${host}${portOrPath}` : portOrPath
                : `${protocol}//${host}:${portOrPath}`;
            window.open(url, '_blank');
        } else {
            addToast('No web UI configured for this service.', 'info');
        }
    };

    const handleOpenSettings = (name: string, data: ServiceInfo) => {
        if (isCorePlatformService(data)) {
            setActiveTab('settings');
        } else {
            handleOpenWebUI(name, data);
        }
    };

    const renderServiceCard = (name: string, rawData: unknown) => {
        const info = rawData as ServiceInfo;
        const data = serviceControl?.name === name ? { ...info, status: serviceControl.status } : info;
        const isCore = isCorePlatformService(data);
        const appId = data.id || '';
        const isUpdating =
            data.status === 'updating' ||
            isLifecycleStatus(data.job_status) ||
            isLifecycleStatus(data.status) ||
            (appId ? updatingServices.has(appId) : false);
        const { degraded: isDegraded, unhealthyUnits } = getDegradedSummary(data);
        const isRunning = (data.status === 'running' || isDegraded) && !isUpdating;
        const isError = data.status === 'error';
        const isBusy = serviceControl?.name === name || isUpdating || restarts.has(name);
        const controlDisabled = isBusy || !canControlServices;
        const sharedVhost = isSharedVhostService(name, data);
        const sharedVhostMessage = `${name} runs on the shared Apache web server. Per-app stop/restart is disabled to protect other sites and the gateway.`;
        const daemonControlDisabled = controlDisabled || sharedVhost;
        const webAvailable = hasWebUI(data);
        const remoteLoopbackBlocked = isRemoteLoopbackRestricted(name, data);
        const remoteLoopbackMessage = buildRemoteLoopbackMessage(name);
        const hasUpdate = Boolean(!isCore && data.update_available && !data.update_error);
        const updateError = !isCore && data.update_error ? data.update_error.trim() : '';
        const installedVer = data.installed_version || data.version || '-';
        const latestVer = data.latest_version;
        const isCheckingThis = checkingSingleService === name;
        const serviceLogUnits = resolveServiceLogUnits(name, data);

        return (
            <div key={name} className={`glass-card relative bg-slate-950/80 border rounded-2xl p-6 transition-all group cursor-default overflow-hidden ${hasUpdate || isDegraded ? 'border-amber-500/30 hover:border-amber-400/60' : 'border-white/10 hover:border-indigo-500/50'}`}>
                <div className={`absolute top-0 left-0 w-1 h-full ${isUpdating ? 'bg-amber-400 animate-pulse' : (isDegraded ? 'bg-amber-500' : (hasUpdate ? 'bg-amber-500/70' : (isRunning ? 'bg-emerald-500/50' : (isError ? 'bg-red-500/50' : 'bg-slate-500/50'))))} transition-colors z-20`}></div>

                {isUpdating && (
                    <div className="mb-4 min-w-0 max-w-full rounded-xl bg-slate-900/90 p-4 text-center">
                        <ProgressRing
                            progress={data.progress || 10}
                            status={isLifecycleStatus(data.job_status) ? data.job_status : 'updating'}
                            logLine={data.log_line || `Updating ${name}...`}
                            startedAt={data.started_at}
                        />
                    </div>
                )}

                {data.components && data.components.length > 1 && (
                    <ul aria-label="Service components" className="mb-4 min-w-0 max-w-full space-y-1 text-xs text-slate-400">
                        {data.components.map(component => <li key={component.unit} className="flex min-w-0 items-center justify-between gap-2"><span className="min-w-0 break-all">{component.unit}: {component.status || 'unknown'} ({component.role || 'required'}{component.configured === false ? ', unconfigured' : ''})</span><button disabled={!canControlServices} title={`View logs for ${component.unit}`} onClick={() => { setLogsModalUnits(serviceLogUnits); setLogsModalService(component.unit); }} className="shrink-0 rounded p-2 text-indigo-300 disabled:opacity-50"><Terminal size={14} /></button></li>)}
                    </ul>
                )}
                {data.last_job && data.last_job.status !== 'completed' && !isUpdating && (
                    <div role="status" className="mb-4 min-w-0 max-w-full break-words rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-xs text-red-300">
                        Last {data.last_job.action}: {data.last_job.status}. {data.last_job.message || 'Check application state and logs before retrying.'}
                    </div>
                )}
                <div className="flex justify-between items-start mb-6 relative z-10">
                    <div className="flex items-center gap-4">
                        <div className="h-12 w-12 bg-white/5 rounded-xl border border-white/10 flex items-center justify-center shadow-inner overflow-hidden group-hover:scale-105 transition-transform">
                            {isCore ? (
                                <Cpu size={24} className={isRunning ? 'text-emerald-400' : (isError ? 'text-red-400' : 'text-slate-500')} />
                            ) : data.id ? (
                                <div className="relative w-8 h-8 flex items-center justify-center">
                                    <img 
                                        src={`/img/${data.id.toLowerCase()}.png`} 
                                        alt={name}
                                        className="w-full h-full object-contain"
                                        onError={(e) => {
                                            e.currentTarget.style.display = 'none';
                                            e.currentTarget.parentElement?.querySelector('.fallback')?.classList.remove('hidden');
                                        }}
                                    />
                                    <Box size={24} className={`fallback hidden ${isRunning ? 'text-emerald-400' : (isError ? 'text-red-400' : 'text-slate-500')} absolute`} />
                                </div>
                            ) : (
                                <Box size={24} className={isRunning ? 'text-emerald-400' : (isError ? 'text-red-400' : 'text-slate-500')} />
                            )}
                        </div>
                        <div>
                            <div className="flex items-center gap-2 flex-wrap">
                                <h3 className="text-base font-bold text-slate-200 group-hover:text-white transition-colors">{name}</h3>
                                {hasUpdate && (
                                    <span className="inline-flex items-center gap-1 text-xs font-bold px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30">
                                        <ArrowUpCircle size={12} className="text-amber-400" />
                                        {latestVer ? `Update ${formatVersion(latestVer)}` : 'Update Available'}
                                    </span>
                                )}
                            </div>
                            <div className="flex items-center gap-2 mt-1 flex-wrap">
                                <span className="relative flex h-2 w-2">
                                    {isRunning && !isDegraded && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
                                    <span className={`relative inline-flex rounded-full h-2 w-2 ${isUpdating || isDegraded ? 'bg-amber-400' : (isRunning ? 'bg-emerald-500' : (isError ? 'bg-red-500' : 'bg-slate-500'))}`}></span>
                                </span>
                                <span className={`text-xs font-medium capitalize ${isDegraded ? 'text-amber-400' : 'text-slate-400'}`}>
                                    {isUpdating ? (data.job_status || 'updating') : (isDegraded ? 'degraded' : data.status)}
                                </span>
                                {isDegraded && unhealthyUnits.length > 0 && (
                                    <span
                                        className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 font-mono"
                                        title={`Unhealthy required components: ${unhealthyUnits.join(', ')}`}
                                    >
                                        {unhealthyUnits.join(', ')} down
                                    </span>
                                )}
                                {sharedVhost && (
                                    <span
                                        className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-slate-400 border border-white/10 uppercase tracking-wider"
                                        title={sharedVhostMessage}
                                    >
                                        shared vhost
                                    </span>
                                )}
                                {data.managed_by && (
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-slate-500 border border-white/5 uppercase tracking-wider">
                                        {data.managed_by}
                                    </span>
                                )}
                                {data.public_domain && (
                                    <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono truncate max-w-[160px]" title={data.public_domain}>
                                        {data.public_domain}
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>
                    <div className="flex items-center gap-1">
                                <button
                                    onClick={() => {
                                        setLogsModalUnits(serviceLogUnits);
                                        setLogsModalService(serviceLogUnits[0] || data.process || name);
                                    }}
                                    disabled={!canControlServices}
                                    title={canControlServices ? 'View live logs' : 'Admin access required'}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 bg-slate-800/80 hover:bg-indigo-500/20 hover:text-indigo-400 text-slate-400 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center"
                                >
                                    <Terminal size={16} />
                                </button>
                        {!isCore && webAvailable && (
                            <button 
                                onClick={() => setIngressModalApp(data.id || data.process || name)}
                                disabled={isBusy}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 text-slate-500 hover:text-indigo-400 hover:bg-white/5 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center"
                                title="Ingress & Deployment"
                            >
                                <Network size={18} />
                            </button>
                        )}
                        {(isCore || webAvailable) && (
                            <button 
                                onClick={() => handleOpenSettings(name, data)}
                                disabled={isBusy || (!isCore && remoteLoopbackBlocked)}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 text-slate-500 hover:text-slate-300 hover:bg-white/5 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center"
                                title={!isCore && remoteLoopbackBlocked ? remoteLoopbackMessage : 'Settings'}
                            >
                                <Settings size={18} />
                            </button>
                        )}
                    </div>
                </div>

                {(() => {
                    const { port: effectivePort, defaultPort, reassigned } = resolveServicePort(name, data);
                    const apiKey = user?.role === 'admin' ? data.api_key?.trim() || '' : '';
                    const isKeyRevealed = revealedKeys.has(name);
                    const isKeyCopied = copiedKeyService === name;

                    return (
                        <div className="mb-6 space-y-3">
                            <div className="grid grid-cols-3 gap-3">
                                <div className={`bg-slate-900/50 rounded-xl p-3 border ${hasUpdate ? 'border-amber-500/20 bg-amber-500/[0.03]' : 'border-white/[0.02]'}`}>
                                    <div className="flex items-center justify-between">
                                        <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Version</span>
                                        {!isCore && data.id && canControlServices && (
                                            <button
                                                onClick={() => handleCheckSingleUpdate(name, data)}
                                                disabled={isBusy || isCheckingThis}
                                                title="Check for updates"
                                                className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40"
                                            >
                                                <RefreshCw size={11} className={isCheckingThis ? 'animate-spin text-indigo-400' : ''} />
                                            </button>
                                        )}
                                    </div>
                                    <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                                        <span className="text-sm font-medium text-slate-300 truncate">{formatVersion(installedVer)}</span>
                                        {hasUpdate && latestVer && (
                                            data.update_url && /^https?:\/\//i.test(data.update_url) ? (
                                                <a
                                                    href={data.update_url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="inline-flex items-center gap-0.5 text-xs font-bold text-amber-400 hover:text-amber-300 transition-colors"
                                                    title="View release notes"
                                                >
                                                    → {formatVersion(latestVer)}
                                                    <ExternalLink size={10} />
                                                </a>
                                            ) : (
                                                <span className="text-xs font-bold text-amber-400">
                                                    → {formatVersion(latestVer)}
                                                </span>
                                            )
                                        )}
                                        {!hasUpdate && updateError && (
                                            <span
                                                className="inline-flex items-center gap-1 text-[10px] font-semibold text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded"
                                                title={`Update check failed: ${updateError}`}
                                            >
                                                <AlertCircle size={10} />
                                                Check failed
                                            </span>
                                        )}
                                    </div>
                                </div>
                                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.02]">
                                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Port</span>
                                    <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                                        {effectivePort != null ? (
                                            <>
                                                <span className="text-sm font-mono font-medium text-slate-200">:{effectivePort}</span>
                                                {reassigned && defaultPort && (
                                                    <span
                                                        className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono"
                                                        title={`Dynamically reassigned from default port ${defaultPort}`}
                                                    >
                                                        def :{defaultPort}
                                                    </span>
                                                )}
                                            </>
                                        ) : (
                                            <span className="text-xs font-medium text-slate-500">Headless</span>
                                        )}
                                    </div>
                                </div>
                                <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.02]">
                                    <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Uptime</span>
                                    <p className="text-sm font-medium text-slate-300 mt-0.5 truncate" title={data.uptime || '-'}>{data.uptime || '-'}</p>
                                </div>
                            </div>

                            {apiKey && (
                                <div className="bg-slate-900/50 rounded-xl px-3 py-2.5 border border-white/[0.04] flex items-center justify-between gap-2">
                                    <div className="flex items-center gap-2 min-w-0 flex-1">
                                        <Key size={13} className="text-indigo-400 shrink-0" />
                                        <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider shrink-0">API Key</span>
                                        <code
                                            className="text-xs font-mono text-slate-300 truncate select-all bg-slate-950/60 px-2 py-0.5 rounded border border-white/5"
                                            title={isKeyRevealed ? apiKey : 'Click eye icon to reveal API key'}
                                        >
                                            {isKeyRevealed ? apiKey : formatMaskedApiKey(apiKey)}
                                        </code>
                                    </div>
                                    <div className="flex items-center gap-1 shrink-0">
                                        <button
                                            type="button"
                                            onClick={() => toggleRevealKey(name)}
                                            title={isKeyRevealed ? 'Hide API key' : 'Reveal API key'}
                                            aria-label={isKeyRevealed ? `Hide ${name} API key` : `Reveal ${name} API key`}
                                            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-white/5 rounded-md transition-colors"
                                        >
                                            {isKeyRevealed ? <EyeOff size={13} /> : <Eye size={13} />}
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => handleCopyApiKey(name, apiKey)}
                                            title="Copy API key"
                                            aria-label={`Copy ${name} API key`}
                                            className="p-1.5 text-slate-400 hover:text-indigo-400 hover:bg-white/5 rounded-md transition-colors"
                                        >
                                            {isKeyCopied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    );
                })()}

                {hasUpdate && data.id && (
                    <RequireClaim>
                        <button
                            onClick={() => handleUpdateService(name, data)}
                            disabled={controlDisabled}
                            title={canControlServices ? `Update ${name}${latestVer ? ` to ${formatVersion(latestVer)}` : ''}` : 'Admin access required'}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive w-full mb-2.5 py-2.5 bg-amber-500/15 hover:bg-amber-500 text-amber-300 hover:text-slate-950 text-xs font-bold rounded-lg transition-all flex items-center justify-center gap-2 border border-amber-500/30 shadow-lg shadow-amber-950/20 disabled:opacity-50"
                        >
                            <ArrowUpCircle size={15} />
                            {isUpdating ? 'Updating...' : `Update ${name}${latestVer ? ` to ${formatVersion(latestVer)}` : ''}`}
                        </button>
                    </RequireClaim>
                )}

                <div className="flex gap-2">
                    {isRunning || isUpdating ? (
                        <>
                            {webAvailable && (
                                <button
                                    onClick={() => handleOpenWebUI(name, data)}
                                    title={remoteLoopbackBlocked ? remoteLoopbackMessage : `Open ${name} Web UI`}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive flex-1 py-2.5 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                                    disabled={isBusy || remoteLoopbackBlocked}
                                >
                                    <Globe size={14} /> Web UI
                                </button>
                            )}
                            <RequireClaim>

                                <button
                                    onClick={() => handleServiceControl(name, data, 'restart')}
                                    disabled={daemonControlDisabled}
                                    title={!canControlServices ? 'Admin access required' : (sharedVhost ? sharedVhostMessage : 'Restart service')}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 bg-slate-800/80 hover:bg-amber-500/20 hover:text-amber-400 text-slate-400 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center"
                                >
                                    <RotateCcw size={16} className={isBusy ? 'animate-spin' : ''} />
                                </button>
                                <button
                                    onClick={() => handleServiceControl(name, data, 'stop')}
                                    disabled={daemonControlDisabled}
                                    title={!canControlServices ? 'Admin access required' : (sharedVhost ? sharedVhostMessage : 'Stop service')}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 bg-slate-800/80 hover:bg-red-500/20 hover:text-red-400 text-slate-400 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center"
                                >
                                    <Square size={16} className="fill-current" />
                                </button>
                            </RequireClaim>
                        </>
                    ) : (
                        <RequireClaim>
                            <button
                                onClick={() => handleServiceControl(name, data, 'start')}
                                disabled={daemonControlDisabled}
                                title={!canControlServices ? 'Admin access required' : (sharedVhost ? sharedVhostMessage : 'Start service')}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive w-full py-2.5 bg-indigo-500/20 hover:bg-indigo-500 text-indigo-300 hover:text-white text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 border border-indigo-500/30 disabled:opacity-50"
                            >
                                <Play size={14} className="fill-current" /> {isBusy ? 'Starting...' : 'Start Service'}
                            </button>
                        </RequireClaim>
                    )}
                </div>
            </div>
        );
    };

    if (isLoading) {
        return <ServicesSkeleton />;
    }

    return (
        <div className="space-y-8 animate-fade-in relative z-10 w-full min-h-screen">
            <div className="absolute inset-0 bg-blue-500/5 rounded-full blur-[120px] pointer-events-none -translate-y-1/2 -translate-x-1/2"></div>
            {/* Header */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end gap-4">
                <div>
                    <h2 className="text-2xl font-bold text-slate-100 flex flex-wrap items-center gap-3">
                        App Ecosystem
                        <span className="text-xs font-semibold px-2.5 py-1 bg-white/10 rounded-full text-slate-300 border border-white/5">{allEntries.length} Total</span>
                        <span className="text-xs font-semibold px-2.5 py-1 bg-emerald-500/10 rounded-full text-emerald-400 border border-emerald-500/20">{runningCount} Running</span>
                        {updatesAvailableCount > 0 && (
                            <span className="text-xs font-semibold px-2.5 py-1 bg-amber-500/15 rounded-full text-amber-300 border border-amber-500/30 flex items-center gap-1.5">
                                <ArrowUpCircle size={13} className="text-amber-400" />
                                {updatesAvailableCount} {updatesAvailableCount === 1 ? 'Update' : 'Updates'} Available
                            </span>
                        )}
                    </h2>
                    <p className="text-slate-400 text-sm mt-2">Manage, monitor, and update services within the nexus.</p>
                </div>
                <div className="flex gap-3">
                    <button
                        onClick={handleCheckAllUpdates}
                        disabled={checkingUpdates}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive px-4 py-2 bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 rounded-lg text-sm font-medium text-slate-300 transition-all flex items-center gap-2 disabled:opacity-50"
                    >
                        <RefreshCw size={14} className={checkingUpdates ? 'animate-spin text-indigo-400' : ''} />
                        {checkingUpdates ? 'Checking Updates...' : 'Check Updates & Sync'}
                    </button>
                </div>
            </div>

            {/* Core Platform */}
            {coreServices.length > 0 && (
                <div>
                    <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <Server size={14} className="text-indigo-400" /> Core Platform
                    </h3>
                    <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-5">
                        {coreServices.map(([name, data]) => renderServiceCard(name, data))}
                    </div>
                </div>
            )}

            {/* Installed Apps */}
            {appServices.length > 0 && (
                <div>
                    <h3 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                        <Box size={14} className="text-emerald-400" /> Installed Applications
                    </h3>
                    <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-5">
                        {appServices.map(([name, data]) => renderServiceCard(name, data))}
                    </div>
                </div>
            )}

            {allEntries.length === 0 && (
                <div className="text-center py-20">
                    <Box size={48} className="mx-auto text-slate-600 mb-4" />
                    <h3 className="text-lg font-semibold text-slate-300 mb-2">No Services Detected</h3>
                    <p className="text-slate-500 text-sm">Install applications from the Marketplace to see them here.</p>
                </div>
            )}

            <ServiceLogsModal 
                serviceName={logsModalService} 
                units={logsModalUnits}
                onClose={() => {
                    setLogsModalService(null);
                    setLogsModalUnits(undefined);
                }}
            />

            {ingressModalApp && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
                    <div className="glass-panel w-full max-w-xl max-h-[85vh] overflow-y-auto rounded-3xl p-6 border border-white/10 relative shadow-2xl">
                        <div className="flex items-center justify-between pb-4 border-b border-white/10">
                            <div className="flex items-center gap-2">
                                <Network className="text-indigo-400" size={20} />
                                <h3 className="text-lg font-bold text-white capitalize">{ingressModalApp} Ingress & Deploy</h3>
                            </div>
                            <button
                                onClick={() => setIngressModalApp(null)}
                                className="obs-touch-target-standard p-2 text-slate-400 hover:text-white rounded-lg hover:bg-white/5 transition-colors flex items-center justify-center"
                            >
                                <X size={18} />
                            </button>
                        </div>
                        <div className="space-y-4">
                            <ExternalAccessCard appName={ingressModalApp} />
                            <DeploymentStatus appName={ingressModalApp} isTriggered={true} />
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
