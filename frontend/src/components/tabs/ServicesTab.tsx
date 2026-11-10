'use client';

import { RefreshCw, Box, Settings, Globe, RotateCcw, Square, Play, Server, Cpu, X, Network, ArrowUpCircle, ExternalLink, Key, Eye, EyeOff, Copy, Check, AlertCircle, AlertTriangle, LayoutList, LayoutGrid, Search, Sliders, ChevronDown, ChevronUp } from 'lucide-react';
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
import StreamingDialog from '@/components/streaming/StreamingDialog';
import { Terminal } from 'lucide-react';
import { useSystemStore } from '@/store/useSystemStore';
import { ExternalAccessCard } from '@/components/ingress/ExternalAccessCard';
import { DeploymentStatus } from '@/components/deploy/DeploymentStatus';
import { ProgressRing } from '@/components/ui/ProgressRing';
import { Modal } from '@/components/ui/Modal';
import { ViewportMenu } from '@/components/ui/ViewportMenu';
import { isLifecycleStatus, lifecycleIdentity, matchingActiveJob, matchingJobOutcome, MarketplaceJobOutcome, PendingAction, LIFECYCLE_RECEIPT_TIMEOUT_MS } from '@/hooks/useMarketplace';

const SERVICE_ROW_TRACKS = '@[720px]:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_minmax(0,0.9fr)_minmax(0,2fr)]';
const SERVICE_CARD_GRID = 'min-w-0 rounded-none shadow-none bg-transparent border-y border-white/[0.07] grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 divide-y divide-white/[0.07] md:divide-y-0 md:[&>*]:border-t md:[&>*]:border-white/[0.07] md:[&>*:nth-child(-n+2)]:border-t-0 md:max-xl:[&>*:nth-child(even)]:border-l xl:[&>*:nth-child(-n+3)]:border-t-0 xl:[&>*:not(:nth-child(3n+1))]:border-l';

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
};

const SERVICE_DISPLAY_NAMES: Record<string, string> = {
    'calibreweb': 'Calibre-Web',
    'qbittorrent': 'qBittorrent',
    'jellyfin': 'Jellyfin',
    'jellyseerr': 'Jellyseerr',
    'overseerr': 'Overseerr',
    'ombi': 'Ombi',
    'sonarr': 'Sonarr',
    'radarr': 'Radarr',
    'prowlarr': 'Prowlarr',
    'bazarr': 'Bazarr',
    'lidarr': 'Lidarr',
    'readarr': 'Readarr',
    'deluged': 'Deluge',
    'deluge': 'Deluge',
    'transmission-daemon': 'Transmission',
    'transmission': 'Transmission',
    'nextcloud': 'Nextcloud',
    'home-assistant@homeassistant': 'Home Assistant',
    'homeassistant': 'Home Assistant',
    'vaultwarden': 'Vaultwarden',
    'wireguard': 'WireGuard',
    'tailscale': 'Tailscale',
    'paperless-ngx': 'Paperless-ngx',
    'paperless-webserver': 'Paperless-ngx',
    'plexmediaserver': 'Plex Media Server',
    'emby-server': 'Emby',
    'sabnzbd': 'SABnzbd',
    'nzbget': 'NZBGet',
    'tautulli': 'Tautulli',
    'af-maintainerr': 'Maintainerr',
    'maintainerr': 'Maintainerr',
    'jackett': 'Jackett',
    'flaresolverr': 'FlareSolverr',
    'navidrome': 'Navidrome',
    'threadfin': 'Threadfin',
    'flood': 'Flood',
    'autobrr': 'Autobrr',
    'qui': 'Qui',
    'syncthing': 'Syncthing',
    'filebrowser': 'FileBrowser',
    'pihole-ftl': 'Pi-hole',
    'grafana-server': 'Grafana',
    'prometheus': 'Prometheus',
    'netdata': 'Netdata',
    'uptime-kuma': 'Uptime Kuma',
    'adguardhome': 'AdGuard Home',
    'rutorrent': 'ruTorrent',
    'rclone': 'Rclone',
    'autoscan': 'Autoscan',
    'audiobookshelf': 'Audiobookshelf',
    'kavita': 'Kavita',
    'librespeed': 'LibreSpeed',
    'thelounge': 'The Lounge',
    'znc': 'ZNC',
    'scrutiny': 'Scrutiny',
    'n8n': 'n8n',
    'gitea': 'Gitea',
    'organizr': 'Organizr',
    'dispatcharr': 'Dispatcharr',
    'duplicati': 'Duplicati',
    'filebot': 'FileBot',
    'listenarr': 'Listenarr',
    'notifiarr': 'Notifiarr',
    'novnc': 'noVNC',
    'pyload': 'pyLoad',
    'requestrr': 'Requestrr',
    'seedcross': 'SeedCross',
    'unmanic': 'Unmanic',
    'palate': 'Palate',
    'af-palate': 'Palate',
    'kasmvnc': 'KasmVNC',
    'af-kasmvnc': 'KasmVNC',
    'mcvnc': 'McVNC',
    'af-mcvnc': 'McVNC',
    'apache2': 'Apache Gateway',
    'aetherflow-frontend': 'AetherFlow Frontend',
    'aetherflow-api': 'AetherFlow API',
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

    const pickString = (...candidateValues: unknown[]): string => {
        for (const candidate of candidateValues) {
            if (typeof candidate === 'string' && candidate.trim()) {
                return candidate.trim();
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
    const ingressReturnFocusRef = useRef<HTMLElement | null>(null);
    const [servicesPollError, setServicesPollError] = useState<unknown>(undefined);
    const [revealedKeys, setRevealedKeys] = useState<Set<string>>(new Set());
    const [stopConfirmService, setStopConfirmService] = useState<{ name: string; data: ServiceInfo } | null>(null);
    const [restartConfirmService, setRestartConfirmService] = useState<{ name: string; data: ServiceInfo } | null>(null);
    const [guardedStartConfirmService, setGuardedStartConfirmService] = useState<{ name: string; data: ServiceInfo } | null>(null);
    const stopDialogReturnFocusRef = useRef<HTMLElement | null>(null);
    const stopDialogCancelRef = useRef<HTMLButtonElement | null>(null);
    const restartDialogReturnFocusRef = useRef<HTMLElement | null>(null);
    const restartDialogCancelRef = useRef<HTMLButtonElement | null>(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [statusFilter, setStatusFilter] = useState<'all' | 'running' | 'stopped' | 'attention' | 'updates'>('all');
    const [isMobileFiltersOpen, setIsMobileFiltersOpen] = useState(false);
    const [viewMode, setViewMode] = useState<'list' | 'card'>('list');
    const [openManageMenuService, setOpenManageMenuService] = useState<string | null>(null);
    const [openAccessMenuService, setOpenAccessMenuService] = useState<string | null>(null);
    const [expandedDetailsServices, setExpandedDetailsServices] = useState<Set<string>>(new Set());
    const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    useEffect(() => {
        if (!openManageMenuService) return;
        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                setOpenManageMenuService(null);
            }
        };
        const handleClickOutside = (event: MouseEvent) => {
            const target = event.target as HTMLElement | null;
            if (!target?.closest(`[data-manage-menu="${openManageMenuService}"]`)) {
                setOpenManageMenuService(null);
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        window.addEventListener('mousedown', handleClickOutside);
        return () => {
            window.removeEventListener('keydown', handleKeyDown);
            window.removeEventListener('mousedown', handleClickOutside);
        };
    }, [openManageMenuService]);

    useEffect(() => {
        if (!openAccessMenuService) return;
        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                setOpenAccessMenuService(null);
            }
        };
        const handleClickOutside = (event: MouseEvent) => {
            const target = event.target as HTMLElement | null;
            if (!target?.closest(`[data-access-menu="${openAccessMenuService}"]`)) {
                setOpenAccessMenuService(null);
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        window.addEventListener('mousedown', handleClickOutside);
        return () => {
            window.removeEventListener('keydown', handleKeyDown);
            window.removeEventListener('mousedown', handleClickOutside);
        };
    }, [openAccessMenuService]);

    useEffect(() => () => {
        if (copyTimerRef.current) {
            clearTimeout(copyTimerRef.current);
        }
    }, []);

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
            if (updateDeadlinesRef.current.size) {
                timer = setTimeout(checkDeadlines, Math.max(0, Math.min(...updateDeadlinesRef.current.values()) - Date.now()));
            }
        };
        const checkDeadlines = () => {
            const expired: string[] = [];
            updateDeadlinesRef.current.forEach((deadline, appId) => {
                if (deadline > Date.now()) return;
                expired.push(appId);
                updateDeadlinesRef.current.delete(appId);
                addToast(`${appId}: update outcome could not be confirmed; its receipt may have been superseded. Check service state and logs before retrying.`, 'error');
            });
            if (expired.length) {
                setUpdatingServices(current => new Set([...current].filter(appId => !expired.includes(appId))));
            }
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

    const { data: services, error: servicesError, mutate, isValidating } = useSWR<Record<string, ServiceInfo>>(
        '/api/v1/auth/services',
        {
            refreshInterval: (currentData) => {
                if (updatingServices.size > 0) return 1500;
                if (!currentData) return 15000;
                const hasActiveJob = Object.values(currentData).some(
                    (item) => item.status === 'updating' || item.job_status === 'updating' || item.job_status === 'installing' || item.job_status === 'uninstalling'
                );
                return hasActiveJob ? 1500 : 15000;
            },
            onSuccess: (snapshot) => {
                setServicesPollError(undefined);
                renewActiveUpdates(snapshot);
            },
            onError: (error) => setServicesPollError(error),
            shouldRetryOnError: false,
        }
    );

    const inventoryError = servicesError || servicesPollError;
    useLifecyclePollRecovery('/api/v1/auth/services', inventoryError, () => mutate());

    useEffect(() => {
        if (!inventoryError && !isValidating) renewActiveUpdates(services);
    }, [services, inventoryError, isValidating, renewActiveUpdates]);

    useEffect(() => {
        if (!services) return;
        Object.entries(services).forEach(([name, info]) => {
            const appId = info.id || name;
            const activeAction = isLifecycleStatus(info.job_status) ? info.job_status : isLifecycleStatus(info.status) ? info.status : undefined;
            const activeIdentity = lifecycleIdentity(info);
            if (activeAction && activeIdentity && (!updatingServices.has(appId) || activeIdentity === expectedJobsRef.current.get(appId))) {
                observedJobsRef.current.set(appId, { action: activeAction, identity: activeIdentity });
            }
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
                const response = await apiFetch('/api/v1/admin/packages/updates/check', { method: 'POST' });
                if (!response.ok) throw new Error('Application update inventory unavailable');
                if (response.ok) {
                    const payload = await response.json().catch(() => null);
                    await mutate();
                    globalMutate('/api/v1/public/marketplace');
                    const records = Array.isArray(payload?.updates)
                        ? (payload.updates as unknown[]).map((item) => normalizeUpdateRecord(item))
                        : [];
                    const failedRecords = records.filter((record) => Boolean(record.error));
                    const availableCount =
                        typeof payload?.updates_available === 'number'
                            ? payload.updates_available
                            : records.filter((record) => record.updateAvailable).length;
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
            const response = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(data.id)}/check-update`, {
                method: 'POST',
            });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || errorData.error || 'Update check failed.');
            }
            const result = await response.json().catch(() => ({}));
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
        } catch (error: unknown) {
            addToast(error instanceof Error ? error.message : 'Unable to check for updates.', 'error');
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
            const response = await apiFetch(`/api/v1/admin/packages/${encodeURIComponent(appId)}/update`, {
                method: 'POST',
            });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || errorData.error || 'Package update request rejected.');
            }
            const receipt = await response.json() as { job_id?: string; started_at?: string };
            const identity = lifecycleIdentity(receipt);
            if (!identity) throw new Error('The server did not return a job identity. Refresh status and check logs before retrying.');
            if (!updateDeadlinesRef.current.has(appId)) throw new Error('Acceptance arrived after status tracking expired. Check service state and logs before retrying.');
            expectedJobsRef.current.set(appId, identity);
            setUpdatingServices(curr => new Set(curr).add(appId));
            const targetVer = data.latest_version ? ` to v${data.latest_version.replace(/^v/i, '')}` : '';
            addToast(`Updating ${name}${targetVer}...`, 'info');
            mutate();
            globalMutate('/api/v1/public/marketplace');
        } catch (error: unknown) {
            expectedJobsRef.current.delete(appId);
            updateDeadlinesRef.current.delete(appId);
            observedJobsRef.current.delete(appId);
            setUpdatingServices((curr) => {
                const next = new Set(curr);
                next.delete(appId);
                return next;
            });
            mutate();
            addToast(error instanceof Error ? error.message : 'Update failed to start.', 'error');
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

        const optimisticStatus = action === 'stop' ? 'stopping' : action === 'start' ? 'starting' : 'restarting';
        setServiceControl({ name, status: optimisticStatus });

        const canonicalTarget = (data.id || data.process || name).trim();
        const processTarget = (data.id || data.process || name).trim();
        try {
            const response = await apiFetch(`/api/v1/admin/services/${encodeURIComponent(canonicalTarget)}/control`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action,
                    managed_by: data.managed_by || 'systemd',
                    process: processTarget,
                })
            });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || errorData.error || 'Daemon control operation rejected.');
            }
            const receipt = await response.json().catch(() => ({}));
            if (receipt.status === 'accepted') trackRestart(name, receipt);
            else addToast(`Successfully executed '${action}' on ${name}.`, 'success');
            void mutate();
        } catch (error: unknown) {
            void mutate();
            addToast(error instanceof Error ? error.message : 'Undefined system exception encountered.', 'error');
        } finally {
            setServiceControl(null);
        }
    };

    const allEntries = Object.entries(services || {});

    const corePlatformProcesses = ['aetherflow-api', 'aetherflow-frontend', 'apache2', 'nginx'];
    const isCorePlatformService = (info: ServiceInfo) =>
        corePlatformProcesses.includes(info.id || info.process || '');

    const hasWebUI = (info: ServiceInfo) => {
        const identifier = (info.id || info.process || '').trim().toLowerCase();
        if (identifier === 'aetherflow-api') {
            return false;
        }
        if (typeof info.default_port === 'number') {
            return info.default_port > 0;
        }
        return (
            (info.id ? SERVICE_WEB_PORTS[info.id] != null : false) ||
            (info.process ? SERVICE_WEB_PORTS[info.process] != null : false)
        );
    };

    const appServices = allEntries.filter(([, serviceData]) => !isCorePlatformService(serviceData as ServiceInfo));

    const isExemptComponent = (component: ServiceComponentInfo) => {
        const unit = (component.unit || '').trim().toLowerCase();
        const role = (component.role || '').trim().toLowerCase();
        const status = (component.status || '').trim().toLowerCase();
        if (role === 'required' || role === 'timer' || unit.endsWith('.timer')) return false;
        const optional = role === 'optional' || role === 'optional-mount' || (!role && (unit === 'rclone-vfs' || unit === 'rclone-vfs.service'));
        if (optional && component.configured !== true) return true;
        const oneshot = role === 'oneshot' || role === 'scheduled-job' || (!role && (unit === 'recyclarr' || unit === 'recyclarr.service' || unit === 'scrutiny-collector' || unit === 'scrutiny-collector.service'));
        if (oneshot) return status === 'stopped' || status === 'inactive' || status === 'completed' || status === 'success';
        return false;
    };

    const isComponentHealthy = (component: ServiceComponentInfo) => {
        if (isExemptComponent(component)) return true;
        const status = (component.status || '').trim().toLowerCase();
        return status === 'running' || status === 'active' || status === 'listening' || status === 'exited';
    };

    const getDegradedSummary = (serviceData: ServiceInfo): { degraded: boolean; unhealthyUnits: string[] } => {
        const explicitDegraded = (serviceData.status || '').trim().toLowerCase() === 'degraded';
        const components = Array.isArray(serviceData.components) ? serviceData.components : [];
        const requiredComponents = components.filter((component) => !isExemptComponent(component));
        const unhealthyUnits = requiredComponents
            .filter((component) => !isComponentHealthy(component))
            .map((component) => component.unit);
        const healthyCount = requiredComponents.length - unhealthyUnits.length;
        const hasFailedComponent = requiredComponents.some((component) => ['failed', 'error'].includes((component.status || '').toLowerCase()));
        const componentDegraded = requiredComponents.length > 0 && unhealthyUnits.length > 0 && (healthyCount > 0 || serviceData.status === 'running' || explicitDegraded || hasFailedComponent);
        return {
            degraded: explicitDegraded || componentDegraded,
            unhealthyUnits,
        };
    };

    const isFailedInstall = (serviceData: ServiceInfo): boolean => {
        const lastJob = serviceData.last_job;
        const isJobFailed = Boolean(
            lastJob &&
            lastJob.action === 'install' &&
            lastJob.status === 'failed'
        );
        const isStatusFailed = serviceData.status === 'install_failed' || serviceData.job_status === 'install_failed';
        return isJobFailed || isStatusFailed;
    };

    const hasAttentionNeed = (serviceData: ServiceInfo): boolean => {
        if (isFailedInstall(serviceData)) return true;
        if (serviceData.status === 'error' || serviceData.status === 'failed') return true;
        if (getDegradedSummary(serviceData).degraded) return true;
        if (serviceData.last_job && serviceData.last_job.status !== 'completed') return true;
        if (serviceData.update_error && serviceData.update_error.trim().length > 0) return true;
        return false;
    };

    const hasAvailableUpdate = (serviceData: ServiceInfo): boolean => {
        return Boolean(serviceData.update_available && !serviceData.update_error);
    };

    const openStopConfirmation = (name: string, serviceData: ServiceInfo) => {
        stopDialogReturnFocusRef.current = document.getElementById(`manage-trigger-${serviceData.id || name}`);
        setOpenManageMenuService(null);
        setStopConfirmService({ name, data: serviceData });
    };

    const restartService = (name: string, serviceData: ServiceInfo, trigger: HTMLElement) => {
        if (!isFailedInstall(serviceData)) {
            void handleServiceControl(name, serviceData, 'restart');
            return;
        }
        restartDialogReturnFocusRef.current = document.getElementById(`manage-trigger-${serviceData.id || name}`) || trigger;
        setOpenManageMenuService(null);
        setRestartConfirmService({ name, data: serviceData });
    };

    const runningCount = allEntries.filter(([, serviceData]) => (serviceData as ServiceInfo).status === 'running').length;
    const stoppedCount = allEntries.filter(([, serviceData]) => {
        const info = serviceData as ServiceInfo;
        const isStoppedStatus = info.status === 'stopped' || info.status === 'inactive' || !info.status;
        return isStoppedStatus;
    }).length;
    const attentionCount = allEntries.filter(([, serviceData]) => hasAttentionNeed(serviceData as ServiceInfo)).length;
    const updatesAvailableCount = appServices.filter(([, serviceData]) => hasAvailableUpdate(serviceData as ServiceInfo)).length;
    const attentionEntries = allEntries.filter(([, serviceData]) => hasAttentionNeed(serviceData as ServiceInfo));
    const primaryAttentionService = attentionEntries.length > 0 ? attentionEntries[0] : null;

    const activeFilterLabel =
        statusFilter === 'running'
            ? 'Running'
            : statusFilter === 'stopped'
                ? 'Stopped'
                : statusFilter === 'attention'
                    ? 'Needs Attention'
                    : statusFilter === 'updates'
                        ? 'Updates'
                        : 'All';
    const activeFilterCount =
        statusFilter === 'running'
            ? runningCount
            : statusFilter === 'stopped'
                ? stoppedCount
                : statusFilter === 'attention'
                    ? attentionCount
                    : statusFilter === 'updates'
                        ? updatesAvailableCount
                        : allEntries.length;

    const formatVersion = (ver?: string) => {
        if (!ver || ver === '-') return '-';
        return ver.startsWith('v') || ver.startsWith('V') ? ver : `v${ver}`;
    };

    const getHumanDisplayName = (name: string, data: ServiceInfo): string => {
        const candidateKeys = [name, data.id, data.process]
            .filter((value): value is string => Boolean(value))
            .map((value) => value.trim().toLowerCase());
        for (const candidateKey of candidateKeys) {
            if (SERVICE_DISPLAY_NAMES[candidateKey]) {
                return SERVICE_DISPLAY_NAMES[candidateKey];
            }
        }
        return name;
    };

    const resolveServicePort = (name: string, serviceData: ServiceInfo): { port: number | null; defaultPort: number | null; reassigned: boolean } => {
        const activePort = typeof serviceData.active_port === 'number' && serviceData.active_port > 0 ? serviceData.active_port : null;
        const defaultPort = typeof serviceData.default_port === 'number' && serviceData.default_port > 0 ? serviceData.default_port : null;
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
        const process = serviceData.process || name;
        const fallback = (serviceData.id ? SERVICE_WEB_PORTS[serviceData.id] : undefined) ?? SERVICE_WEB_PORTS[process];
        if (typeof fallback === 'number' && fallback > 0) {
            return { port: fallback, defaultPort: fallback, reassigned: false };
        }
        return { port: null, defaultPort: null, reassigned: false };
    };

    const toggleRevealKey = (serviceKey: string) => {
        setRevealedKeys((previousState) => {
            const nextState = new Set(previousState);
            if (nextState.has(serviceKey)) {
                nextState.delete(serviceKey);
            } else {
                nextState.add(serviceKey);
            }
            return nextState;
        });
    };

    const handleCopyApiKey = async (name: string, apiKey: string) => {
        try {
            await navigator.clipboard.writeText(apiKey);
            setCopiedKeyService(name);
            addToast(`Copied ${name} API key to clipboard.`, 'success');
            if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
            copyTimerRef.current = setTimeout(() => {
                setCopiedKeyService((current) => (current === name ? null : current));
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

    const isLoopbackService = (name: string, serviceData: ServiceInfo) => {
        const scope = (serviceData.bind_scope || '').trim().toLowerCase();
        if (scope === 'loopback') return true;
        if (scope === 'network') return false;
        const identifiers = [serviceData.id, serviceData.process, name]
            .filter((value): value is string => Boolean(value))
            .map((value) => value.trim().toLowerCase());
        return identifiers.some((value) => LOOPBACK_IDENTIFIERS.has(value));
    };

    const isSharedVhostService = (name: string, serviceData: ServiceInfo) => {
        if (isCorePlatformService(serviceData)) return false;
        const scope = (serviceData.control_scope || '').trim().toLowerCase();
        if (scope === 'shared-vhost') return true;
        if (scope === 'service') return false;
        const identifier = (serviceData.id || '').trim().toLowerCase();
        if (SHARED_VHOST_APP_IDS.has(identifier)) return true;
        const process = (serviceData.process || '').trim().toLowerCase().replace(/\.service$/i, '');
        const normalizedName = name.trim().toLowerCase();
        if (SHARED_VHOST_APP_IDS.has(normalizedName)) return true;
        return process === 'apache2' && identifier !== 'apache2';
    };

    const resolveServiceLogUnits = (name: string, serviceData: ServiceInfo): string[] => {
        const fromComponents = Array.isArray(serviceData.components)
            ? serviceData.components.map((component) => (component.unit || '').trim()).filter(Boolean)
            : [];
        const fromUnits = Array.isArray(serviceData.units)
            ? serviceData.units.map((unit) => (unit || '').trim()).filter(Boolean)
            : [];
        const merged = Array.from(new Set([...fromComponents, ...fromUnits]));
        if (merged.length > 0) return merged;
        return [serviceData.process || name];
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

    const resolveDirectAppProtocol = (serviceData: ServiceInfo) => {
        const rawScheme = (serviceData.web_scheme || '').trim().toLowerCase().replace(/:$/, '');
        if (rawScheme === 'https' || rawScheme === 'http') {
            return `${rawScheme}:`;
        }
        if (isCorePlatformService(serviceData)) {
            const idOrProc = (serviceData.id || serviceData.process || '').trim().toLowerCase();
            if (idOrProc === 'apache2') {
                return 'https:';
            }
            return resolveBrowserProtocol();
        }
        return 'http:';
    };

    const isRemoteLoopbackRestricted = (name: string, serviceData: ServiceInfo) => {
        if (!isLoopbackService(name, serviceData)) {
            return false;
        }
        if (serviceData.external_access_enabled && Boolean(serviceData.public_domain?.trim())) {
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

    const handleOpenWebUI = (name: string, serviceData: ServiceInfo) => {
        const pathSuffix = serviceData.web_path ? (serviceData.web_path.startsWith('/') ? serviceData.web_path : `/${serviceData.web_path}`) : '';
        const publicDomain = serviceData.public_domain?.trim();
        if (serviceData.external_access_enabled && publicDomain) {
            const proto = serviceData.tls_enabled === false ? 'http:' : 'https:';
            window.open(`${proto}//${publicDomain}${pathSuffix}`, '_blank');
            return;
        }
        if (isRemoteLoopbackRestricted(name, serviceData)) {
            addToast(
                buildRemoteLoopbackMessage(name),
                'info'
            );
            return;
        }
        const browserHostname = resolveBrowserHostname();
        const useLoopbackHost = isLoopbackService(name, serviceData) && isLocalBrowserHost(browserHostname);
        const host = useLoopbackHost ? '127.0.0.1' : browserHostname;
        const protocol = resolveDirectAppProtocol(serviceData);
        const effectivePort = serviceData.active_port || serviceData.default_port;
        if (effectivePort && effectivePort > 0) {
            window.open(`${protocol}//${host}:${effectivePort}${pathSuffix}`, '_blank');
            return;
        }
        const process = serviceData.process || name;
        const portOrPath = (serviceData.id ? SERVICE_WEB_PORTS[serviceData.id] : undefined) ?? SERVICE_WEB_PORTS[process];
        if (portOrPath != null) {
            const url = typeof portOrPath === 'string'
                ? portOrPath.startsWith('/') ? `${resolveBrowserProtocol()}//${host}${portOrPath}` : portOrPath
                : `${protocol}//${host}:${portOrPath}`;
            window.open(url, '_blank');
        } else {
            addToast('No web UI configured for this service.', 'info');
        }
    };

    const handleOpenSettings = (name: string, serviceData: ServiceInfo) => {
        if (isCorePlatformService(serviceData)) {
            setActiveTab('settings');
        } else {
            handleOpenWebUI(name, serviceData);
        }
    };

    const resolveUptimeDisplay = (serviceData: ServiceInfo): string => {
        if (isFailedInstall(serviceData) && !['running', 'degraded'].includes(serviceData.status)) {
            return 'Not running';
        }
        if (!serviceData.uptime || serviceData.uptime === 'stopped' || serviceData.uptime === '-') {
            return serviceData.status === 'running' ? '-' : 'Not running';
        }
        return serviceData.uptime;
    };

    const filteredEntries = allEntries.filter(([name, rawData]) => {
        const serviceData = rawData as ServiceInfo;
        const displayName = getHumanDisplayName(name, serviceData);
        if (searchQuery.trim().length > 0) {
            const query = searchQuery.trim().toLowerCase();
            const matchesName = name.toLowerCase().includes(query);
            const matchesDisplay = displayName.toLowerCase().includes(query);
            const matchesId = Boolean(serviceData.id && serviceData.id.toLowerCase().includes(query));
            const matchesProcess = Boolean(serviceData.process && serviceData.process.toLowerCase().includes(query));
            const matchesPublicDomain = Boolean(serviceData.public_domain && serviceData.public_domain.toLowerCase().includes(query));
            const matchesInternalDomain = Boolean(serviceData.internal_domain && serviceData.internal_domain.toLowerCase().includes(query));
            const { port: effectivePort } = resolveServicePort(name, serviceData);
            const matchesPort = effectivePort != null && String(effectivePort).includes(query);
            if (!matchesName && !matchesDisplay && !matchesId && !matchesProcess && !matchesPublicDomain && !matchesInternalDomain && !matchesPort) {
                return false;
            }
        }

        if (statusFilter === 'running') {
            return serviceData.status === 'running';
        }
        if (statusFilter === 'stopped') {
            const isStopped = serviceData.status === 'stopped' || serviceData.status === 'inactive' || !serviceData.status;
            return isStopped;
        }
        if (statusFilter === 'attention') {
            return hasAttentionNeed(serviceData);
        }
        if (statusFilter === 'updates') {
            return hasAvailableUpdate(serviceData);
        }
        return true;
    });

    const sortedFilteredEntries = [...filteredEntries].sort(([firstName], [secondName]) => {
        return firstName.localeCompare(secondName, undefined, { sensitivity: 'base' });
    });

    const filteredCoreServices = sortedFilteredEntries.filter(([, serviceData]) => isCorePlatformService(serviceData as ServiceInfo));
    const filteredAppServices = sortedFilteredEntries.filter(([, serviceData]) => !isCorePlatformService(serviceData as ServiceInfo));

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
        const failedInstall = isFailedInstall(data);
        const isRunning = data.status === 'running' && !isUpdating;
        const isOperational = (data.status === 'running' || isDegraded) && !isUpdating;
        const isError = data.status === 'error' || data.status === 'failed';
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
        const humanName = getHumanDisplayName(name, data);

        return (
            <div key={name} role="article" aria-label={`${name} service`} className="relative min-w-0 p-5 hover:bg-white/[0.02] transition-colors group overflow-hidden">
                <div className={`absolute top-0 left-0 w-1 h-full ${isUpdating ? 'bg-amber-400 animate-pulse' : (failedInstall || isError ? 'bg-red-500' : (isDegraded ? 'bg-amber-500' : (hasUpdate ? 'bg-amber-400' : (isRunning ? 'bg-emerald-500' : 'bg-slate-600'))))} transition-colors z-20`} />

                <div className="flex flex-wrap justify-between items-start mb-4 relative z-10 gap-3">
                    <div className="flex flex-1 basis-[220px] items-start gap-3 min-w-0">
                        <div className="h-11 w-11 shrink-0 bg-white/[0.04] rounded-xl border border-white/[0.08] flex items-center justify-center shadow-inner overflow-hidden">
                            {isCore ? (
                                <Cpu size={22} className={isRunning ? 'text-emerald-400' : (isError || failedInstall ? 'text-rose-300' : 'text-slate-500')} />
                            ) : data.id ? (
                                <div className="relative w-7 h-7 flex items-center justify-center">
                                    <img
                                        src={`/img/${data.id.toLowerCase()}.png`}
                                        alt={name}
                                        className="w-full h-full object-contain"
                                        onError={(event) => {
                                            event.currentTarget.style.display = 'none';
                                            event.currentTarget.parentElement?.querySelector('.fallback')?.classList.remove('hidden');
                                        }}
                                    />
                                    <Box size={22} className={`fallback hidden ${isRunning ? 'text-emerald-400' : (isError || failedInstall ? 'text-rose-300' : 'text-slate-500')} absolute`} />
                                </div>
                            ) : (
                                <Box size={22} className={isRunning ? 'text-emerald-400' : (isError || failedInstall ? 'text-rose-300' : 'text-slate-500')} />
                            )}
                        </div>
                        <div className="min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                                <h3 className="w-full text-sm font-semibold text-slate-100 line-clamp-2 break-words leading-snug" title={humanName !== name ? `${humanName} (${name})` : name}>
                                    {humanName}
                                </h3>
                                {humanName !== name && (
                                    <span className="text-xs font-mono text-slate-300 break-all sm:break-normal" title={name}>
                                        {name}
                                    </span>
                                )}
                                {hasUpdate && (
                                    <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30">
                                        <ArrowUpCircle size={11} className="text-amber-400" />
                                        {latestVer ? `Update ${formatVersion(latestVer)}` : 'Update Available'}
                                    </span>
                                )}
                            </div>
                            <div className="flex items-center gap-2 mt-1 flex-wrap">
                                <span className="relative flex h-2 w-2">
                                    {isRunning && !isDegraded && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />}
                                    <span className={`relative inline-flex rounded-full h-2 w-2 ${isUpdating ? 'bg-amber-400' : (isError ? 'bg-red-500' : (isDegraded ? 'bg-amber-500' : (isRunning ? 'bg-emerald-500' : 'bg-slate-500')))}`} />
                                </span>
                                <span className={`text-xs font-medium capitalize ${isError ? 'text-rose-300' : (isDegraded ? 'text-amber-400' : 'text-slate-300')}`}>
                                    {isUpdating ? (data.job_status || 'updating') : (isDegraded ? 'degraded' : data.status)}
                                </span>
                                {isDegraded && unhealthyUnits.length > 0 && (
                                    <span
                                        className="text-xs px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 font-mono"
                                        title={`Unhealthy required components: ${unhealthyUnits.join(', ')}`}
                                    >
                                        {unhealthyUnits.join(', ')} down
                                    </span>
                                )}
                                {sharedVhost && (
                                    <span
                                        className="text-xs px-1.5 py-0.5 rounded bg-white/5 text-slate-300 border border-white/10 uppercase tracking-wider"
                                        title={sharedVhostMessage}
                                    >
                                        shared vhost
                                    </span>
                                )}
                                {data.managed_by && (
                                    <span className="text-xs px-1.5 py-0.5 rounded bg-white/5 text-slate-300 border border-white/10 uppercase tracking-wider">
                                        {data.managed_by}
                                    </span>
                                )}
                                {data.public_domain && (
                                    <span className="text-xs px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono truncate max-w-[150px]" title={data.public_domain}>
                                        {data.public_domain}
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>
                    <div className="ml-auto flex flex-wrap items-center gap-2 shrink-0">
                        <button
                            type="button"
                            onClick={() => {
                                setLogsModalUnits(serviceLogUnits);
                                setLogsModalService(serviceLogUnits[0] || data.process || name);
                            }}
                            disabled={!canControlServices}
                            title={canControlServices ? 'View live logs' : 'Admin access required'}
                            className="obs-touch-target-standard p-2 bg-slate-800/90 hover:bg-slate-700/90 text-slate-200 hover:text-white border border-slate-700/80 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center min-h-[40px] min-w-[40px]"
                        >
                            <Terminal size={15} />
                        </button>
                        {!isCore && webAvailable && (
                            <button
                                type="button"
                                onClick={(event) => {
                                    ingressReturnFocusRef.current = event.currentTarget;
                                    setIngressModalApp(data.id || data.process || name);
                                }}
                                disabled={isBusy}
                                className="obs-touch-target-standard p-2 text-slate-400 hover:text-indigo-400 hover:bg-white/5 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center min-h-[40px] min-w-[40px]"
                                title="Ingress & Deployment"
                            >
                                <Network size={16} />
                            </button>
                        )}
                        {(isCore || webAvailable) && (
                            <button
                                type="button"
                                onClick={() => handleOpenSettings(name, data)}
                                disabled={isBusy || (!isCore && remoteLoopbackBlocked)}
                                className="obs-touch-target-standard p-2 text-slate-400 hover:text-slate-200 hover:bg-white/5 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center min-h-[40px] min-w-[40px]"
                                title={!isCore && remoteLoopbackBlocked ? remoteLoopbackMessage : 'Settings'}
                            >
                                <Settings size={16} />
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
                        <div className="mb-4 space-y-2.5">
                            <div className="grid grid-cols-3 divide-x divide-white/[0.06] border-y border-white/[0.06] py-3 text-left">
                                <div className={`min-w-0 pr-3 ${hasUpdate ? 'text-amber-300' : ''}`}>
                                    <div className="flex items-center justify-between">
                                        <span className="text-xs uppercase font-bold text-slate-400 tracking-wider">Version</span>
                                        {!isCore && data.id && canControlServices && (
                                            <button
                                                type="button"
                                                onClick={() => handleCheckSingleUpdate(name, data)}
                                                disabled={isBusy || isCheckingThis}
                                                title="Check for updates"
                                                className="obs-touch-target-standard text-slate-400 hover:text-slate-200 transition-colors disabled:opacity-40 min-h-[36px] sm:min-h-[32px] min-w-[44px] flex items-center justify-center"
                                            >
                                                <RefreshCw size={11} className={isCheckingThis ? 'animate-spin text-indigo-400' : ''} />
                                            </button>
                                        )}
                                    </div>
                                    <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                                        <span className="text-xs font-medium text-slate-300 truncate">{formatVersion(installedVer)}</span>
                                        {hasUpdate && latestVer && (
                                            data.update_url && /^https?:\/\//i.test(data.update_url) ? (
                                                <a
                                                    href={data.update_url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="obs-touch-target-standard min-h-[36px] min-w-[36px] px-1.5 inline-flex items-center gap-1 text-xs font-semibold text-amber-400 hover:text-amber-300 transition-colors"
                                                    title="View release notes"
                                                >
                                                    → {formatVersion(latestVer)}
                                                    <ExternalLink size={10} />
                                                </a>
                                            ) : (
                                                <span className="text-xs font-semibold text-amber-400">
                                                    → {formatVersion(latestVer)}
                                                </span>
                                            )
                                        )}
                                        {!hasUpdate && updateError && (
                                            <span
                                                className="inline-flex items-center gap-1 text-xs font-semibold text-red-400 bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded"
                                                aria-label={`Update check failed: ${updateError}`}
                                            >
                                                <AlertCircle size={10} />
                                                Check failed
                                            </span>
                                        )}
                                    </div>
                                </div>
                                <div className="min-w-0 px-3">
                                    <span className="text-xs uppercase font-bold text-slate-400 tracking-wider">Port</span>
                                    <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                                        {effectivePort != null ? (
                                            <>
                                                <span className="text-xs font-mono font-medium text-slate-200">:{effectivePort}</span>
                                                {reassigned && defaultPort && (
                                                    <span
                                                        className="text-xs px-1 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono"
                                                        title={`Dynamically reassigned from default port ${defaultPort}`}
                                                    >
                                                        def :{defaultPort}
                                                    </span>
                                                )}
                                            </>
                                        ) : (
                                            <span className="text-xs font-medium text-slate-400">Headless</span>
                                        )}
                                    </div>
                                </div>
                                <div className="min-w-0 pl-3">
                                    <span className="text-xs uppercase font-bold text-slate-400 tracking-wider">Uptime</span>
                                    <p className="text-xs font-medium text-slate-300 mt-0.5 truncate" title={resolveUptimeDisplay(data)}>{resolveUptimeDisplay(data)}</p>
                                </div>
                            </div>

                            {apiKey && (
                                <div className="bg-white/[0.04] rounded-xl px-3 py-2 border border-white/[0.08] flex items-center justify-between gap-2">
                                    <div className="flex items-center gap-2 min-w-0 flex-1">
                                        <Key size={12} className="text-indigo-400 shrink-0" />
                                        <span className="text-xs uppercase font-bold text-slate-400 tracking-wider shrink-0">API Key</span>
                                        <code
                                            className="text-xs font-mono text-slate-300 truncate select-all bg-white/[0.04] px-2 py-0.5 rounded border border-white/5"
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
                                            className="obs-touch-target-standard p-1.5 text-slate-400 hover:text-slate-200 hover:bg-white/5 rounded-md transition-colors min-h-[40px] min-w-[40px] flex items-center justify-center"
                                        >
                                            {isKeyRevealed ? <EyeOff size={13} /> : <Eye size={13} />}
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => handleCopyApiKey(name, apiKey)}
                                            title="Copy API key"
                                            aria-label={`Copy ${name} API key`}
                                            className="obs-touch-target-standard p-1.5 text-slate-400 hover:text-indigo-400 hover:bg-white/5 rounded-md transition-colors min-h-[40px] min-w-[40px] flex items-center justify-center"
                                        >
                                            {isKeyCopied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    );
                })()}

                {updateError && (
                    <p role="note" className="mb-3 min-w-0 break-words text-xs text-rose-300">
                        Update check failed: {updateError}
                    </p>
                )}

                {data.components && data.components.length > 1 && (
                    <ul aria-label="Service components" className="mb-4 min-w-0 max-w-full divide-y divide-white/[0.06] text-xs text-slate-400">
                        {data.components.map((component) => (
                            <li key={component.unit} className="flex min-w-0 items-center justify-between gap-2 py-1">
                                <span className="min-w-0 break-all text-xs">
                                    {component.unit}: {component.status || 'unknown'} ({component.role || 'required'}{component.configured === false ? ', unconfigured' : ''})
                                </span>
                                <button
                                    type="button"
                                    disabled={!canControlServices}
                                    title={`View logs for ${component.unit}`}
                                    onClick={() => {
                                        setLogsModalUnits(serviceLogUnits);
                                        setLogsModalService(component.unit);
                                    }}
                                    className="obs-touch-target-standard shrink-0 rounded p-1.5 text-indigo-300 hover:text-indigo-200 hover:bg-white/5 disabled:opacity-50 min-h-[40px] min-w-[40px] flex items-center justify-center"
                                >
                                    <Terminal size={13} />
                                </button>
                            </li>
                        ))}
                    </ul>
                )}

                {isUpdating && (
                    <div className="mb-4 min-w-0 max-w-full border-y border-amber-500/20 bg-amber-500/[0.04] p-4 text-center">
                        <ProgressRing
                            progress={data.progress || 10}
                            status={isLifecycleStatus(data.job_status) ? data.job_status : 'updating'}
                            logLine={data.log_line || `Updating ${name}...`}
                            startedAt={data.started_at}
                        />
                    </div>
                )}

                {failedInstall && (
                    <div role="status" className="mb-4 min-w-0 max-w-full border-t border-rose-500/20 bg-rose-500/[0.07] p-3 text-xs text-slate-200">
                        <div className="font-semibold flex items-center gap-1.5 mb-1 text-rose-300">
                            <AlertCircle size={14} className="shrink-0 text-rose-300" />
                            Install failed — rollback/recovery unconfirmed
                        </div>
                        <p className="text-slate-200 text-xs sm:text-[13px] leading-relaxed break-words">
                            {data.last_job?.message || 'The application installer encountered an error. State recovery is unconfirmed.'}
                        </p>
                    </div>
                )}

                {!failedInstall && data.last_job && data.last_job.status !== 'completed' && !isUpdating && (
                    <div role="status" className="mb-4 min-w-0 max-w-full break-words border-y border-red-500/20 bg-red-500/5 p-3 text-xs text-red-300">
                        Last {data.last_job.action}: {data.last_job.status}. {data.last_job.message || 'Check application state and logs before retrying.'}
                    </div>
                )}

                {hasUpdate && data.id && (
                    <RequireClaim>
                        <button
                            type="button"
                            onClick={() => handleUpdateService(name, data)}
                            disabled={controlDisabled}
                            title={canControlServices ? `Update ${name}${latestVer ? ` to ${formatVersion(latestVer)}` : ''}` : 'Admin access required'}
                            className="obs-touch-target-standard w-full mb-2.5 py-2.5 bg-amber-500/15 hover:bg-amber-500 text-amber-300 hover:text-slate-950 text-xs font-semibold rounded-lg transition-all flex items-center justify-center gap-2 border border-amber-500/30 disabled:opacity-50 min-h-[40px]"
                        >
                            <ArrowUpCircle size={14} />
                            {isUpdating ? 'Updating...' : `Update ${name}${latestVer ? ` to ${formatVersion(latestVer)}` : ''}`}
                        </button>
                    </RequireClaim>
                )}

                <div className="flex gap-2 flex-wrap">
                    {isOperational || isUpdating ? (
                        <>
                            {webAvailable && (
                                <button
                                    type="button"
                                    onClick={() => handleOpenWebUI(name, data)}
                                    title={remoteLoopbackBlocked ? remoteLoopbackMessage : `Open ${name} Web UI`}
                                    className="obs-touch-target-standard flex-1 min-w-[90px] py-2 px-3 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-200 hover:text-white border border-indigo-500/40 text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50 min-h-[40px]"
                                    disabled={isBusy || remoteLoopbackBlocked}
                                >
                                    <Globe size={14} /> Web UI
                                </button>
                            )}
                            <RequireClaim>
                                <button
                                    type="button"
                                    onClick={(event) => restartService(name, data, event.currentTarget)}
                                    disabled={daemonControlDisabled}
                                    title={!canControlServices ? 'Admin access required' : (sharedVhost ? sharedVhostMessage : 'Restart service')}
                                    className="obs-touch-target-standard py-2 px-3 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300/90 hover:text-amber-200 border border-amber-500/30 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5 min-h-[40px]"
                                >
                                    <RotateCcw size={14} className={isBusy ? 'animate-spin' : ''} /> Restart
                                </button>
                                <button
                                    type="button"
                                    onClick={() => openStopConfirmation(name, data)}
                                    disabled={daemonControlDisabled}
                                    title={!canControlServices ? 'Admin access required' : (sharedVhost ? sharedVhostMessage : 'Stop service')}
                                    className="obs-touch-target-standard py-2 px-3 bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 hover:text-rose-200 border border-rose-500/40 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5 min-h-[40px]"
                                >
                                    <Square size={13} className="fill-current" /> Stop
                                </button>
                            </RequireClaim>
                        </>
                    ) : failedInstall ? (
                        <>
                            <button
                                type="button"
                                onClick={() => {
                                    setLogsModalUnits(serviceLogUnits);
                                    setLogsModalService(serviceLogUnits[0] || data.process || name);
                                }}
                                disabled={!canControlServices}
                                title={canControlServices ? 'Review installation failure logs' : 'Admin access required'}
                                className="obs-touch-target-standard flex-1 min-w-[120px] py-2 px-3.5 bg-red-500/20 hover:bg-red-500/30 text-red-200 border border-red-500/40 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50 min-h-[40px]"
                            >
                                <Terminal size={14} /> Review installation failure
                            </button>
                            <RequireClaim>
                                <button
                                    type="button"
                                    onClick={() => setGuardedStartConfirmService({ name, data })}
                                    disabled={daemonControlDisabled}
                                    title={!canControlServices ? 'Admin access required' : 'Start service (warning: install failed and recovery state is unconfirmed)'}
                                    className="obs-touch-target-standard py-2 px-3 bg-white/[0.04] hover:bg-slate-800 text-slate-300 hover:text-white border border-white/[0.08] rounded-lg text-xs font-medium flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50 min-h-[40px]"
                                >
                                    <Play size={13} className="fill-current" /> Start Service (Guarded)
                                </button>
                            </RequireClaim>
                        </>
                    ) : (
                        <>
                            <RequireClaim>
                                <button
                                    type="button"
                                    onClick={() => handleServiceControl(name, data, 'start')}
                                    disabled={daemonControlDisabled}
                                    title={!canControlServices ? 'Admin access required' : (sharedVhost ? sharedVhostMessage : 'Start service')}
                                    className="obs-touch-target-standard flex-1 min-w-[120px] py-2 px-3 bg-indigo-500/20 hover:bg-indigo-500 text-indigo-300 hover:text-white text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 border border-indigo-500/30 disabled:opacity-50 min-h-[40px]"
                                >
                                    <Play size={14} className="fill-current" /> {isBusy ? 'Starting...' : 'Start Service'}
                                </button>
                            </RequireClaim>
                            <button
                                type="button"
                                onClick={() => {
                                    setLogsModalUnits(serviceLogUnits);
                                    setLogsModalService(serviceLogUnits[0] || data.process || name);
                                }}
                                disabled={!canControlServices}
                                title={canControlServices ? 'View live logs' : 'Admin access required'}
                                className="obs-touch-target-standard py-2 px-3 bg-slate-800/90 hover:bg-slate-700/90 text-slate-200 hover:text-white border border-slate-700/80 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5 min-h-[40px]"
                            >
                                <Terminal size={14} /> Logs
                            </button>
                        </>
                    )}
                </div>
            </div>
        );
    };

    const renderServiceRow = (name: string, rawData: unknown) => {
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
        const failedInstall = isFailedInstall(data);
        const isRunning = data.status === 'running' && !isUpdating;
        const isOperational = (data.status === 'running' || isDegraded) && !isUpdating;
        const isError = data.status === 'error' || data.status === 'failed';
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
        const { port: effectivePort, defaultPort, reassigned } = resolveServicePort(name, data);
        const apiKey = user?.role === 'admin' ? data.api_key?.trim() || '' : '';
        const isKeyRevealed = revealedKeys.has(name);
        const isKeyCopied = copiedKeyService === name;
        const humanName = getHumanDisplayName(name, data);

        return (
            <div
                key={name}
                role="article"
                aria-label={`${name} service`}
                className={`min-w-0 max-w-full hover:bg-white/[0.025] p-3 sm:p-4 @[720px]:px-3 @[720px]:py-2 transition-colors flex flex-col gap-3 @[720px]:grid @[720px]:items-center @[720px]:gap-x-2 @[720px]:gap-y-0 ${SERVICE_ROW_TRACKS}`}
            >
                <div className="grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-3 gap-y-1.5 sm:flex sm:items-center sm:justify-between @[720px]:contents min-w-0 w-full">
                    <div className="col-start-1 flex items-start gap-2.5 min-w-0 w-full sm:flex-1">
                    <div className="h-8 w-8 shrink-0 bg-white/[0.04] rounded-lg border border-white/[0.08] flex items-center justify-center overflow-hidden">
                        {isCore ? (
                            <Cpu size={18} className={isRunning ? 'text-emerald-400' : (isError || failedInstall ? 'text-red-400' : 'text-slate-500')} />
                        ) : data.id ? (
                            <div className="relative w-5 h-5 flex items-center justify-center">
                                <img
                                    src={`/img/${data.id.toLowerCase()}.png`}
                                    alt={name}
                                    className="w-full h-full object-contain"
                                    onError={(event) => {
                                        event.currentTarget.style.display = 'none';
                                        event.currentTarget.parentElement?.querySelector('.fallback')?.classList.remove('hidden');
                                    }}
                                />
                                <Box size={18} className={`fallback hidden ${isRunning ? 'text-emerald-400' : (isError || failedInstall ? 'text-red-400' : 'text-slate-500')} absolute`} />
                            </div>
                        ) : (
                            <Box size={18} className={isRunning ? 'text-emerald-400' : (isError || failedInstall ? 'text-red-400' : 'text-slate-500')} />
                        )}
                    </div>

                    <div className="min-w-0 flex-1">
                        <div className="flex flex-col justify-center min-h-[40px]">
                            <span className="text-sm font-semibold text-slate-100 break-words leading-tight" title={humanName !== name ? `${humanName} (${name})` : name}>
                                {humanName}
                            </span>
                            {humanName !== name ? (
                                <div className="flex items-center gap-1.5 flex-wrap mt-0.5">
                                    <span className="text-xs font-mono text-slate-300 break-all sm:break-normal" title={name}>
                                        {name}
                                    </span>
                                    {sharedVhost && (
                                        <span className="text-xs px-1.5 py-0.5 rounded bg-white/5 text-slate-300 border border-white/10 uppercase tracking-wider" title={sharedVhostMessage}>
                                            shared vhost
                                        </span>
                                    )}
                                </div>
                            ) : sharedVhost ? (
                                <span className="text-xs px-1.5 py-0.5 rounded bg-white/5 text-slate-300 border border-white/10 uppercase tracking-wider w-fit mt-0.5" title={sharedVhostMessage}>
                                    shared vhost
                                </span>
                            ) : null}
                        </div>

                            {apiKey && (
                            <div className="mt-1.5 flex items-center gap-2 flex-wrap">
                                <Key size={12} className="text-indigo-400 shrink-0" />
                                <span className="text-xs uppercase font-bold text-slate-400 tracking-wider">API Key</span>
                                <code
                                    className="text-xs font-mono text-slate-300 truncate select-all bg-white/[0.04] px-2 py-0.5 rounded border border-white/5"
                                    title={isKeyRevealed ? apiKey : 'Click eye icon to reveal API key'}
                                >
                                    {isKeyRevealed ? apiKey : formatMaskedApiKey(apiKey)}
                                </code>
                                <button
                                    type="button"
                                    onClick={() => toggleRevealKey(name)}
                                    title={isKeyRevealed ? 'Hide API key' : 'Reveal API key'}
                                    aria-label={isKeyRevealed ? `Hide ${name} API key` : `Reveal ${name} API key`}
                                    className="obs-touch-target-standard p-1 text-slate-400 hover:text-slate-200 rounded min-h-[40px] min-w-[40px] flex items-center justify-center"
                                >
                                    {isKeyRevealed ? <EyeOff size={12} /> : <Eye size={12} />}
                                </button>
                                <button
                                    type="button"
                                    onClick={() => handleCopyApiKey(name, apiKey)}
                                    title="Copy API key"
                                    aria-label={`Copy ${name} API key`}
                                    className="obs-touch-target-standard p-1 text-slate-400 hover:text-indigo-400 rounded min-h-[40px] min-w-[40px] flex items-center justify-center"
                                >
                                    {isKeyCopied ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                                </button>
                            </div>
                        )}
                    </div>
                </div>

                    <div className="col-start-1 sm:col-auto flex flex-col justify-center gap-1 min-w-0 pl-[42px] sm:pl-0 sm:items-end @[720px]:items-start min-h-[20px] sm:min-h-[40px]">
                        <div className="flex flex-wrap items-center gap-1.5 min-w-0">
                            <span className="relative flex h-2 w-2 shrink-0">
                                {isRunning && !isDegraded && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />}
                                <span className={`relative inline-flex rounded-full h-2 w-2 ${isUpdating ? 'bg-amber-400' : (isError ? 'bg-red-500' : (isDegraded ? 'bg-amber-500' : (isRunning ? 'bg-emerald-500' : 'bg-slate-500')))}`} />
                            </span>
                            <span className={`text-xs sm:text-[13px] font-medium capitalize truncate ${isError ? 'text-rose-300' : (isDegraded ? 'text-amber-400' : 'text-slate-300')}`}>
                                {isUpdating ? (data.job_status || 'updating') : (isDegraded ? 'degraded' : data.status)}
                            </span>
                            {isDegraded && unhealthyUnits.length > 0 && (
                                <span className="min-w-0 break-all text-xs text-amber-300 font-mono">
                                    {unhealthyUnits.join(', ')} down
                                </span>
                            )}
                        </div>
                        <div className={`min-w-0 w-full text-xs gap-x-2 gap-y-0.5 @[720px]:flex @[720px]:flex-wrap ${expandedDetailsServices.has(name) ? 'flex flex-wrap' : 'hidden sm:flex sm:flex-wrap'}`}>
                        <div className="min-w-0 flex flex-col justify-center gap-1 min-h-[40px] @[720px]:min-h-0">
                            <span className="text-xs uppercase font-bold text-slate-400 tracking-wider @[720px]:hidden">Version</span>
                            <div className="flex flex-wrap items-center gap-1.5 min-w-0">
                                <span className="min-w-0 break-all text-xs sm:text-[13px] font-medium text-slate-300">{formatVersion(installedVer)}</span>
                                {hasUpdate && latestVer && (
                                    data.update_url && /^https?:\/\//i.test(data.update_url) ? (
                                        <a
                                            href={data.update_url}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="inline-flex min-w-0 break-all items-center gap-0.5 text-xs font-semibold text-amber-400 hover:text-amber-300"
                                            title="View release notes"
                                        >
                                            → {formatVersion(latestVer)}
                                            <ExternalLink size={10} />
                                        </a>
                                    ) : (
                                        <span className="min-w-0 break-all text-xs font-semibold text-amber-400">
                                            → {formatVersion(latestVer)}
                                        </span>
                                    )
                                )}
                                {!hasUpdate && updateError && (
                                    <span
                                        className="inline-flex max-w-full items-center gap-1 text-xs font-semibold text-rose-300"
                                        aria-label={`Update check failed: ${updateError}`}
                                    >
                                        <AlertCircle size={10} />
                                        Check failed
                                    </span>
                                )}
                            </div>
                        </div>

                        <div className="min-w-0 flex flex-col justify-center gap-1 min-h-[40px] @[720px]:min-h-0">
                            <span className="text-xs uppercase font-bold text-slate-400 tracking-wider @[720px]:hidden">Uptime</span>
                            <div className="min-w-0">
                                <span className="break-words text-xs sm:text-[13px] font-medium text-slate-300" title={resolveUptimeDisplay(data)}>{resolveUptimeDisplay(data)}</span>
                            </div>
                        </div>

                        </div>
                        {data.managed_by && (
                            <span className="hidden sm:inline-flex @[720px]:hidden text-xs px-1.5 py-0.5 rounded bg-white/5 text-slate-300 border border-white/10 uppercase tracking-wider">
                                {data.managed_by}
                            </span>
                        )}
                    </div>

                    <div className="col-start-2 row-start-1 row-span-2 sm:hidden flex items-center justify-end shrink-0 self-center">
                        <button
                            type="button"
                            onClick={() => {
                                setExpandedDetailsServices((currentExpanded) => {
                                    const updatedExpanded = new Set(currentExpanded);
                                    if (updatedExpanded.has(name)) {
                                        updatedExpanded.delete(name);
                                    } else {
                                        updatedExpanded.add(name);
                                    }
                                    return updatedExpanded;
                                });
                            }}
                            aria-expanded={expandedDetailsServices.has(name)}
                            aria-label={`Toggle details for ${name}`}
                            title={`Toggle details for ${name}`}
                            className="sm:hidden obs-touch-target-standard py-1.5 px-2.5 bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-slate-100 border border-slate-700/60 rounded-lg text-xs font-medium flex items-center justify-center gap-1 min-h-[44px] min-w-[44px] shrink-0"
                        >
                            {expandedDetailsServices.has(name) ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                            <span>Details</span>
                        </button>
                    </div>
                </div>

                <div className="flex flex-col gap-3 min-w-0 w-full pt-3 border-t border-white/[0.06] @[720px]:contents">
                    <div className={`gap-4 text-xs @[720px]:contents min-w-0 w-full ${expandedDetailsServices.has(name) ? 'grid grid-cols-1 @[520px]:grid-cols-3' : 'hidden sm:grid sm:grid-cols-3'}`}>
                        <div className="relative min-w-0 flex flex-col justify-center gap-1 min-h-[40px]" data-access-menu={name}>
                            <span className="text-xs uppercase font-bold text-slate-400 tracking-wider @[720px]:hidden">Port</span>
                            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 min-w-0 max-w-full">
                                <div className="flex min-w-0 basis-16 grow shrink-0 flex-wrap items-center gap-x-2 gap-y-1">
                                    {effectivePort != null ? (
                                        <>
                                            <span className="text-xs font-mono font-medium text-slate-100 whitespace-nowrap shrink-0 inline-block min-w-[6ch]">:{effectivePort}</span>
                                            {reassigned && defaultPort && (
                                                <span className="text-xs text-indigo-300 font-mono whitespace-nowrap" title={`Default ${defaultPort}`}>
                                                    def :{defaultPort}
                                                </span>
                                            )}
                                        </>
                                    ) : (
                                        <span className="text-xs font-medium text-slate-400 whitespace-nowrap inline-block min-w-[6ch]">Headless</span>
                                    )}
                                </div>
                                {(webAvailable || isCore || Boolean(data.public_domain || data.internal_domain)) && (
                                    <div className="ml-auto inline-flex shrink-0">
                                        <button
                                            type="button"
                                            id={`connection-trigger-${appId || name}`}
                                            onClick={() => setOpenAccessMenuService((currentOpen) => (currentOpen === name ? null : name))}
                                            aria-expanded={openAccessMenuService === name}
                                            aria-haspopup="menu"
                                            aria-controls={`connection-menu-${appId || name}`}
                                            aria-label={`Connection details for ${name}`}
                                            title={`Connection details for ${name}`}
                                            className={`obs-touch-target-standard py-1 px-2 border rounded-lg text-xs font-semibold transition-colors flex items-center justify-center gap-1 min-h-[44px] sm:min-h-[40px] min-w-[40px] shrink-0 ${
                                                openAccessMenuService === name
                                                    ? 'bg-slate-700 text-white border-slate-500'
                                                    : 'bg-white/[0.03] hover:bg-white/[0.07] text-slate-200 border-white/[0.08]'
                                            }`}
                                        >
                                            <span className="@[720px]:sr-only @[1100px]:not-sr-only">Connection</span>
                                            <ChevronDown size={14} className={`transition-transform ${openAccessMenuService === name ? 'rotate-180' : ''}`} />
                                        </button>
                                    </div>
                                )}
                            </div>
                            {(webAvailable || isCore || Boolean(data.public_domain || data.internal_domain)) && openAccessMenuService === name && (
                                <ViewportMenu
                                    id={`connection-menu-${appId || name}`}
                                    role="menu"
                                    aria-label={`Connection details for ${name}`}
                                    align="left"
                                    onDismiss={() => setOpenAccessMenuService(null)}
                                    className="min-w-[200px] p-1.5 bg-slate-900/95 backdrop-blur-xl border border-white/10 rounded-xl shadow-2xl flex flex-col gap-1.5"
                                >
                                    {(data.public_domain || data.internal_domain) && (
                                        <div className="px-2.5 py-1.5 border-b border-white/[0.08] text-xs">
                                            <span className="text-xs uppercase font-bold text-slate-400 tracking-wider block">Endpoint</span>
                                            {data.public_domain && (
                                                <span className="font-mono text-indigo-300 break-all select-all block mt-0.5" title={data.public_domain}>
                                                    {data.public_domain}
                                                </span>
                                            )}
                                            {data.internal_domain && data.internal_domain !== data.public_domain && (
                                                <span className="font-mono text-slate-300 break-all select-all block mt-0.5" title={data.internal_domain}>
                                                    {data.internal_domain}
                                                </span>
                                            )}
                                        </div>
                                    )}
                                    {!isCore && webAvailable && (
                                        <button
                                            type="button"
                                            role="menuitem"
                                            onClick={(event) => {
                                                ingressReturnFocusRef.current = event.currentTarget.closest('[data-access-menu]')?.querySelector<HTMLElement>('[aria-haspopup="menu"]') ?? null;
                                                setOpenAccessMenuService(null);
                                                setIngressModalApp(data.id || data.process || name);
                                            }}
                                            disabled={isBusy}
                                            className="obs-touch-target-standard w-full py-2 px-2.5 text-left text-slate-300 hover:text-white hover:bg-slate-800 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex items-center gap-2 min-h-[40px]"
                                            aria-label={`Ingress and deployment for ${name}`}
                                            title="Ingress & Deployment"
                                        >
                                            <Network size={14} className="text-indigo-400 shrink-0" />
                                            <span>Ingress & Deployment</span>
                                        </button>
                                    )}
                                    {(isCore || webAvailable) && (
                                        <button
                                            type="button"
                                            role="menuitem"
                                            onClick={() => {
                                                setOpenAccessMenuService(null);
                                                handleOpenSettings(name, data);
                                            }}
                                            disabled={isBusy || (!isCore && remoteLoopbackBlocked)}
                                            className="obs-touch-target-standard w-full py-2 px-2.5 text-left text-slate-300 hover:text-white hover:bg-slate-800 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex items-center gap-2 min-h-[40px]"
                                            aria-label={`Settings for ${name}`}
                                            title={!isCore && remoteLoopbackBlocked ? remoteLoopbackMessage : 'Settings'}
                                        >
                                            <Settings size={14} className="text-slate-400 shrink-0" />
                                            <span>Settings</span>
                                        </button>
                                    )}
                                </ViewportMenu>
                            )}
                        </div>

                        {expandedDetailsServices.has(name) && (data.managed_by || data.public_domain || data.internal_domain) && (
                            <div className="sm:hidden min-w-0 w-full flex items-center gap-2 flex-wrap text-xs pt-1 border-t border-white/[0.08]">
                                <span className="text-xs uppercase font-bold text-slate-400 tracking-wider shrink-0">Runtime</span>
                                {data.managed_by && (
                                    <span className="text-xs px-2 py-0.5 rounded bg-white/5 text-slate-300 border border-white/10 uppercase tracking-wider">
                                        {data.managed_by}
                                    </span>
                                )}
                                {data.public_domain && (
                                    <span className="text-xs px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono break-all" title={data.public_domain}>
                                        {data.public_domain}
                                    </span>
                                )}
                                {data.internal_domain && data.internal_domain !== data.public_domain && (
                                    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono break-all" title={data.internal_domain}>
                                        {data.internal_domain}
                                    </span>
                                )}
                            </div>
                        )}
                    </div>

                    {!failedInstall || isOperational ? (
                        <div role="group" aria-label={`${name} actions`} className="flex flex-wrap items-center gap-2 min-w-0 w-full @[720px]:justify-end">
                    {hasUpdate && data.id && !failedInstall && (
                        <RequireClaim>
                            <button
                                type="button"
                                onClick={() => handleUpdateService(name, data)}
                                disabled={controlDisabled}
                                title={canControlServices ? `Update ${name}${latestVer ? ` to ${formatVersion(latestVer)}` : ''}` : 'Admin access required'}
                                className="obs-touch-target-standard py-2 px-3 bg-amber-500/15 hover:bg-amber-500 text-amber-300 hover:text-slate-950 text-xs font-semibold rounded-lg transition-all flex items-center justify-center gap-1.5 border border-amber-500/30 disabled:opacity-50 min-h-[44px] sm:min-h-[40px] min-w-[40px] shrink-0"
                            >
                                <ArrowUpCircle size={14} /> <span className="@[720px]:sr-only @[1100px]:not-sr-only">Update</span>
                            </button>
                        </RequireClaim>
                    )}

                    {isOperational || isUpdating ? (
                        <>
                            {webAvailable ? (
                                <button
                                    type="button"
                                    onClick={() => handleOpenWebUI(name, data)}
                                    title={remoteLoopbackBlocked ? remoteLoopbackMessage : `Open ${name} Web UI`}
                                    className="col-span-1 obs-touch-target-standard py-2 px-2 sm:px-2.5 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-200 hover:text-white border border-indigo-500/40 text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-1 sm:gap-1.5 disabled:opacity-50 min-h-[44px] sm:min-h-[40px] min-w-[40px] shrink-0 max-w-full"
                                    disabled={isBusy || remoteLoopbackBlocked}
                                >
                                    <Globe size={14} /> <span className="@[720px]:sr-only @[1100px]:not-sr-only">Web UI</span>
                                </button>
                            ) : (
                                null
                            )}
                            <button
                                type="button"
                                onClick={() => {
                                    setLogsModalUnits(serviceLogUnits);
                                    setLogsModalService(serviceLogUnits[0] || data.process || name);
                                }}
                                disabled={!canControlServices}
                                title={canControlServices ? 'View live logs' : 'Admin access required'}
                                className={`obs-touch-target-standard py-2 px-2 sm:px-2.5 bg-slate-800/90 hover:bg-slate-700/90 text-slate-200 hover:text-white border border-slate-700/80 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-1 sm:gap-1.5 min-h-[44px] sm:min-h-[40px] min-w-[40px] shrink-0 max-w-full ${
                                    webAvailable ? 'col-span-1' : 'col-span-2'
                                }`}
                            >
                                <Terminal size={14} /> <span className="@[720px]:sr-only @[1100px]:not-sr-only">Logs</span>
                            </button>
                            <div className="relative inline-flex min-w-0 max-w-full shrink-0" data-manage-menu={name}>
                                <button
                                    type="button"
                                    id={`manage-trigger-${appId || name}`}
                                    onClick={() => setOpenManageMenuService((currentOpen) => (currentOpen === name ? null : name))}
                                    aria-expanded={openManageMenuService === name}
                                    aria-haspopup="menu"
                                    aria-controls={`manage-menu-${appId || name}`}
                                    aria-label={`Manage ${name} service actions`}
                                    title={!canControlServices ? 'Admin access required' : `Manage ${name} service actions`}
                                    className={`obs-touch-target-standard py-2 px-2 sm:px-2.5 border rounded-lg text-xs font-medium transition-colors flex items-center justify-center gap-1 sm:gap-1.5 min-h-[44px] sm:min-h-[40px] min-w-[40px] shrink-0 w-full ${
                                        openManageMenuService === name
                                            ? 'bg-slate-700 text-white border-slate-500'
                                            : 'bg-slate-800/90 hover:bg-slate-700/90 text-slate-200 hover:text-white border border-slate-700/80'
                                    }`}
                                >
                                    <Sliders size={14} /> Manage
                                </button>
                                {openManageMenuService === name && (
                                    <ViewportMenu
                                        id={`manage-menu-${appId || name}`}
                                        role="menu"
                                        aria-label={`${name} service actions`}
                                        onDismiss={() => setOpenManageMenuService(null)}
                                        className="min-w-[170px] p-1.5 bg-slate-900/95 backdrop-blur-xl border border-white/10 rounded-xl shadow-2xl flex flex-col gap-1.5"
                                    >
                                        <RequireClaim>
                                            <button
                                                type="button"
                                                role="menuitem"
                                                onClick={(event) => restartService(name, data, event.currentTarget)}
                                                disabled={daemonControlDisabled}
                                                title={!canControlServices ? 'Admin access required' : (sharedVhost ? sharedVhostMessage : 'Restart service')}
                                                aria-label={`Restart ${name} service`}
                                                className="obs-touch-target-standard w-full py-2 px-3 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300/90 hover:text-amber-200 border border-amber-500/30 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 flex items-center justify-start gap-2 min-h-[40px]"
                                            >
                                                <RotateCcw size={14} className={isBusy ? 'animate-spin' : ''} /> Restart
                                            </button>
                                            <button
                                                type="button"
                                                role="menuitem"
                                                onClick={() => {
                                                    openStopConfirmation(name, data);
                                                }}
                                                disabled={daemonControlDisabled}
                                                title={!canControlServices ? 'Admin access required' : (sharedVhost ? sharedVhostMessage : 'Stop service')}
                                                aria-label={`Stop ${name} service`}
                                                className="obs-touch-target-standard w-full py-2 px-3 bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 hover:text-rose-200 border border-rose-500/40 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 flex items-center justify-start gap-2 min-h-[40px]"
                                            >
                                                <Square size={13} className="fill-current" /> Stop
                                            </button>
                                            {!isCore && data.id && (
                                                <button
                                                    type="button"
                                                    role="menuitem"
                                                    onClick={() => {
                                                        void handleCheckSingleUpdate(name, data);
                                                    }}
                                                    disabled={isBusy || isCheckingThis || !canControlServices}
                                                    title={!canControlServices ? 'Admin access required' : 'Check for updates'}
                                                    aria-label={`Check for updates for ${name}`}
                                                    className="obs-touch-target-standard w-full py-2 px-3 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/60 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 flex items-center justify-start gap-2 min-h-[40px]"
                                                >
                                                    <RefreshCw size={14} className={isCheckingThis ? 'animate-spin text-indigo-400' : ''} />
                                                    <span>{isCheckingThis ? 'Checking updates...' : 'Check for updates'}</span>
                                                </button>
                                            )}
                                        </RequireClaim>
                                    </ViewportMenu>
                                )}
                            </div>
                        </>
                    ) : (
                        <>
                            <RequireClaim>
                                <button
                                    type="button"
                                    onClick={() => handleServiceControl(name, data, 'start')}
                                    disabled={daemonControlDisabled}
                                    title={!canControlServices ? 'Admin access required' : (sharedVhost ? sharedVhostMessage : 'Start service')}
                                    className={`obs-touch-target-standard py-2 px-2 sm:px-3 bg-indigo-500/20 hover:bg-indigo-500 text-indigo-300 hover:text-white text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-1.5 border border-indigo-500/30 disabled:opacity-50 min-h-[44px] sm:min-h-[40px] min-w-[40px] shrink-0 max-w-full ${
                                        !isCore && data.id ? 'col-span-1' : 'col-span-2 sm:col-span-1'
                                    }`}
                                >
                                    <Play size={13} className="fill-current" /> {isBusy ? 'Starting...' : 'Start Service'}
                                </button>
                            </RequireClaim>
                            <button
                                type="button"
                                onClick={() => {
                                    setLogsModalUnits(serviceLogUnits);
                                    setLogsModalService(serviceLogUnits[0] || data.process || name);
                                }}
                                disabled={!canControlServices}
                                title={canControlServices ? 'View live logs' : 'Admin access required'}
                                className="col-span-1 obs-touch-target-standard py-2 px-2 sm:px-3 bg-slate-800/90 hover:bg-slate-700/90 text-slate-200 hover:text-white border border-slate-700/80 rounded-lg text-xs font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-1.5 min-h-[44px] sm:min-h-[40px] min-w-[40px] shrink-0 max-w-full"
                            >
                                <Terminal size={14} /> <span className="@[720px]:sr-only @[1100px]:not-sr-only">Logs</span>
                            </button>
                            {!isCore && data.id && (
                                <div className="relative inline-flex min-w-0 max-w-full" data-manage-menu={name}>
                                    <button
                                        type="button"
                                        id={`manage-trigger-${appId || name}`}
                                        onClick={() => setOpenManageMenuService((currentOpen) => (currentOpen === name ? null : name))}
                                        aria-expanded={openManageMenuService === name}
                                        aria-haspopup="menu"
                                        aria-controls={`manage-menu-${appId || name}`}
                                        aria-label={`Manage ${name} service actions`}
                                        title={!canControlServices ? 'Admin access required' : `Manage ${name} service actions`}
                                        className={`obs-touch-target-standard py-2 px-2 sm:px-3 border rounded-lg text-xs font-medium transition-colors flex items-center justify-center gap-1 sm:gap-1.5 min-h-[44px] sm:min-h-[40px] min-w-[40px] shrink-0 max-w-full ${
                                            openManageMenuService === name
                                                ? 'bg-slate-700 text-white border-slate-500'
                                                : 'bg-slate-800/90 hover:bg-slate-700/90 text-slate-200 hover:text-white border border-slate-700/80'
                                        }`}
                                    >
                                        <Sliders size={14} /> Manage
                                    </button>
                                    {openManageMenuService === name && (
                                        <ViewportMenu
                                            id={`manage-menu-${appId || name}`}
                                            role="menu"
                                            aria-label={`${name} service actions`}
                                            onDismiss={() => setOpenManageMenuService(null)}
                                            className="min-w-[170px] p-1.5 bg-slate-900/95 backdrop-blur-xl border border-white/10 rounded-xl shadow-2xl flex flex-col gap-1.5"
                                        >
                                            <RequireClaim>
                                                <button
                                                    type="button"
                                                    role="menuitem"
                                                    onClick={() => {
                                                        void handleCheckSingleUpdate(name, data);
                                                    }}
                                                    disabled={isBusy || isCheckingThis || !canControlServices}
                                                    title={!canControlServices ? 'Admin access required' : 'Check for updates'}
                                                    aria-label={`Check for updates for ${name}`}
                                                    className="obs-touch-target-standard w-full py-2 px-3 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/60 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 flex items-center justify-start gap-2 min-h-[40px]"
                                                >
                                                    <RefreshCw size={14} className={isCheckingThis ? 'animate-spin text-indigo-400' : ''} />
                                                    <span>{isCheckingThis ? 'Checking updates...' : 'Check for updates'}</span>
                                                </button>
                                            </RequireClaim>
                                        </ViewportMenu>
                                    )}
                                </div>
                            )}
                        </>
                    )}
                </div>
            ) : (
                <div role="group" aria-label={`${name} actions`} className="flex flex-wrap items-center gap-2 min-w-0 w-full @[720px]:justify-end">
                    <button
                        type="button"
                        onClick={() => {
                            setLogsModalUnits(serviceLogUnits);
                            setLogsModalService(serviceLogUnits[0] || data.process || name);
                        }}
                        disabled={!canControlServices}
                        title={canControlServices ? 'Review installation failure logs' : 'Admin access required'}
                        className="obs-touch-target-standard py-2 px-3 bg-red-500/20 hover:bg-red-500/30 text-red-200 border border-red-500/40 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50 min-h-[44px] sm:min-h-[40px] min-w-[40px] shrink-0 max-w-full"
                    >
                        <Terminal size={14} className="shrink-0" />
                        <span>Review installation failure</span>
                    </button>
                </div>
            )}
                </div>

                {data.components && data.components.length > 1 && (
                    <ul aria-label="Service components" className="col-span-full min-w-0 grid grid-cols-1 @[640px]:grid-cols-2 gap-x-6 border-t border-white/[0.06] pt-2 text-xs text-slate-400">
                        {data.components.map((component) => (
                            <li key={component.unit} className="flex min-w-0 items-center justify-between gap-2">
                                <span className="min-w-0 break-all">
                                    {component.unit}: {component.status || 'unknown'} ({component.role || 'required'}{component.configured === false ? ', unconfigured' : ''})
                                </span>
                                <button
                                    type="button"
                                    disabled={!canControlServices}
                                    title={`View logs for ${component.unit}`}
                                    onClick={() => {
                                        setLogsModalUnits(serviceLogUnits);
                                        setLogsModalService(component.unit);
                                    }}
                                    className="obs-touch-target-standard shrink-0 rounded-lg p-2 text-indigo-300 hover:text-indigo-200 hover:bg-white/5 disabled:opacity-50 min-h-[40px] min-w-[40px] flex items-center justify-center"
                                >
                                    <Terminal size={12} />
                                </button>
                            </li>
                        ))}
                    </ul>
                )}

                {updateError && (
                    <p role="note" className="col-span-full min-w-0 break-words text-xs text-rose-300">
                        Update check failed: {updateError}
                    </p>
                )}

                {failedInstall && (
                    <div
                        role="status"
                        className="w-full min-w-0 order-last col-span-full border-t border-rose-500/20 bg-rose-500/[0.07] p-3 text-xs text-slate-200 break-words flex flex-col gap-2"
                    >
                        <div className="font-semibold flex items-center gap-1.5 text-rose-300 mb-1">
                            <AlertCircle size={14} className="shrink-0 text-rose-300" />
                            Install failed — rollback/recovery unconfirmed
                        </div>
                        <p className="text-slate-200 text-sm leading-relaxed">
                            {data.last_job?.message || 'The application installer encountered an error. State recovery is unconfirmed.'}
                        </p>
                        {isOperational ? <p className="text-xs text-amber-300/90">The daemon is running; installation recovery remains unconfirmed.</p> : <div className="flex flex-col sm:flex-row items-end sm:items-center justify-end gap-2 sm:gap-3 pt-2 border-t border-white/[0.08] w-full">
                            <span className="text-xs sm:text-[13px] text-amber-300/90 flex items-center gap-1.5">
                                <AlertTriangle size={13} className="shrink-0 text-amber-400" />
                                <span>Confirmation required; starting does not repair the failed installation.</span>
                            </span>
                            <RequireClaim>
                                <button
                                    type="button"
                                    onClick={() => setGuardedStartConfirmService({ name, data })}
                                    disabled={daemonControlDisabled}
                                    title={!canControlServices ? 'Admin access required' : 'Start service (warning: install failed and recovery state is unconfirmed)'}
                                    className="obs-touch-target-standard py-2 px-3 bg-white/[0.04] hover:bg-slate-800 text-slate-200 hover:text-white border border-white/[0.08] rounded-lg text-xs sm:text-[13px] font-medium flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50 min-h-[44px] shrink-0 max-w-full text-center"
                                >
                                    <Play size={13} className="fill-current shrink-0" /> <span>Start Service (Guarded)</span>
                                </button>
                            </RequireClaim>
                        </div>}
                    </div>
                )}

                {!failedInstall && data.last_job && data.last_job.status !== 'completed' && !isUpdating && (
                    <div
                        role="status"
                        className="w-full min-w-0 order-last col-span-full text-xs text-amber-300 bg-amber-500/[0.07] border-t border-amber-500/20 p-3 break-words"
                    >
                        Last {data.last_job.action}: {data.last_job.status}. {data.last_job.message || 'Check application state and logs before retrying.'}
                    </div>
                )}
            </div>
        );
    };

    if (services === undefined && inventoryError) {
        return (
            <section className="w-full min-h-[50vh] flex items-center justify-center px-4">
                <div role="alert" className="w-full border-y border-rose-500/30 bg-gradient-to-r from-rose-500/[0.08] to-transparent px-4 py-6 text-center space-y-3">
                    <AlertCircle size={28} className="mx-auto text-rose-300" />
                    <h2 className="text-base font-semibold text-rose-100">Service inventory unavailable</h2>
                    <p className="text-sm text-rose-200/90">
                        No service inventory has been loaded, so an empty fleet cannot be confirmed.
                        {inventoryError instanceof Error ? ` ${inventoryError.message}` : ''}
                    </p>
                    <button
                        type="button"
                        onClick={() => void mutate()}
                        disabled={isValidating}
                        className="obs-touch-target-standard min-h-[44px] px-4 py-2 rounded-lg border border-rose-400/40 bg-rose-500/15 text-rose-100 hover:bg-rose-500/25 disabled:opacity-50"
                    >
                        {isValidating ? 'Retrying inventory…' : 'Retry service inventory'}
                    </button>
                </div>
            </section>
        );
    }

    if (services === undefined) {
        return <div role="status" aria-label="Loading service inventory"><ServicesSkeleton /></div>;
    }

    return (
        <div className="relative z-10 min-w-0 max-w-full w-full">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] pb-4">
                <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="text-xs font-semibold px-2.5 py-1 bg-indigo-500/10 rounded-full text-indigo-200 border border-indigo-400/20">
                        {allEntries.length} Total
                    </span>
                    <p className="text-slate-400 text-xs leading-relaxed">
                        Monitor daemon health, inspect logs, and manage application lifecycles across the fleet.
                    </p>
                </div>
                <button
                    type="button"
                    onClick={handleCheckAllUpdates}
                    disabled={checkingUpdates}
                    aria-label="Check Updates & Sync"
                    title="Check Updates & Sync"
                    className="obs-touch-target-standard h-10 sm:h-11 min-h-[40px] sm:min-h-[44px] px-3 sm:px-3.5 bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 rounded-lg text-xs sm:text-sm font-medium text-slate-200 transition-all flex items-center gap-1.5 sm:gap-2 disabled:opacity-50 shrink-0"
                >
                    <RefreshCw size={14} className={checkingUpdates ? 'animate-spin text-indigo-400' : ''} />
                    <span className="sm:hidden">{checkingUpdates ? 'Syncing...' : 'Sync'}</span>
                    <span className="hidden sm:inline">{checkingUpdates ? 'Checking Updates...' : 'Check Updates & Sync'}</span>
                </button>
            </div>

            {Boolean(inventoryError) && (
                <div role="status" className="border-b border-amber-500/25 bg-gradient-to-r from-amber-500/[0.08] to-transparent px-4 py-3 text-xs text-amber-100">
                    Service refresh failed. Showing the most recently available inventory; newer WebSocket service updates remain visible when received.
                    <button
                        type="button"
                        onClick={() => void mutate()}
                        disabled={isValidating}
                        className="obs-touch-target-standard ml-2 min-h-[40px] px-2 underline underline-offset-2 disabled:opacity-50"
                    >
                        {isValidating ? 'Retrying…' : 'Retry'}
                    </button>
                </div>
            )}

            {attentionCount > 0 && (
                <div role="region" aria-label="Fleet attention required" className="border-y border-amber-500/25 bg-gradient-to-r from-amber-500/[0.08] via-rose-500/[0.05] to-transparent px-4 py-3 text-slate-200">
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between sm:gap-3">
                        <div className="flex items-start gap-2.5 w-full min-w-0 flex-1">
                            <AlertTriangle className="text-red-400 shrink-0 mt-0.5" size={16} />
                            <div className="min-w-0 text-xs leading-relaxed">
                                <span className="font-semibold text-red-200">
                                    Attention ({attentionCount}):
                                </span>{' '}
                                {attentionEntries.map(([serviceName, serviceDataRaw], attentionIndex) => {
                                    const serviceData = serviceDataRaw as ServiceInfo;
                                    const humanName = getHumanDisplayName(serviceName, serviceData);
                                    const failedInstall = isFailedInstall(serviceData);
                                    const degradedSummary = getDegradedSummary(serviceData);
                                    const reason = failedInstall
                                        ? 'Install failed · Recovery unconfirmed'
                                        : degradedSummary.degraded
                                            ? `Degraded (${degradedSummary.unhealthyUnits.join(', ')} offline)`
                                            : serviceData.update_error
                                                ? 'Update check error'
                                                : serviceData.last_job
                                                    ? `${serviceData.last_job.action} ${serviceData.last_job.status}`
                                                    : 'Attention needed';
                                    return (
                                        <span key={serviceName} className="text-red-300">
                                            {attentionIndex > 0 ? ', ' : ''}
                                            <strong className="text-red-200 font-semibold">{humanName}</strong> — {reason}
                                        </span>
                                    );
                                })}
                            </div>
                        </div>
                        <div className="flex items-center gap-1.5 self-start sm:self-auto shrink-0 flex-wrap">
                            {primaryAttentionService && (
                                <button
                                    type="button"
                                    disabled={!canControlServices}
                                    onClick={() => {
                                        const logUnits = resolveServiceLogUnits(primaryAttentionService[0], primaryAttentionService[1]);
                                        setLogsModalUnits(logUnits);
                                        setLogsModalService(logUnits[0] || primaryAttentionService[1].process || primaryAttentionService[0]);
                                    }}
                                    title={canControlServices ? `Inspect failure logs for ${primaryAttentionService[0]}` : 'Admin access required'}
                                    className="obs-touch-target-standard h-9 min-h-[40px] px-2.5 sm:px-3 bg-red-500/15 hover:bg-red-500/25 text-red-200 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 flex items-center gap-1.5"
                                >
                                    <Terminal size={13} /> Inspect Logs
                                </button>
                            )}
                            <button
                                type="button"
                                onClick={() => setStatusFilter(statusFilter === 'attention' ? 'all' : 'attention')}
                                className="obs-touch-target-standard h-9 min-h-[40px] px-2.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors flex items-center border border-slate-700/50"
                            >
                                {statusFilter === 'attention'
                                    ? 'Show all services'
                                    : attentionCount === 1
                                        ? 'Filter affected service'
                                        : 'Filter affected services'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            <div role="group" aria-label="Service search and filters" className="flex min-w-0 flex-col gap-3 border-b border-white/[0.07] py-4">
                <div className="flex items-center gap-2">
                    <div className="relative flex-1 min-w-0">
                        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                        <input
                            type="text"
                            value={searchQuery}
                            onChange={(event) => setSearchQuery(event.target.value)}
                            placeholder="Name, domain or port"
                            aria-label="Search services by name, domain, port"
                            className="w-full h-11 min-h-[44px] pl-9 pr-12 bg-white/[0.03] border border-white/[0.08] rounded-xl text-xs sm:text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                        />
                        {searchQuery.length > 0 && (
                            <button
                                type="button"
                                onClick={() => setSearchQuery('')}
                                title="Clear search"
                                className="obs-touch-target-standard absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 p-1.5 rounded min-h-[44px] sm:min-h-[40px] min-w-[44px] sm:min-w-[40px] flex items-center justify-center"
                            >
                                <X size={14} />
                            </button>
                        )}
                    </div>
                    <div className="flex min-h-[44px] items-center shrink-0 gap-1">
                        <button
                            type="button"
                            onClick={() => setViewMode('list')}
                            title="Compact list view"
                            aria-label="Compact list view"
                            aria-pressed={viewMode === 'list'}
                            className={`obs-touch-target-standard h-10 min-h-[44px] sm:min-h-[40px] min-w-[44px] sm:min-w-[40px] px-2.5 sm:px-3 rounded-md text-xs font-medium flex items-center justify-center gap-1.5 transition-colors ${viewMode === 'list' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                        >
                            <LayoutList size={14} aria-hidden="true" /> <span>List</span>
                        </button>
                        <button
                            type="button"
                            onClick={() => setViewMode('card')}
                            title="Card grid view"
                            aria-label="Card grid view"
                            aria-pressed={viewMode === 'card'}
                            className={`obs-touch-target-standard h-10 min-h-[44px] sm:min-h-[40px] min-w-[44px] sm:min-w-[40px] px-2.5 sm:px-3 rounded-md text-xs font-medium flex items-center justify-center gap-1.5 transition-colors ${viewMode === 'card' ? 'bg-slate-800 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'}`}
                        >
                            <LayoutGrid size={14} aria-hidden="true" /> <span>Cards</span>
                        </button>
                    </div>
                </div>

                <div className="sm:hidden">
                    <button
                        type="button"
                        onClick={() => setIsMobileFiltersOpen((previousOpen) => !previousOpen)}
                        aria-expanded={isMobileFiltersOpen}
                        aria-controls="services-status-filter-group"
                        aria-label={`Status filter: ${activeFilterLabel} (${activeFilterCount})${attentionCount > 0 ? `, ${attentionCount} need attention` : ''}${updatesAvailableCount > 0 ? `, ${updatesAvailableCount} ${updatesAvailableCount === 1 ? 'update' : 'updates'} available` : ''}. Tap to change filter.`}
                        className="obs-touch-target-standard w-full flex items-center justify-between gap-2 flex-wrap px-3 py-2 bg-white/[0.03] border border-white/[0.08] rounded-lg text-xs font-medium text-slate-200 min-h-[44px]"
                    >
                        <span className="flex items-center gap-1.5 flex-wrap min-w-0">
                            <span className="text-slate-400 font-normal">Filter:</span>
                            <span className="font-semibold text-slate-100">{activeFilterLabel}</span>
                            <span className="px-1.5 py-0.5 rounded bg-white/10 text-slate-300 font-mono text-xs">
                                {activeFilterCount}
                            </span>
                            {attentionCount > 0 && (
                                <span className="text-xs text-rose-300 font-medium whitespace-nowrap">
                                    · {attentionCount} attention
                                </span>
                            )}
                            {updatesAvailableCount > 0 && (
                                <span className="text-xs text-amber-300 font-medium whitespace-nowrap">
                                    · {updatesAvailableCount} {updatesAvailableCount === 1 ? 'update' : 'updates'}
                                </span>
                            )}
                        </span>
                        <span className="flex items-center gap-1 text-slate-400 text-xs min-h-[44px] min-w-[44px] justify-end shrink-0">
                            <span>{isMobileFiltersOpen ? 'Collapse' : 'Change'}</span>
                            <ChevronDown size={14} className={`transition-transform duration-200 ${isMobileFiltersOpen ? 'rotate-180' : ''}`} />
                        </span>
                    </button>
                </div>

                <div
                    id="services-status-filter-group"
                    className={`${isMobileFiltersOpen ? 'flex' : 'hidden'} sm:flex items-center gap-1.5 flex-wrap pt-0.5 sm:pt-0`}
                >
                    <button
                        type="button"
                        onClick={() => {
                            setStatusFilter('all');
                            setIsMobileFiltersOpen(false);
                        }}
                        className={`obs-touch-target-standard px-3 py-2 rounded-lg text-xs font-medium transition-colors min-h-[40px] flex items-center ${statusFilter === 'all' ? 'bg-indigo-600 text-white shadow-sm' : 'bg-white/[0.03] text-slate-400 hover:text-slate-200 border border-white/[0.08]'}`}
                    >
                        All ({allEntries.length})
                    </button>
                    <button
                        type="button"
                        onClick={() => {
                            setStatusFilter('running');
                            setIsMobileFiltersOpen(false);
                        }}
                        className={`obs-touch-target-standard px-3 py-2 rounded-lg text-xs font-medium transition-colors min-h-[40px] flex items-center ${statusFilter === 'running' ? 'bg-emerald-600 text-white shadow-sm' : 'bg-white/[0.03] text-slate-400 hover:text-slate-200 border border-white/[0.08]'}`}
                    >
                        Running ({runningCount})
                    </button>
                    <button
                        type="button"
                        onClick={() => {
                            setStatusFilter('stopped');
                            setIsMobileFiltersOpen(false);
                        }}
                        className={`obs-touch-target-standard px-3 py-2 rounded-lg text-xs font-medium transition-colors min-h-[40px] flex items-center ${statusFilter === 'stopped' ? 'bg-slate-700 text-white shadow-sm' : 'bg-white/[0.03] text-slate-400 hover:text-slate-200 border border-white/[0.08]'}`}
                    >
                        Stopped ({stoppedCount})
                    </button>
                    <button
                        type="button"
                        onClick={() => {
                            setStatusFilter('attention');
                            setIsMobileFiltersOpen(false);
                        }}
                        className={`obs-touch-target-standard px-3 py-2 rounded-lg text-xs font-medium transition-colors min-h-[40px] flex items-center gap-1.5 ${statusFilter === 'attention' ? 'bg-red-600 text-white shadow-sm' : 'bg-white/[0.03] text-slate-400 hover:text-slate-200 border border-white/[0.08]'}`}
                    >
                        {attentionCount > 0 && <AlertTriangle size={12} className={statusFilter === 'attention' ? 'text-white' : 'text-red-400'} />}
                        Needs Attention ({attentionCount})
                    </button>
                    <button
                        type="button"
                        onClick={() => {
                            setStatusFilter('updates');
                            setIsMobileFiltersOpen(false);
                        }}
                        className={`obs-touch-target-standard px-3 py-2 rounded-lg text-xs font-medium transition-colors min-h-[40px] flex items-center gap-1.5 ${statusFilter === 'updates' ? 'bg-amber-600 text-white shadow-sm' : 'bg-white/[0.03] text-slate-400 hover:text-slate-200 border border-white/[0.08]'}`}
                    >
                        {updatesAvailableCount > 0 && <ArrowUpCircle size={12} className={statusFilter === 'updates' ? 'text-white' : 'text-amber-400'} />}
                        Updates ({updatesAvailableCount})
                    </button>
                </div>
            </div>

            {(searchQuery.trim().length > 0 || statusFilter !== 'all') && (
                <div className="flex items-center justify-between gap-3 text-xs text-slate-400 px-1">
                    <span>
                        Showing {sortedFilteredEntries.length} of {allEntries.length} services
                    </span>
                    <button
                        type="button"
                        onClick={() => {
                            setSearchQuery('');
                            setStatusFilter('all');
                            setIsMobileFiltersOpen(false);
                        }}
                        className="obs-touch-target-standard text-indigo-400 hover:text-indigo-300 font-medium underline underline-offset-2 min-h-[44px] sm:min-h-[40px] min-w-[44px] sm:min-w-[40px] px-2 py-1 flex items-center justify-center"
                    >
                        Reset filters
                    </button>
                </div>
            )}

            {filteredCoreServices.length > 0 && (
                <div>
                    <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider py-4 flex items-center gap-2">
                        <Server size={14} className="text-indigo-400" /> Core Platform
                    </h3>
                    {viewMode === 'card' ? (
                        <div aria-label="Core platform service grid" className={SERVICE_CARD_GRID}>
                            {filteredCoreServices.map(([name, data]) => renderServiceCard(name, data))}
                        </div>
                    ) : (
                        <div aria-label="Core platform service list" className="@container min-w-0 rounded-none shadow-none bg-transparent border-y border-white/[0.07] divide-y divide-white/[0.07]">
                            <div className={`hidden @[720px]:grid ${SERVICE_ROW_TRACKS} gap-x-2 items-center px-3 py-3 text-xs font-semibold uppercase tracking-wider text-slate-400`}>
                                <div>Service</div>
                                <div>Status &amp; Version</div>
                                <div>Endpoint</div>
                                <div className="text-right">Actions</div>
                            </div>
                            {filteredCoreServices.map(([name, data]) => renderServiceRow(name, data))}
                        </div>
                    )}
                </div>
            )}

            {filteredAppServices.length > 0 && (
                <div>
                    <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider py-4 flex items-center gap-2">
                        <Box size={14} className="text-emerald-400" /> Installed Applications
                    </h3>
                    {viewMode === 'card' ? (
                        <div aria-label="Installed application service grid" className={SERVICE_CARD_GRID}>
                            {filteredAppServices.map(([name, data]) => renderServiceCard(name, data))}
                        </div>
                    ) : (
                        <div aria-label="Installed application service list" className="@container min-w-0 rounded-none shadow-none bg-transparent border-y border-white/[0.07] divide-y divide-white/[0.07]">
                            <div className={`hidden @[720px]:grid ${SERVICE_ROW_TRACKS} gap-x-2 items-center px-3 py-3 text-xs font-semibold uppercase tracking-wider text-slate-400`}>
                                <div>Service</div>
                                <div>Status &amp; Version</div>
                                <div>Endpoint</div>
                                <div className="text-right">Actions</div>
                            </div>
                            {filteredAppServices.map(([name, data]) => renderServiceRow(name, data))}
                        </div>
                    )}
                </div>
            )}

            {allEntries.length === 0 && (
                <div className="text-center py-20">
                    <Box size={48} className="mx-auto text-slate-600 mb-4" />
                    <h3 className="text-lg font-semibold text-slate-300 mb-2">No Services Detected</h3>
                    <p className="text-slate-500 text-sm">Install applications from the Marketplace to see them here.</p>
                </div>
            )}

            {allEntries.length > 0 && sortedFilteredEntries.length === 0 && (
                <div role="status" className="text-center py-12 px-4 border-b border-white/[0.07]">
                    <Box size={36} className="mx-auto text-slate-500 mb-2" />
                    <h3 className="text-sm font-semibold text-slate-200 mb-1">No matching services found</h3>
                    <p className="text-xs text-slate-400 mb-3">
                        No services match &ldquo;{searchQuery}&rdquo; with filter &ldquo;{statusFilter}&rdquo;.
                    </p>
                    <button
                        type="button"
                        onClick={() => {
                            setSearchQuery('');
                            setStatusFilter('all');
                            setIsMobileFiltersOpen(false);
                        }}
                        className="obs-touch-target-standard px-4 py-2 bg-indigo-500/20 hover:bg-indigo-500 text-indigo-300 hover:text-white rounded-lg text-xs font-semibold transition-colors min-h-[44px] sm:min-h-[40px] min-w-[44px] sm:min-w-[40px] flex items-center justify-center"
                    >
                        Reset filters
                    </button>
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

            {stopConfirmService && (
                <StreamingDialog
                    name={`Stop ${stopConfirmService.name}`}
                    labelledBy="stop-service-title"
                    initialFocusRef={stopDialogCancelRef}
                    returnFocusRef={stopDialogReturnFocusRef}
                    onClose={() => setStopConfirmService(null)}
                >
                    <div className="glass-panel w-full max-w-md rounded-2xl p-6 border border-white/[0.08] bg-white/[0.04] shadow-2xl space-y-4">
                        <div className="flex items-center gap-3 text-rose-300">
                            <AlertCircle size={22} className="shrink-0" />
                            <h3 id="stop-service-title" className="text-base font-bold text-white">
                                Stop {stopConfirmService.name}?
                            </h3>
                        </div>
                        <p className="text-sm text-slate-300 leading-relaxed">
                            Stopping this service will terminate active processes and disconnect running clients. Daemon controls can restart it later.
                        </p>
                        <div className="flex justify-end gap-3 pt-2">
                            <button
                                ref={stopDialogCancelRef}
                                type="button"
                                onClick={() => setStopConfirmService(null)}
                                className="obs-touch-target-standard px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition-colors min-h-[40px]"
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={() => {
                                    const target = stopConfirmService;
                                    setStopConfirmService(null);
                                    void handleServiceControl(target.name, target.data, 'stop');
                                }}
                                className="obs-touch-target-standard px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-semibold transition-colors min-h-[40px]"
                            >
                                Confirm Stop
                            </button>
                        </div>
                    </div>
                </StreamingDialog>
            )}

            {restartConfirmService && (
                <StreamingDialog
                    name={`Restart ${restartConfirmService.name}`}
                    labelledBy="restart-service-title"
                    initialFocusRef={restartDialogCancelRef}
                    returnFocusRef={restartDialogReturnFocusRef}
                    onClose={() => setRestartConfirmService(null)}
                >
                    <div className="glass-panel w-full max-w-md rounded-2xl p-6 border border-white/[0.08] bg-white/[0.04] shadow-2xl space-y-4">
                        <div className="flex items-center gap-3 text-amber-300">
                            <AlertCircle size={22} className="shrink-0" />
                            <h3 id="restart-service-title" className="text-base font-bold text-white">
                                Restart {restartConfirmService.name}?
                            </h3>
                        </div>
                        <p className="text-sm text-slate-300 leading-relaxed">
                            Its last installation failed and recovery is unconfirmed. Restarting may interrupt clients or leave the service unavailable; review the failure logs first.
                        </p>
                        <div className="flex justify-end gap-3 pt-2">
                            <button ref={restartDialogCancelRef} type="button" onClick={() => setRestartConfirmService(null)} className="obs-touch-target-standard px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition-colors min-h-[40px]">Cancel</button>
                            <button
                                type="button"
                                onClick={() => {
                                    const target = restartConfirmService;
                                    setRestartConfirmService(null);
                                    void handleServiceControl(target.name, target.data, 'restart');
                                }}
                                className="obs-touch-target-standard px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold transition-colors min-h-[40px]"
                            >
                                Confirm Restart
                            </button>
                        </div>
                    </div>
                </StreamingDialog>
            )}

            {guardedStartConfirmService && (
                <StreamingDialog
                    name={`Start ${guardedStartConfirmService.name} (Guarded)`}
                    onClose={() => setGuardedStartConfirmService(null)}
                >
                    <div className="glass-panel w-full max-w-md rounded-2xl p-6 border border-white/[0.08] bg-white/[0.04] shadow-2xl space-y-4">
                        <div className="flex items-center gap-3 text-rose-300">
                            <AlertCircle size={22} className="shrink-0" />
                            <h3 id="guarded-start-title" className="text-base font-bold text-white">
                                Start {guardedStartConfirmService.name} (Guarded)?
                            </h3>
                        </div>
                        <div id="guarded-start-description" className="space-y-2 text-sm text-slate-300 leading-relaxed">
                            <p>
                                The previous installation of {guardedStartConfirmService.name} failed and state recovery or rollback is unconfirmed.
                            </p>
                            <p className="text-xs text-slate-400">
                                Starting this service in an unconfirmed recovery state may fail or cause unexpected behavior. Review failure logs before attempting manual operations. No safe recovery is guaranteed.
                            </p>
                        </div>
                        <div className="flex flex-wrap items-center justify-end gap-3 pt-2">
                            <button
                                type="button"
                                onClick={() => setGuardedStartConfirmService(null)}
                                className="obs-touch-target-standard px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg text-xs font-semibold transition-colors min-h-[44px] min-w-[44px]"
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={() => {
                                    const targetService = guardedStartConfirmService;
                                    setGuardedStartConfirmService(null);
                                    void handleServiceControl(targetService.name, targetService.data, 'start');
                                }}
                                className="obs-touch-target-standard px-4 py-2.5 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold transition-colors min-h-[44px] min-w-[44px]"
                            >
                                Start anyway
                            </button>
                        </div>
                    </div>
                </StreamingDialog>
            )}

            {ingressModalApp && (
                <Modal
                    isOpen
                    title={`${ingressModalApp} Ingress & Deploy`}
                    onClose={() => setIngressModalApp(null)}
                    returnFocusRef={ingressReturnFocusRef}
                    className="max-w-xl max-h-[85vh] rounded-3xl"
                >
                    <div className="space-y-4">
                        <ExternalAccessCard appName={ingressModalApp} />
                        <DeploymentStatus appName={ingressModalApp} isTriggered={true} />
                    </div>
                </Modal>
            )}
        </div>
    );
}
