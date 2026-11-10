import { Settings, Sparkles, DownloadCloud, AlertCircle, Eye, EyeOff, Key, Monitor, Globe, Clock, LayoutDashboard, Radio, HardDriveDownload, Shield, KeyRound, RefreshCw, UserCircle, Bell, Cpu, CheckCircle2, ArrowUpRight, Terminal, Layers, Save, Folder, ChevronLeft, ChevronRight } from 'lucide-react';
import {
    AI_MODELS,
    CLOUD_MODEL_IDS,
    DEFAULT_LOCAL_MODEL_ID,
    DEFAULT_LOCAL_RUNTIME_ID,
    LOCAL_AI_RUNTIMES,
    isForbiddenModelAlias,
    isLocalRuntimeId,
    parseStoredAiSettings,
    resolveProviderForModel,
} from '@/lib/ai-models';
import type { AIProviderID, LocalAIRuntimeID } from '@/lib/ai-models';
import { useCallback, useEffect, useId, useRef, useState, FormEvent } from 'react';
import useSWR from 'swr';
import dynamic from 'next/dynamic';
import GlassSelect, { type GlassSelectOption } from '@/components/ui/GlassSelect';
import FlowAiMarkdown from '@/components/ui/FlowAiMarkdown';

const BackupTab = dynamic(() => import('@/components/tabs/BackupTab'), { ssr: false });
const SecurityTab = dynamic(() => import('@/components/tabs/SecurityTab'), { ssr: false });
const ProfileTab = dynamic(() => import('@/components/tabs/ProfileTab'), { ssr: false });
const DashboardSettingsTab = dynamic(() => import('@/components/tabs/DashboardSettingsTab'), { ssr: false });
const OIDCClientsTab = dynamic(() => import('@/components/tabs/OIDCClientsTab'), { ssr: false });
const NotificationsSettingsTab = dynamic(() => import('@/components/tabs/NotificationsSettingsTab'), { ssr: false });
const McBrowserSettingsTab = dynamic(() => import('@/components/tabs/McBrowserSettingsTab'), { ssr: false });
import { useToast } from '@/contexts/ToastContext';
import { useSystemStore } from '@/store/useSystemStore';
import { useTranslations } from 'next-intl';
import { SettingsSkeleton } from '@/components/layout/SkeletonBox';
import { apiFetch } from '@/lib/fetcher';
import { isTransientLifecycleError, LIFECYCLE_RECOVERY_INTERVAL_MS, useLifecyclePollRecovery } from '@/hooks/useLifecyclePollRecovery';
import {
    getSystemUpdateView, isSystemUpdateLaunchTerminal, UPDATE_STATUS_POLL_MS, UPDATE_STATUS_MAX_AGE_MS, UPDATE_CHECK_MAX_AGE_MS,
    type SystemUpdateCheck, type SystemUpdateLaunch, type SystemUpdateStatus, type SystemUpdateView, type UpdateSnapshot,
} from '@/lib/system-update';

const PROVIDER_CARDS: {
    id: AIProviderID;
    label: string;
    subtitle: string;
    accent: string;
    activeBorder: string;
    activeBg: string;
}[] = [
    {
        id: 'gemini',
        label: 'Google Gemini',
        subtitle: 'Gemini 4 Argon',
        accent: 'text-amber-400',
        activeBorder: 'border-amber-500/40',
        activeBg: 'bg-amber-500/10',
    },
    {
        id: 'openai',
        label: 'OpenAI',
        subtitle: 'GPT-6 & GPT-6.1 Series',
        accent: 'text-emerald-400',
        activeBorder: 'border-emerald-500/40',
        activeBg: 'bg-emerald-500/10',
    },
    {
        id: 'anthropic',
        label: 'Anthropic Claude',
        subtitle: 'Claude Fable 5.1 & 5.5 Series',
        accent: 'text-orange-400',
        activeBorder: 'border-orange-500/40',
        activeBg: 'bg-orange-500/10',
    },
    {
        id: 'localai',
        label: 'Local Ollama / LM',
        subtitle: 'Self-Hosted Local Inference',
        accent: 'text-purple-400',
        activeBorder: 'border-purple-500/40',
        activeBg: 'bg-purple-500/10',
    },
];

const DEFAULT_DASHBOARD_OPTIONS: GlassSelectOption[] = [
    { value: 'overview', label: 'Overview / Metrics', description: 'Live hardware telemetry and system vitals' },
    { value: 'services', label: 'Services', description: 'Active systemd daemons and container processes' },
    { value: 'marketplace', label: 'Marketplace', description: 'One-click self-hosted application catalog' },
    { value: 'fileshare', label: 'Cloud Files', description: 'Browser-based storage and media explorer' },
    { value: 'ai', label: 'AI Chat', description: 'FlowAI autonomous infrastructure assistant' },
    { value: 'backups', label: 'Backups', description: 'Snapshots and disaster recovery archives' },
    { value: 'security', label: 'Security', description: 'Zero-trust policies, sessions, and firewall' },
];

const TIMEZONE_OPTIONS: GlassSelectOption[] = [
    { value: 'UTC', label: 'UTC', badge: 'Default', badgeVariant: 'indigo' },
    { value: 'America/New_York', label: 'America/New_York', badge: 'EST/EDT', badgeVariant: 'slate' },
    { value: 'America/Chicago', label: 'America/Chicago', badge: 'CST/CDT', badgeVariant: 'slate' },
    { value: 'America/Denver', label: 'America/Denver', badge: 'MST/MDT', badgeVariant: 'slate' },
    { value: 'America/Los_Angeles', label: 'America/Los_Angeles', badge: 'PST/PDT', badgeVariant: 'slate' },
    { value: 'Europe/London', label: 'Europe/London', badge: 'GMT/BST', badgeVariant: 'slate' },
    { value: 'Europe/Berlin', label: 'Europe/Berlin', badge: 'CET/CEST', badgeVariant: 'slate' },
    { value: 'Asia/Tokyo', label: 'Asia/Tokyo', badge: 'JST', badgeVariant: 'slate' },
    { value: 'Australia/Sydney', label: 'Australia/Sydney', badge: 'AEST/AEDT', badgeVariant: 'slate' },
];

const LANGUAGE_OPTIONS: GlassSelectOption[] = [
    { value: 'en', label: 'English', badge: 'EN', badgeVariant: 'indigo' },
    { value: 'zh', label: '中文 (Chinese)', badge: 'ZH', badgeVariant: 'slate' },
    { value: 'es', label: 'Español (Spanish)', badge: 'ES', badgeVariant: 'slate' },
    { value: 'de', label: 'Deutsch (German)', badge: 'DE', badgeVariant: 'slate' },
    { value: 'fr', label: 'Français (French)', badge: 'FR', badgeVariant: 'slate' },
    { value: 'dk', label: 'Dansk (Danish)', badge: 'DK', badgeVariant: 'slate' },
];

const UPDATE_CHANNEL_OPTIONS: GlassSelectOption[] = [
    {
        value: 'stable',
        label: 'Stable',
        description: 'Verified production releases with atomic rollback protection',
        badge: 'Recommended',
        badgeVariant: 'emerald',
        dotColor: 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.85)]',
    },
    {
        value: 'nightly',
        label: 'Nightly',
        description: 'Bleeding-edge builds directly from the nightly branch',
        badge: 'Unstable',
        badgeVariant: 'amber',
        dotColor: 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.85)]',
    },
];

const UPDATE_CHANNEL_PILL_STYLES: Record<string, string> = {
    stable: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
    nightly: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
};

const normalizeUpdateChannel = (channel: unknown): string =>
    channel === 'nightly' || channel === 'experimental' ? 'nightly' : 'stable';

const SETTINGS_DEFAULTS = {
    aiModel: 'gemini-4-argon',
    localRuntime: DEFAULT_LOCAL_RUNTIME_ID as string,
    localModel: DEFAULT_LOCAL_MODEL_ID,
    systemPrompt: 'You are FlowAI, a highly intelligent infrastructure assistant connected to a local Next.js + Go Nexus environment. Always prioritize safe and performant configurations.',
    geminiApiKey: '',
    openaiApiKey: '',
    anthropicApiKey: '',
    lmStudioEndpoint: '',
    ollamaEndpoint: '',
    anthropicEndpoint: '',
    timezone: 'UTC',
    updateChannel: 'stable',
    defaultDashboard: 'overview',
    baseDomain: '',
};

function readSettingsValues(data?: Record<string, string>): typeof SETTINGS_DEFAULTS {
    const values = { ...SETTINGS_DEFAULTS };
    for (const key of Object.keys(values) as (keyof typeof values)[]) {
        if (typeof data?.[key] === 'string') values[key] = data[key];
    }
    const parsedAi = parseStoredAiSettings(data);
    values.aiModel = parsedAi.aiModel;
    values.localRuntime = parsedAi.localRuntime;
    values.localModel = parsedAi.localModel;
    values.updateChannel = normalizeUpdateChannel(values.updateChannel);
    return values;
}

async function fetchUpdateSnapshot<Value>(url: string): Promise<UpdateSnapshot<Value>> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    try {
        const response = await apiFetch(url, { signal: controller.signal, cache: 'no-store' });
        const data = await response.json().catch(() => null);
        if (!response.ok) throw Object.assign(new Error(data?.error || data?.message || `Update request failed (${response.status})`), { status: response.status });
        if (!data || typeof data !== 'object' || Array.isArray(data)) throw Object.assign(new Error('Invalid update response'), { status: response.status });
        return { ...data, checkedAt: Date.now() };
    } finally {
        clearTimeout(timeout);
    }
}

const ACTIVE_UPDATE_JOB_STORAGE_KEY = 'aetherflow_active_update_job_unit';
const DEFAULT_UPDATE_POLL_INTERVAL_MS = process.env.NODE_ENV === 'test' ? 20 : 1500;
const DEFAULT_UPDATE_MAX_POLL_ATTEMPTS = 40;
const VALID_SELF_UPDATE_JOB_UNIT_PATTERN =
    /^aetherflow-self-update-[a-z0-9-]+-[a-z0-9-]+-[a-f0-9]{8,32}\.service$/;

type UpdateJobOutcome = 'idle' | 'pending' | 'success' | 'error';

interface UpdateStatusPayload {
    status?: string;
    completed?: boolean;
    success?: boolean;
    job_unit?: string;
    active_job_unit?: string;
    action?: string | null;
    channel?: string;
    engine?: string;
    error?: string | null;
    exit_code?: number | null;
    message?: string;
}

interface SettingsTabProps {
    updatePollIntervalMs?: number;
    updateMaxPollAttempts?: number;
}

function getSettingsUpdateView(input: Parameters<typeof getSystemUpdateView>[0] & {
    status?: UpdateSnapshot<SystemUpdateStatus & UpdateStatusPayload>;
    statusError?: { status?: number; message: string };
    checkError?: { status?: number; message: string };
    trackedJobUnit: string;
    jobCheckedAt: number | null;
    updateOutcome: UpdateJobOutcome;
    updateMessage: string;
    isUpdating: boolean;
}): SystemUpdateView {
    const { status: updateStatus, check: updateData, statusError: updateStatusError, checkError: updateError,
        trackedJobUnit, jobCheckedAt, updateOutcome, updateMessage, isUpdating, now } = input;
    let view = getSystemUpdateView(input);
    if (updateStatus?.status === 'idle' && updateStatus.state === 'idle' && updateStatus.job_unit === ''
        && updateStatus.active_job_unit === '' && updateStatus.completed === true && !updateStatus.error && !updateStatusError
        && updateStatus.checkedAt <= now && now - updateStatus.checkedAt < UPDATE_STATUS_MAX_AGE_MS) {
        const versionsKnown = [updateData?.currentVersion, updateData?.latestVersion].every(version =>
            typeof version === 'string' && /^(?:v?\d[\w.+-]*|(?:nightly|experimental)-[0-9a-f]{7,40})$/i.test(version)
        );
        const checkVerified = Boolean(updateData && !updateError && !updateData.error && versionsKnown
            && updateData.checkedAt <= now && now - updateData.checkedAt < UPDATE_CHECK_MAX_AGE_MS
            && (!updateData.channel || normalizeUpdateChannel(updateData.channel) === input.savedChannel));
        const available = checkVerified && updateData?.updateAvailable === true
            && updateData.currentVersion !== updateData.latestVersion;
        view = {
            ...view, kind: available ? 'available' : 'unknown', isLatest: false, updateAvailable: available,
            canLaunch: available && !view.isBusy && !input.settingsPending && input.channel === input.savedChannel,
            message: available ? `A verified update to ${updateData?.latestVersion} is available.`
                : 'Independent runtime verification is unavailable; latest-release status is not confirmed.',
        };
    }
    const permanentError = [updateStatusError, updateError].find(error => error && !isTransientLifecycleError(error));
    if (permanentError) {
        return { ...view, kind: 'failed', canLaunch: false, isLatest: false,
            message: `${permanentError.message} ${permanentError.status === 401 || permanentError.status === 403
                ? 'Restore authorization or authenticate again, then check for updates.'
                : 'Update observation is unavailable. Check for updates to retry; no idle state is confirmed.'}` };
    }
    if (trackedJobUnit) {
        const stale = jobCheckedAt !== null && now - jobCheckedAt >= UPDATE_STATUS_MAX_AGE_MS;
        return { ...view, kind: updateOutcome === 'error' ? 'failed' : stale ? 'reconnecting' : 'running',
            message: stale && updateOutcome !== 'error' ? `Update receipt is stale; outcome remains unverified. ${updateMessage}` : updateMessage,
            isLatest: false, isBusy: true, canLaunch: false };
    }
    return {
        ...view,
        kind: isUpdating ? 'running' : view.kind,
        message: isUpdating ? updateMessage : view.message,
        isLatest: !isUpdating && view.isLatest,
        isBusy: view.isBusy || isUpdating,
        canLaunch: view.canLaunch && !isUpdating,
    };
}

function isValidSelfUpdateJobUnit(jobUnit: string): boolean {
    return VALID_SELF_UPDATE_JOB_UNIT_PATTERN.test(jobUnit.trim());
}

function advertisedUpdateJob(payload: UpdateStatusPayload | undefined): string {
    const unit = payload?.active_job_unit || (payload?.completed === false ? payload.job_unit : '');
    if (typeof unit !== 'string' || !isValidSelfUpdateJobUnit(unit)) return '';
    const action = unit.replace('aetherflow-self-update-', '').split('-')[0];
    return payload?.action != null && payload.action !== action ? '' : unit;
}

function readStoredUpdateJobUnit(): string {
    if (typeof window === 'undefined') return '';
    try {
        const storedUnit = window.sessionStorage.getItem(ACTIVE_UPDATE_JOB_STORAGE_KEY)?.trim() || '';
        if (!storedUnit) return '';
        if (!isValidSelfUpdateJobUnit(storedUnit)) {
            window.sessionStorage.removeItem(ACTIVE_UPDATE_JOB_STORAGE_KEY);
            return '';
        }
        return storedUnit;
    } catch {
        return '';
    }
}

function writeStoredUpdateJobUnit(jobUnit: string): void {
    if (typeof window === 'undefined') return;
    try {
        const cleanUnit = jobUnit.trim();
        if (cleanUnit && isValidSelfUpdateJobUnit(cleanUnit)) {
            window.sessionStorage.setItem(ACTIVE_UPDATE_JOB_STORAGE_KEY, cleanUnit);
        } else {
            window.sessionStorage.removeItem(ACTIVE_UPDATE_JOB_STORAGE_KEY);
        }
    } catch {
        return;
    }
}

function evaluateUpdateStatusPayload(
    payload: UpdateStatusPayload | null | undefined,
    expectedJobUnit: string
): { isTerminal: boolean; isSuccess: boolean; message: string; confirmed?: boolean } {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        return { isTerminal: true, isSuccess: false, message: 'Update job returned an invalid status payload.' };
    }
    const status = typeof payload.status === 'string' ? payload.status.trim().toLowerCase() : '';
    const jobUnit = typeof payload.job_unit === 'string' ? payload.job_unit.trim() : '';
    const error = typeof payload.error === 'string' ? payload.error.trim() : '';
    const message = typeof payload.message === 'string' ? payload.message.trim() : '';
    const action = jobUnit.replace('aetherflow-self-update-', '').split('-')[0];
    if (jobUnit !== expectedJobUnit || !isValidSelfUpdateJobUnit(jobUnit)
        || (payload.action != null && payload.action !== action)) {
        return { isTerminal: true, isSuccess: false, message: 'Update status returned a missing or mismatched job unit.' };
    }
    if (['initiated', 'queued', 'launching', 'running'].includes(status) && payload.completed === false
        && payload.success !== true && !error && payload.exit_code == null) {
        return { isTerminal: false, isSuccess: false, message: message || `Updating system (${jobUnit})...` };
    }
    if (status === 'succeeded' && payload.completed === true && payload.success === true && payload.exit_code === 0 && !error) {
        return {
            isTerminal: true, isSuccess: true, confirmed: true,
            message: message || `System update completed successfully (${jobUnit}).`,
        };
    }
    const exitCode = typeof payload.exit_code === 'number' ? ` (exit code ${payload.exit_code})` : '';
    return {
        isTerminal: true, isSuccess: false,
        confirmed: status === 'failed' && payload.completed === true && payload.success === false
            && payload.exit_code !== 0 && Boolean(error),
        message: error || message || (status === 'failed'
            ? `System update failed${exitCode}.`
            : 'Update job status is unknown, unavailable, or inconsistent.'),
    };
}

export default function SettingsTab({
    updatePollIntervalMs = DEFAULT_UPDATE_POLL_INTERVAL_MS,
    updateMaxPollAttempts = DEFAULT_UPDATE_MAX_POLL_ATTEMPTS,
}: SettingsTabProps = {}) {
    const t = useTranslations('Settings');
    const { addToast } = useToast();
    const {
        theme,
        language,
        setLanguage,
        ambientColor1,
        ambientColor2,
        setActiveTab: setActiveMainTab,
        activeSettingsTab: activeTab,
        setActiveSettingsTab: setActiveTab,
    } = useSystemStore();

    const settingsFormId = useId();
    const settingsNavigationRef = useRef<HTMLElement>(null);
    const settingsRailManualNavigationRef = useRef(false);
    const [canScrollLeft, setCanScrollLeft] = useState(false);
    const [canScrollRight, setCanScrollRight] = useState(false);
    const [hasOverflow, setHasOverflow] = useState(false);

    const handleRailManualNavigation = () => {
        settingsRailManualNavigationRef.current = true;
    };

    const handleScrollRail = (direction: 'left' | 'right') => {
        const navigation = settingsNavigationRef.current;
        if (!navigation) return;
        settingsRailManualNavigationRef.current = true;
        const scrollDelta = direction === 'left' ? -200 : 200;
        navigation.scrollBy({ left: scrollDelta, behavior: 'smooth' });
    };

    const { data: settingsData, isLoading, mutate: mutateSettings } = useSWR<Record<string, string>>(
        '/api/v1/auth/settings'
    );
    useEffect(() => {
        const navigation = settingsNavigationRef.current;
        if (!navigation) return;
        settingsRailManualNavigationRef.current = false;
        const updateScrollState = () => {
            const scrollOverflow = navigation.scrollWidth > navigation.clientWidth + 1;
            setHasOverflow(scrollOverflow);
            setCanScrollLeft(navigation.scrollLeft > 1);
            setCanScrollRight(navigation.scrollLeft + navigation.clientWidth < navigation.scrollWidth - 1);
        };
        const updateStateAndAlignment = () => {
            const focusedElement = navigation.ownerDocument.activeElement;
            const focusedButton = focusedElement instanceof HTMLButtonElement && navigation.contains(focusedElement) ? focusedElement : null;
            const alignmentButton = focusedButton ?? navigation.querySelector<HTMLButtonElement>('[aria-current="page"]');
            const navigationBounds = navigation.getBoundingClientRect();
            if (alignmentButton && navigationBounds.width > 0 && !settingsRailManualNavigationRef.current) {
                const alignmentBounds = alignmentButton.getBoundingClientRect();
                if (alignmentBounds.left < navigationBounds.left) {
                    navigation.scrollLeft += alignmentBounds.left - navigationBounds.left;
                } else if (alignmentBounds.right > navigationBounds.right) {
                    navigation.scrollLeft += alignmentBounds.right - navigationBounds.right;
                }
            }
            updateScrollState();
        };
        updateStateAndAlignment();
        const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(updateStateAndAlignment);
        observer?.observe(navigation);
        navigation.querySelectorAll('button').forEach((buttonElement) => observer?.observe(buttonElement));
        window.addEventListener('resize', updateStateAndAlignment);
        navigation.addEventListener('scroll', updateScrollState, { passive: true });
        return () => {
            observer?.disconnect();
            window.removeEventListener('resize', updateStateAndAlignment);
            navigation.removeEventListener('scroll', updateScrollState);
        };
    }, [activeTab, isLoading, language]);

    const [settingsDraft, setSettingsDraft] = useState<Partial<typeof SETTINGS_DEFAULTS>>({});
    const savedSettings = readSettingsValues(settingsData);
    const {
        aiModel: model,
        localRuntime: rawLocalRuntime,
        localModel,
        systemPrompt: prompt,
        geminiApiKey: apiKey,
        openaiApiKey,
        anthropicApiKey,
        lmStudioEndpoint,
        ollamaEndpoint,
        anthropicEndpoint,
        timezone,
        updateChannel,
        defaultDashboard,
        baseDomain,
    } = { ...savedSettings, ...settingsDraft };
    const localRuntime: LocalAIRuntimeID = isLocalRuntimeId(rawLocalRuntime)
        ? rawLocalRuntime
        : DEFAULT_LOCAL_RUNTIME_ID;
    const effectiveLocalModel =
        localModel.trim() && !isForbiddenModelAlias(localModel)
            ? localModel.trim()
            : LOCAL_AI_RUNTIMES.find((rt) => rt.id === localRuntime)?.defaultModel || DEFAULT_LOCAL_MODEL_ID;

    const setField = (key: keyof typeof SETTINGS_DEFAULTS, value: string) =>
        setSettingsDraft(current => ({ ...current, [key]: value }));
    const setModel = (value: string) => {
        if (isLocalRuntimeId(value)) {
            const rtDef = LOCAL_AI_RUNTIMES.find((rt) => rt.id === value);
            const nextLocalModel =
                localModel.trim() && !isForbiddenModelAlias(localModel)
                    ? localModel.trim()
                    : rtDef?.defaultModel || DEFAULT_LOCAL_MODEL_ID;
            setSettingsDraft(current => ({
                ...current,
                localRuntime: value,
                localModel: nextLocalModel,
                aiModel: nextLocalModel,
            }));
            return;
        }
        setSettingsDraft(current => ({
            ...current,
            aiModel: value,
            ...(!CLOUD_MODEL_IDS.includes(value) && !isForbiddenModelAlias(value)
                ? { localModel: value }
                : {}),
        }));
    };
    const setLocalRuntime = (runtimeId: LocalAIRuntimeID) => {
        const rtDef = LOCAL_AI_RUNTIMES.find((rt) => rt.id === runtimeId);
        const nextLocalModel =
            localModel.trim() && !isForbiddenModelAlias(localModel)
                ? localModel.trim()
                : rtDef?.defaultModel || DEFAULT_LOCAL_MODEL_ID;
        setSettingsDraft(current => ({
            ...current,
            localRuntime: runtimeId,
            localModel: nextLocalModel,
            aiModel: nextLocalModel,
        }));
    };
    const setLocalModel = (value: string) => {
        setSettingsDraft(current => ({
            ...current,
            localModel: value,
            aiModel: value,
        }));
    };
    const setPrompt = (value: string) => setField('systemPrompt', value);
    const setApiKey = (value: string) => setField('geminiApiKey', value);
    const setOpenaiApiKey = (value: string) => setField('openaiApiKey', value);
    const setAnthropicApiKey = (value: string) => setField('anthropicApiKey', value);
    const setLmStudioEndpoint = (value: string) => setField('lmStudioEndpoint', value);
    const setOllamaEndpoint = (value: string) => setField('ollamaEndpoint', value);
    const setAnthropicEndpoint = (value: string) => setField('anthropicEndpoint', value);
    const setTimezone = (value: string) => setField('timezone', value);
    const setUpdateChannel = (value: string) => setField('updateChannel', value);
    const setDefaultDashboard = (value: string) => setField('defaultDashboard', value);
    const setBaseDomain = (value: string) => setField('baseDomain', value);

    // UI state
    const [showApiKey, setShowApiKey] = useState(false);
    const [showOpenaiApiKey, setShowOpenaiApiKey] = useState(false);
    const [showAnthropicApiKey, setShowAnthropicApiKey] = useState(false);
    const [isSaving, setIsSaving] = useState(false);
    const [updateLaunch, setUpdateLaunch] = useState<SystemUpdateLaunch | null>(null);
    const [launchError, setLaunchError] = useState('');
    const launchRequestInFlight = useRef(false);
    const [updateNow, setUpdateNow] = useState(Date.now);
    const [isTesting, setIsTesting] = useState(false);
    const [isUpdating, setIsUpdating] = useState(() => Boolean(readStoredUpdateJobUnit()));
    const [updateMessage, setUpdateMessage] = useState(() => {
        const storedUnit = readStoredUpdateJobUnit();
        return storedUnit ? `Recovering update status (${storedUnit})...` : '';
    });
    const [updateOutcome, setUpdateOutcome] = useState<UpdateJobOutcome>(() =>
        readStoredUpdateJobUnit() ? 'pending' : 'idle'
    );

    const isMountedRef = useRef(true);
    const activePollIdRef = useRef(0);
    const pollingJobUnitRef = useRef('');
    const pollAbortControllerRef = useRef<AbortController | null>(null);
    const pollRetryTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    const pollTimeoutRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    const launchTimeoutRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
    const launchAbortControllerRef = useRef<AbortController | null>(null);
    const [trackedJobUnit, setTrackedJobUnit] = useState(readStoredUpdateJobUnit);
    const [jobCheckedAt, setJobCheckedAt] = useState<number | null>(null);
    const stoppedJobRef = useRef('');
    const settledJobRef = useRef('');

    useEffect(() => {
        isMountedRef.current = true;
        return () => {
            isMountedRef.current = false;
            activePollIdRef.current += 1;
            pollingJobUnitRef.current = '';
            pollAbortControllerRef.current?.abort();
            if (pollRetryTimerRef.current) clearTimeout(pollRetryTimerRef.current);
            clearTimeout(pollTimeoutRef.current);
            clearTimeout(launchTimeoutRef.current);
            launchAbortControllerRef.current?.abort();
        };
    }, []);

    const handleTestConnection = async (providerOverride?: string, extraPayload?: Record<string, string>) => {
        const testProvider = providerOverride || resolveProviderForModel(model);
        const trimmedAnthropicEp = anthropicEndpoint.trim();

        let resolvedTestModel = extraPayload?.model?.trim() || '';
        if (!resolvedTestModel) {
            if (testProvider === 'anthropic' || testProvider === 'anthropic-local') {
                if (
                    settingsDraft.localModel !== undefined &&
                    settingsDraft.localModel.trim() !== '' &&
                    !isForbiddenModelAlias(settingsDraft.localModel)
                ) {
                    resolvedTestModel = settingsDraft.localModel.trim();
                } else if (
                    resolveProviderForModel(model) === 'localai' &&
                    localRuntime === 'anthropic-local'
                ) {
                    resolvedTestModel = effectiveLocalModel;
                } else if (model.startsWith('claude-')) {
                    resolvedTestModel = model;
                } else {
                    resolvedTestModel = 'claude-sonnet-5-5';
                }
            } else if (
                testProvider === 'localai' ||
                testProvider === 'lm-studio' ||
                testProvider === 'ollama'
            ) {
                resolvedTestModel = localModel.trim() || effectiveLocalModel;
            } else if (testProvider === 'openai') {
                resolvedTestModel = model.startsWith('gpt-') ? model : 'gpt-6.1-sol';
            } else {
                resolvedTestModel = model.startsWith('gemini-') ? model : 'gemini-4-argon';
            }
        }

        if (isForbiddenModelAlias(resolvedTestModel)) {
            addToast(
                'Invalid model ID: provider or locality aliases cannot be used as inference model IDs.',
                'error'
            );
            return;
        }

        const anthropicOverrides =
            (testProvider === 'anthropic' || testProvider === 'anthropic-local') && trimmedAnthropicEp
                ? {
                      endpoint: trimmedAnthropicEp,
                      anthropic_endpoint: trimmedAnthropicEp,
                  }
                : {};

        setIsTesting(true);
        try {
            const res = await apiFetch('/api/v1/admin/settings/test-ai', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    gemini_api_key: apiKey,
                    openai_api_key: openaiApiKey,
                    anthropic_api_key: anthropicApiKey,
                    provider: testProvider,
                    model: resolvedTestModel,
                    ...anthropicOverrides,
                    ...extraPayload,
                }),
            });
            const data = await res.json();
            if (res.ok) {
                addToast(data.message || `${testProvider} connection successful!`, 'success');
            } else {
                addToast(data.error || data.message || 'Remote connection refused.', 'error');
            }
        } catch (_err) {
            addToast('API dispatch failure: Remote connection test.', 'error');
        } finally {
            setIsTesting(false);
        }
    };

    const { data: updateData, error: updateError, isValidating: isCheckingUpdate, mutate: mutateUpdateData } = useSWR<UpdateSnapshot<SystemUpdateCheck & UpdateStatusPayload>>(
        settingsData ? ['/api/v1/auth/system/update/check', savedSettings.updateChannel] as const : null,
        async ([url, channel]: readonly [string, string]) => {
            const data = await fetchUpdateSnapshot<SystemUpdateCheck & UpdateStatusPayload>(url);
            return { ...data, channel: normalizeUpdateChannel(data.channel || channel) };
        },
        {
            refreshInterval: 60000, shouldRetryOnError: false,
            revalidateOnFocus: false, revalidateOnReconnect: false,
            onSuccess: () => setUpdateNow(Date.now()),
        }
    );
    useLifecyclePollRecovery(`/api/v1/auth/system/update/check:${savedSettings.updateChannel}`, updateError, mutateUpdateData);

    const { data: updateStatus, error: updateStatusError, mutate: mutateUpdateStatus } = useSWR<UpdateSnapshot<SystemUpdateStatus & UpdateStatusPayload>>(
        '/api/v1/auth/system/update/status',
        fetchUpdateSnapshot<SystemUpdateStatus & UpdateStatusPayload>,
        {
            refreshInterval: UPDATE_STATUS_POLL_MS,
            dedupingInterval: 1000,
            refreshWhenHidden: true,
            refreshWhenOffline: true,
            revalidateOnFocus: false,
            revalidateOnReconnect: false,
            shouldRetryOnError: false,
            onSuccess: status => {
                setUpdateNow(Date.now());
                setUpdateLaunch(current => isSystemUpdateLaunchTerminal(current, status, Date.now()) ? null : current);
            },
        }
    );
    useLifecyclePollRecovery('/api/v1/auth/system/update/status', updateStatusError, mutateUpdateStatus, UPDATE_STATUS_POLL_MS);

    const monitorUpdateJob = useCallback(
        async function monitorJob(rawJobUnit: string, initialMessage?: string): Promise<void> {
            const jobUnit = rawJobUnit.trim();
            if (!isMountedRef.current) return;
            if (!isValidSelfUpdateJobUnit(jobUnit)) {
                writeStoredUpdateJobUnit('');
                pollingJobUnitRef.current = '';
                setTrackedJobUnit('');
                setUpdateLaunch(null);
                setUpdateOutcome('error');
                setUpdateMessage('Update initiation returned an invalid or missing self-update job unit.');
                setIsUpdating(false);
                return;
            }
            if (pollRetryTimerRef.current) clearTimeout(pollRetryTimerRef.current);
            clearTimeout(pollTimeoutRef.current);
            pollAbortControllerRef.current?.abort();
            const pollId = ++activePollIdRef.current;
            pollingJobUnitRef.current = jobUnit;
            stoppedJobRef.current = '';
            setTrackedJobUnit(jobUnit);
            writeStoredUpdateJobUnit(jobUnit);
            setIsUpdating(true);
            setUpdateOutcome('pending');
            setUpdateMessage(initialMessage || `Recovering update status (${jobUnit})...`);
            const maxAttempts = Number.isFinite(updateMaxPollAttempts)
                ? Math.max(1, Math.floor(updateMaxPollAttempts)) : DEFAULT_UPDATE_MAX_POLL_ATTEMPTS;
            const intervalMs = Number.isFinite(updatePollIntervalMs)
                ? Math.max(5, updatePollIntervalMs) : DEFAULT_UPDATE_POLL_INTERVAL_MS;
            const poll = async (attempt: number): Promise<void> => {
                if (!isMountedRef.current || activePollIdRef.current !== pollId) return;
                const controller = new AbortController();
                pollAbortControllerRef.current = controller;
                const timeout = setTimeout(() => controller.abort(), 10000);
                pollTimeoutRef.current = timeout;
                try {
                    const response = await apiFetch(
                        `/api/v1/auth/system/update/status?job_unit=${encodeURIComponent(jobUnit)}`,
                        { signal: controller.signal, cache: 'no-store' }
                    );
                    const payload: UpdateStatusPayload | null = await response.json().catch(() => null);
                    if (!isMountedRef.current || activePollIdRef.current !== pollId) return;
                    if (!response.ok) {
                        throw Object.assign(new Error(payload?.error || payload?.message
                            || `Failed to query update job status (HTTP ${response.status}).`), { status: response.status });
                    }
                    const evaluation = evaluateUpdateStatusPayload(payload, jobUnit);
                    if (evaluation.confirmed) {
                        settledJobRef.current = jobUnit;
                        writeStoredUpdateJobUnit('');
                        pollingJobUnitRef.current = '';
                        setTrackedJobUnit('');
                        setJobCheckedAt(Date.now());
                        setUpdateLaunch(null);
                        setLaunchError(evaluation.isSuccess ? '' : evaluation.message);
                        setUpdateOutcome(evaluation.isSuccess ? 'success' : 'error');
                        setUpdateMessage(evaluation.message);
                        setIsUpdating(false);
                        if (evaluation.isSuccess) {
                            void mutateUpdateData().catch(() => undefined);
                            void mutateUpdateStatus().catch(() => undefined);
                        }
                        return;
                    }
                    if (evaluation.isTerminal) {
                        setUpdateOutcome('error');
                        setIsUpdating(false);
                        setUpdateMessage(`${evaluation.message} The job identity is retained; waiting for a verified receipt before another update.`);
                        pollRetryTimerRef.current = setTimeout(() => void poll(1), LIFECYCLE_RECOVERY_INTERVAL_MS);
                        return;
                    }
                    setJobCheckedAt(Date.now());
                    setIsUpdating(true);
                    setUpdateOutcome('pending');
                    setUpdateMessage(evaluation.message);
                } catch (error) {
                    if (!isMountedRef.current || activePollIdRef.current !== pollId) return;
                    if (!isTransientLifecycleError(error)) {
                        stoppedJobRef.current = jobUnit;
                        setIsUpdating(false);
                        setUpdateOutcome('error');
                        const status = (error as { status?: number }).status;
                        setUpdateMessage(`${(error as Error).message} ${status === 401 || status === 403
                            ? 'Restore authorization and check for updates to resume observation.'
                            : 'Automatic observation stopped; check for updates to retry.'} The tracked job outcome remains unverified.`);
                        return;
                    }
                    setUpdateMessage(`Reconnecting automatically to update status (${jobUnit}); no duplicate update will be submitted.`);
                } finally {
                    clearTimeout(timeout);
                }
                if (!isMountedRef.current || activePollIdRef.current !== pollId) return;
                pollRetryTimerRef.current = setTimeout(() => void poll(attempt < maxAttempts ? attempt + 1 : 1), intervalMs);
            };
            await poll(1);
        },
        [mutateUpdateData, mutateUpdateStatus, updateMaxPollAttempts, updatePollIntervalMs]
    );

    const recoverableJobUnit = advertisedUpdateJob(updateStatus) || advertisedUpdateJob(updateData);

    useEffect(() => {
        const jobUnit = trackedJobUnit || readStoredUpdateJobUnit() || recoverableJobUnit;
        if (jobUnit && jobUnit !== settledJobRef.current && pollingJobUnitRef.current !== jobUnit) void monitorUpdateJob(jobUnit);
    }, [trackedJobUnit, recoverableJobUnit, monitorUpdateJob]);

    useEffect(() => {
        const timer = setInterval(() => setUpdateNow(Date.now()), UPDATE_STATUS_POLL_MS);
        return () => clearInterval(timer);
    }, []);

    useEffect(() => {
        if (updateStatus?.state === 'complete') void mutateUpdateData().catch(() => undefined);
    }, [updateStatus?.state, updateStatus?.operationId, updateStatus?.currentVersion, mutateUpdateData]);

    const updateViewInput = {
        status: updateStatus, check: updateData, statusError: updateStatusError, checkError: updateError,
        launch: updateLaunch, launchError, channel: updateChannel,
        savedChannel: savedSettings.updateChannel, settingsPending: isSaving, now: updateNow,
        trackedJobUnit, jobCheckedAt, updateOutcome, updateMessage, isUpdating,
    };
    const updateView = getSettingsUpdateView(updateViewInput);

    if (isLoading) return <SettingsSkeleton />;

    const activeProvider = resolveProviderForModel(model);
    const activeModelDef = Object.values(AI_MODELS).flat().find(candidateModel => candidateModel.id === model) || {
        id: model,
        name: model,
        tier: activeProvider === 'localai' ? ('local' as const) : ('latest' as const),
    };

    const isActiveProviderConfigured =
        activeProvider === 'gemini'
            ? Boolean(apiKey)
            : activeProvider === 'openai'
            ? Boolean(openaiApiKey)
            : activeProvider === 'anthropic'
            ? Boolean(anthropicApiKey)
            : Boolean(lmStudioEndpoint || ollamaEndpoint || anthropicEndpoint);

    const activeEndpointSummary =
        activeProvider === 'gemini'
            ? 'generativelanguage.googleapis.com'
            : activeProvider === 'openai'
            ? 'api.openai.com/v1'
            : activeProvider === 'anthropic'
            ? anthropicEndpoint || 'api.anthropic.com/v1'
            : localRuntime === 'ollama'
            ? ollamaEndpoint || 'http://localhost:11434'
            : localRuntime === 'anthropic-local'
            ? anthropicEndpoint || 'http://localhost:8080'
            : lmStudioEndpoint || 'http://localhost:1234';

    const handleSave = async (event?: FormEvent) => {
        if (event) event.preventDefault();
        const isLocalActive = activeProvider === 'localai';
        const resolvedModelForSave = isLocalActive ? localModel.trim() : model.trim();
        if (isForbiddenModelAlias(resolvedModelForSave)) {
            addToast(
                'Invalid AI model ID: specify an installed model ID instead of a provider or runtime alias.',
                'error'
            );
            return;
        }

        setIsSaving(true);

        const submittedSettings = { ...savedSettings, ...settingsDraft };
        const payload = {
            aiModel: resolvedModelForSave,
            localModel: effectiveLocalModel,
            localProvider: localRuntime,
            systemPrompt: prompt,
            geminiApiKey: apiKey,
            openaiApiKey: openaiApiKey,
            anthropicApiKey: anthropicApiKey,
            lmStudioEndpoint: lmStudioEndpoint,
            ollamaEndpoint: ollamaEndpoint,
            anthropicEndpoint: anthropicEndpoint,
            language: language,
            theme: theme,
            ambientColor1: ambientColor1,
            ambientColor2: ambientColor2,
            timezone: timezone,
            updateChannel: updateChannel,
            defaultDashboard: defaultDashboard,
            baseDomain: baseDomain.trim(),
            setupCompleted: true
        };

        try {
            const res = await apiFetch('/api/v1/admin/settings', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                addToast('Configuration synced to AetherFlow Engine', 'success');
                await mutateSettings().then((data) => {
                    if (!data) return;
                    setSettingsDraft(current => {
                        const next = { ...current };
                        for (const key of Object.keys(next) as (keyof typeof SETTINGS_DEFAULTS)[]) {
                            if (next[key] === submittedSettings[key]) delete next[key];
                        }
                        return next;
                    });
                }, () => undefined);
            } else {
                const errData = await res.json().catch(() => ({ message: `HTTP ${res.status}` }));
                addToast(errData.message || errData.error || `Configuration sync rejected (${res.status})`, 'error');
            }
        } catch (_err) {
            addToast('API dispatch failure: Configuration flush.', 'error');
        } finally {
            setIsSaving(false);
        }
    };

    const handleRunUpdate = async (startedAt: number) => {
        if (launchRequestInFlight.current || pollingJobUnitRef.current || !getSettingsUpdateView({ ...updateViewInput, now: startedAt }).canLaunch) return;
        launchRequestInFlight.current = true;
        setLaunchError('');
        setUpdateMessage('');
        setUpdateOutcome('idle');
        setUpdateLaunch({
            state: 'launching', startedAt, operationId: null,
            previousOperationId: updateStatus?.operationId ?? null, message: '',
        });
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        launchAbortControllerRef.current = controller;
        launchTimeoutRef.current = timeout;
        try {
            const res = await apiFetch('/api/v1/admin/system/update/run', {
                method: 'POST', signal: controller.signal,
            });
            const data = await res.json().catch(() => null) as (UpdateStatusPayload & { operationId?: string }) | null;
            if (!isMountedRef.current) return;
            if (res.ok && data && (data.status !== undefined || data.job_unit !== undefined)) {
                const jobUnit = typeof data.job_unit === 'string' ? data.job_unit.trim() : '';
                if (isValidSelfUpdateJobUnit(jobUnit) && data.completed === true
                    && (data.status === 'succeeded' || data.status === 'failed')) {
                    const evaluation = evaluateUpdateStatusPayload(data, jobUnit);
                    if (!evaluation.confirmed) {
                        void monitorUpdateJob(jobUnit, evaluation.message);
                        return;
                    }
                    settledJobRef.current = jobUnit;
                    setUpdateLaunch(null);
                    setLaunchError(evaluation.isSuccess ? '' : evaluation.message);
                    setUpdateOutcome(evaluation.isSuccess ? 'success' : 'error');
                    setUpdateMessage(evaluation.message);
                    setIsUpdating(false);
                    writeStoredUpdateJobUnit('');
                    if (evaluation.isSuccess) void mutateUpdateData().catch(() => undefined);
                    return;
                }
                if (data.status !== 'initiated' || data.completed !== false || !isValidSelfUpdateJobUnit(jobUnit)) {
                    const message = 'Update initiation returned an invalid or missing self-update job unit.';
                    setUpdateLaunch(null);
                    setLaunchError(message);
                    setUpdateOutcome('error');
                    setUpdateMessage(message);
                    setIsUpdating(false);
                    return;
                }
                setUpdateLaunch(current => current && ({ ...current, state: 'accepted', operationId: data.operationId || null }));
                void monitorUpdateJob(jobUnit, data.message || `Updating system (${jobUnit})...`);
            } else if (res.status === 202) {
                setUpdateLaunch(current => current && ({
                    ...current, state: 'accepted', operationId: data?.operationId || null,
                    message: data?.message || 'Update launcher acknowledged the request.',
                }));
            } else if (res.ok) {
                setUpdateLaunch(current => current && ({
                    ...current, state: 'uncertain', message: 'The launcher acknowledgement was not confirmed.',
                }));
            } else {
                setLaunchError(data?.error || data?.message || `Update launcher rejected the request (${res.status}).`);
                setUpdateLaunch(null);
            }
        } catch {
            if (!isMountedRef.current) return;
            setUpdateLaunch(current => current && ({
                ...current, state: 'uncertain',
                message: 'The update trigger response was lost. Reconnecting without submitting a duplicate request.',
            }));
        } finally {
            clearTimeout(timeout);
            launchRequestInFlight.current = false;
            if (isMountedRef.current) void mutateUpdateStatus().catch(() => undefined);
        }
    };

    const handleCheckForUpdates = async () => {
        addToast('Checking for updates...', 'success');
        if (stoppedJobRef.current && trackedJobUnit) void monitorUpdateJob(trackedJobUnit);
        await Promise.allSettled([mutateUpdateData(), mutateUpdateStatus()]);
    };

    return (
        <div className="space-y-6 animate-fade-in relative pb-12 w-full min-w-0">
            {/* Open Top Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-2 border-b border-white/[0.07] relative z-20 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className="h-10 w-10 rounded-lg flex items-center justify-center border bg-indigo-500/10 border-indigo-500/20 text-indigo-400 shrink-0">
                        <Settings size={20} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">System &amp; Workspace Settings</h2>
                            <span className="shrink-0 whitespace-nowrap text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                Global Control
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5">
                                <span className="absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400"></span>
                                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide">
                                Active Environment &middot; AetherFlow Linux Runtime
                            </span>
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    {['preferences', 'ai', 'system'].includes(activeTab) && (
                        <button
                            type="submit"
                            form={settingsFormId}
                            disabled={isSaving}
                            className="obs-touch-target-standard min-h-[44px] obs-gpu-120hz-interactive flex items-center gap-1.5 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold transition-all disabled:opacity-50"
                        >
                            <Save size={13} />
                            <span>{isSaving ? 'Saving...' : 'Save Configuration'}</span>
                        </button>
                    )}
                </div>
            </div>

            <div className="sm:hidden border-b border-white/[0.07] pb-3">
                <label htmlFor="settings-section" className="block text-xs text-slate-400 mb-2">Settings section</label>
                <select id="settings-section" value={activeTab} onChange={(event) => setActiveTab(event.target.value as typeof activeTab)} className="obs-touch-target-standard w-full min-w-0 rounded-xl border border-white/10 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus-visible:outline-2 focus-visible:outline-indigo-400">
                    <option value="preferences">{t('interfacePreferences')}</option>
                    <option value="ai">{t('flowAIEngine')}</option>
                    <option value="system">{t('systemUpdates')}</option>
                    <option value="backups">Backups</option>
                    <option value="security">Security</option>
                    <option value="dashboard">Dashboard</option>
                    <option value="profile">Profile</option>
                    <option value="oidc-clients">OIDC Clients</option>
                    <option value="notifications">Notifications</option>
                    <option value="mcbrowser">McBrowser</option>
                </select>
            </div>
            <div className="hidden sm:flex min-h-[44px] items-center justify-between gap-2">
                <p id="settings-nav-hint" className="text-xs text-slate-400">
                    {hasOverflow ? '10 settings sections · Scroll horizontally for more →' : '10 settings sections'}
                </p>
                {hasOverflow && <div className="flex items-center gap-1">
                    <button
                        type="button"
                        aria-label="Previous settings sections"
                        disabled={!canScrollLeft}
                        onClick={() => handleScrollRail('left')}
                        className="obs-touch-target-standard min-h-[40px] min-w-[40px] p-1.5 rounded-lg border border-white/10 text-slate-400 hover:text-white hover:bg-white/5 disabled:opacity-30 disabled:pointer-events-none transition-colors"
                    >
                        <ChevronLeft size={14} />
                    </button>
                    <button
                        type="button"
                        aria-label="Next settings sections"
                        disabled={!canScrollRight}
                        onClick={() => handleScrollRail('right')}
                        className="obs-touch-target-standard min-h-[40px] min-w-[40px] p-1.5 rounded-lg border border-white/10 text-slate-400 hover:text-white hover:bg-white/5 disabled:opacity-30 disabled:pointer-events-none transition-colors"
                    >
                        <ChevronRight size={14} />
                    </button>
                </div>}
            </div>
            <div className="hidden sm:block relative w-full min-w-0">
                {canScrollLeft && (
                    <div aria-hidden="true" className="pointer-events-none absolute left-0 top-0 bottom-2 w-8 bg-gradient-to-r from-slate-950 to-transparent z-20" />
                )}
                {canScrollRight && (
                    <div aria-hidden="true" className="pointer-events-none absolute right-0 top-0 bottom-2 w-8 bg-gradient-to-l from-slate-950 to-transparent z-20" />
                )}
            <nav
                ref={settingsNavigationRef}
                aria-label="Settings navigation rail"
                aria-describedby="settings-nav-hint"
                onPointerDown={handleRailManualNavigation}
                onTouchStart={handleRailManualNavigation}
                onFocusCapture={(event) => {
                    if (event.target instanceof HTMLButtonElement) settingsRailManualNavigationRef.current = false;
                }}
                onWheel={(event) => {
                    if (event.deltaX !== 0 || event.shiftKey) handleRailManualNavigation();
                }}
                className="hidden sm:flex items-center gap-1 border-b border-white/[0.07] overflow-x-auto custom-scrollbar pb-2 relative z-10 w-full min-w-0"
            >
                <button 
                    type="button" 
                    onClick={() => setActiveTab('preferences')}
                    aria-current={activeTab === 'preferences' ? 'page' : undefined}
                    className={`obs-touch-target-standard min-h-[44px] px-3.5 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 -mb-px shrink-0 transition-colors flex items-center gap-2 ${activeTab === 'preferences' ? 'border-indigo-400 text-indigo-300 bg-indigo-500/[0.06]' : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-white/20'}`}
                >
                    <Monitor size={15} /> {t('interfacePreferences')}
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('ai')}
                    aria-current={activeTab === 'ai' ? 'page' : undefined}
                    className={`obs-touch-target-standard min-h-[44px] px-3.5 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 -mb-px shrink-0 transition-colors flex items-center gap-2 ${activeTab === 'ai' ? 'border-indigo-400 text-indigo-300 bg-indigo-500/[0.06]' : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-white/20'}`}
                >
                    <Sparkles size={15} /> {t('flowAIEngine')}
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('system')}
                    aria-current={activeTab === 'system' ? 'page' : undefined}
                    className={`obs-touch-target-standard min-h-[44px] px-3.5 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 -mb-px shrink-0 transition-colors flex items-center gap-2 ${activeTab === 'system' ? 'border-indigo-400 text-indigo-300 bg-indigo-500/[0.06]' : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-white/20'}`}
                >
                    <DownloadCloud size={15} /> {t('systemUpdates')}
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('backups')}
                    aria-current={activeTab === 'backups' ? 'page' : undefined}
                    className={`obs-touch-target-standard min-h-[44px] px-3.5 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 -mb-px shrink-0 transition-colors flex items-center gap-2 ${activeTab === 'backups' ? 'border-indigo-400 text-indigo-300 bg-indigo-500/[0.06]' : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-white/20'}`}
                >
                    <HardDriveDownload size={15} /> Backups
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('security')}
                    aria-current={activeTab === 'security' ? 'page' : undefined}
                    className={`obs-touch-target-standard min-h-[44px] px-3.5 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 -mb-px shrink-0 transition-colors flex items-center gap-2 ${activeTab === 'security' ? 'border-indigo-400 text-indigo-300 bg-indigo-500/[0.06]' : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-white/20'}`}
                >
                    <Shield size={15} /> Security
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('dashboard')}
                    aria-current={activeTab === 'dashboard' ? 'page' : undefined}
                    className={`obs-touch-target-standard min-h-[44px] px-3.5 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 -mb-px shrink-0 transition-colors flex items-center gap-2 ${activeTab === 'dashboard' ? 'border-indigo-400 text-indigo-300 bg-indigo-500/[0.06]' : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-white/20'}`}
                >
                    <LayoutDashboard size={15} /> Dashboard
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('profile')}
                    aria-current={activeTab === 'profile' ? 'page' : undefined}
                    className={`obs-touch-target-standard min-h-[44px] px-3.5 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 -mb-px shrink-0 transition-colors flex items-center gap-2 ${activeTab === 'profile' ? 'border-indigo-400 text-indigo-300 bg-indigo-500/[0.06]' : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-white/20'}`}
                >
                    <UserCircle size={15} /> Profile
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('oidc-clients')}
                    aria-current={activeTab === 'oidc-clients' ? 'page' : undefined}
                    className={`obs-touch-target-standard min-h-[44px] px-3.5 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 -mb-px shrink-0 transition-colors flex items-center gap-2 ${activeTab === 'oidc-clients' ? 'border-indigo-400 text-indigo-300 bg-indigo-500/[0.06]' : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-white/20'}`}
                >
                    <KeyRound size={15} /> OIDC Clients
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('notifications')}
                    aria-current={activeTab === 'notifications' ? 'page' : undefined}
                    className={`obs-touch-target-standard min-h-[44px] px-3.5 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 -mb-px shrink-0 transition-colors flex items-center gap-2 ${activeTab === 'notifications' ? 'border-indigo-400 text-indigo-300 bg-indigo-500/[0.06]' : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-white/20'}`}
                >
                    <Bell size={15} /> Notifications
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('mcbrowser')}
                    aria-current={activeTab === 'mcbrowser' ? 'page' : undefined}
                    className={`obs-touch-target-standard min-h-[44px] px-3.5 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 -mb-px shrink-0 transition-colors flex items-center gap-2 ${activeTab === 'mcbrowser' ? 'border-indigo-400 text-indigo-300 bg-indigo-500/[0.06]' : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-white/20'}`}
                >
                    <Folder size={15} /> McBrowser
                </button>
            </nav>
            </div>

            {['preferences', 'ai', 'system'].includes(activeTab) ? (
                <div className="space-y-8 relative z-10 w-full">
                    <form id={settingsFormId} onSubmit={handleSave} className="space-y-8 w-full">
                        
                        {/* -----------------------------
                            TAB: General Preferences 
                        ------------------------------- */}
                        {activeTab === 'preferences' && (
                            <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-white/[0.07] border-b border-white/[0.07] w-full min-w-0 animate-fade-in">
                                <div className="obs-canvas-section p-5 sm:p-6 space-y-6 relative z-20">
                                    <div className="space-y-6">
                                        <div className="flex items-center justify-between border-b border-white/[0.07] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                                    <LayoutDashboard size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Navigation & Localization</h3>
                                                    <p className="text-xs text-slate-400">Default workspace landing view, regional clock, and display language.</p>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="divide-y divide-white/[0.07]">
                                            <div className="py-4 first:pt-0 last:pb-0 space-y-2.5">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <LayoutDashboard size={15} className="text-indigo-400" /> Default Dashboard
                                                    </label>
                                                    <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Post-Login Route</span>
                                                </div>
                                                <p className="text-xs text-slate-400 leading-relaxed">Select the default view presented immediately after authentication.</p>
                                                <GlassSelect
                                                    value={defaultDashboard}
                                                    onChange={setDefaultDashboard}
                                                    options={DEFAULT_DASHBOARD_OPTIONS}
                                                    ariaLabel="Default Dashboard"
                                                />
                                            </div>

                                            <div className="py-4 first:pt-0 last:pb-0 space-y-2.5">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <Clock size={15} className="text-blue-400" /> Timezone
                                                    </label>
                                                    <span className="text-xs font-mono uppercase tracking-wider text-slate-400">{timezone}</span>
                                                </div>
                                                <p className="text-xs text-slate-400 leading-relaxed">Set your local timezone for system telemetry, cron schedules, and audit logs.</p>
                                                <GlassSelect
                                                    value={timezone}
                                                    onChange={setTimezone}
                                                    options={TIMEZONE_OPTIONS}
                                                    ariaLabel="Timezone"
                                                />
                                            </div>

                                            <div className="py-4 first:pt-0 last:pb-0 space-y-2.5">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <Globe size={15} className="text-emerald-400" /> {t('language')}
                                                    </label>
                                                    <span className="text-xs font-mono uppercase tracking-wider text-slate-400">{language.toUpperCase()}</span>
                                                </div>
                                                <p className="text-xs text-slate-400 leading-relaxed">Determine the primary display language of the AetherFlow interface.</p>
                                                <GlassSelect
                                                    value={language}
                                                    onChange={setLanguage}
                                                    options={LANGUAGE_OPTIONS}
                                                    ariaLabel={t('language')}
                                                />
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div className="obs-canvas-section p-5 sm:p-6 space-y-6">
                                    <div className="space-y-6">
                                        <div className="flex items-center justify-between border-b border-white/[0.07] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                    <Radio size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Connectivity & Telemetry</h3>
                                                    <p className="text-xs text-slate-400">Reverse-proxy domain routing, realtime transport protocol, and heartbeat cadence.</p>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="divide-y divide-white/[0.07]">
                                            <div className="py-4 first:pt-0 last:pb-0 space-y-2.5">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <Globe size={15} className="text-indigo-400" /> Server Base Domain
                                                    </label>
                                                    <span className="text-xs font-mono uppercase tracking-wider text-indigo-400">Apache2 Auto-Route</span>
                                                </div>
                                                <p className="text-xs text-slate-400 leading-relaxed">
                                                    Automatically assigns <span className="font-mono text-indigo-300">jellyfin.{baseDomain.trim().replace(/^\*\./, '') || 'domain.com'}</span> via Apache2 reverse proxy when installing apps.
                                                </p>
                                                <input
                                                    type="text"
                                                    value={baseDomain}
                                                    onChange={(event) => setBaseDomain(event.target.value)}
                                                    placeholder="domain.com"
                                                    className="obs-touch-target-standard min-h-[44px] w-full bg-slate-900 border border-white/10 rounded-lg px-4 py-2.5 text-slate-200 text-sm font-mono focus:outline-none focus:border-indigo-500/50 transition-colors"
                                                />
                                            </div>

                                            <div className="py-4 first:pt-0 last:pb-0 space-y-2.5">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <Radio size={15} className="text-indigo-400" /> Telemetry Transport
                                                    </label>
                                                    <span className="text-xs font-mono uppercase tracking-wider text-emerald-400">WebSocket</span>
                                                </div>
                                                <p className="text-xs text-slate-400 leading-relaxed">Full-duplex WebSocket streaming with real-time 1.0s telemetry updates.</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* -----------------------------
                            TAB: Flow AI Engine 
                        ------------------------------- */}
                        {activeTab === 'ai' && (
                            <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-white/[0.07] border-b border-white/[0.07] w-full min-w-0 animate-fade-in">
                                {/* LEFT/MAIN COLUMN: Active Provider, Model Selector, and Credentials */}
                                <div className="lg:col-span-7 divide-y divide-white/[0.07] min-w-0">
                                    {/* Active Provider & Default Model Card */}
                                    <div className="obs-canvas-section p-5 sm:p-6 space-y-6 relative z-20">
                                        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                                    <Cpu size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Active Provider & Model Configuration</h3>
                                                    <p className="text-xs text-slate-400">Select your primary AI ecosystem and default inference model.</p>
                                                </div>
                                            </div>
                                            <span className="px-2.5 py-1 rounded-md text-xs font-bold uppercase tracking-wider bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                                                {activeModelDef.name}
                                            </span>
                                        </div>

                                        {/* Provider Selector Cards */}
                                        <div>
                                            <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-3">
                                                Inference Provider Ecosystem
                                            </label>
                                            <div className="grid grid-cols-1 sm:grid-cols-2 2xl:grid-cols-4 rounded-xl border border-white/[0.08] overflow-hidden bg-transparent">
                                                {PROVIDER_CARDS.map((providerItem, providerIndex) => {
                                                    const isSelected = activeProvider === providerItem.id;
                                                    return (
                                                        <button
                                                            key={providerItem.id}
                                                            type="button"
                                                            aria-pressed={isSelected}
                                                            onClick={() => {
                                                                if (providerItem.id === 'localai') {
                                                                    setModel(effectiveLocalModel);
                                                                } else if (activeProvider !== providerItem.id && AI_MODELS[providerItem.id]?.[0]?.id) {
                                                                    setModel(AI_MODELS[providerItem.id][0].id);
                                                                }
                                                            }}
                                                            className={`obs-touch-target-standard min-h-[44px] obs-gpu-120hz-interactive p-4 text-left transition-all flex flex-col justify-between gap-2.5 focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-indigo-400 ${
                                                                providerIndex < 3 ? 'border-b 2xl:border-b-0' : ''
                                                            } ${
                                                                providerIndex < 2 ? 'sm:border-b 2xl:border-b-0' : 'sm:border-b-0'
                                                            } ${
                                                                providerIndex % 2 === 0 ? 'sm:border-r' : 'sm:border-r-0'
                                                            } ${
                                                                providerIndex < 3 ? '2xl:border-r' : '2xl:border-r-0'
                                                            } border-white/[0.07] ${
                                                                isSelected
                                                                    ? `${providerItem.activeBg} shadow-inner`
                                                                    : 'bg-transparent hover:bg-white/[0.03]'
                                                            }`}
                                                        >
                                                            <div className="flex items-center justify-between">
                                                                <Sparkles size={15} className={isSelected ? providerItem.accent : 'text-slate-500'} />
                                                                <span className={`h-2 w-2 rounded-full ${isSelected ? 'bg-indigo-400 ring-2 ring-indigo-400/30' : 'bg-slate-700'}`} />
                                                            </div>
                                                            <div>
                                                                <div className="text-xs font-bold text-slate-100 leading-tight">{providerItem.label}</div>
                                                                <div className="text-xs text-slate-400 mt-0.5 leading-relaxed break-words">{providerItem.subtitle}</div>
                                                            </div>
                                                        </button>
                                                    );
                                                })}
                                            </div>
                                        </div>

                                        <div className="pt-6 border-t border-white/[0.07] space-y-3">
                                            <div className="flex flex-wrap items-center justify-between gap-2">
                                                <div>
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <Monitor size={15} className="text-blue-400" /> {t('defaultModel')}
                                                    </label>
                                                    <p className="text-xs text-slate-400 leading-relaxed mt-0.5">Default model loaded when launching FlowAI Assistant. Can be switched per-chat.</p>
                                                </div>
                                                <span className="text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                                                    Tier: {activeModelDef.tier}
                                                </span>
                                            </div>

                                            <div className="pt-1">
                                                <GlassSelect
                                                    value={model}
                                                    onChange={setModel}
                                                    ariaLabel={t('defaultModel')}
                                                    options={Object.entries(AI_MODELS).flatMap(([providerId, models]) =>
                                                        models.map((modelItem) => ({
                                                            value: modelItem.id,
                                                            label: modelItem.name,
                                                            badge: modelItem.tier,
                                                            badgeVariant: modelItem.tier === 'latest' ? 'indigo' : 'slate',
                                                            group: providerId.charAt(0).toUpperCase() + providerId.slice(1),
                                                        }))
                                                    )}
                                                />
                                            </div>

                                            <div className="pt-2 border-t border-white/[0.07] space-y-2.5">
                                                <div className="flex flex-wrap items-center justify-between gap-2">
                                                    <label
                                                        htmlFor="installed-local-model-input"
                                                        className="text-xs font-semibold text-slate-200 flex items-center gap-2"
                                                    >
                                                        <Cpu size={14} className="text-purple-400" /> Installed Local Model ID
                                                    </label>
                                                    <div className="flex flex-wrap gap-1.5">
                                                        {LOCAL_AI_RUNTIMES.map((runtimeItem) => (
                                                            <button
                                                                key={runtimeItem.id}
                                                                type="button"
                                                                onClick={() => setLocalRuntime(runtimeItem.id)}
                                                                className={`obs-touch-target-standard min-h-[32px] px-2 py-1 rounded-md text-xs font-semibold border transition-colors ${
                                                                    localRuntime === runtimeItem.id
                                                                        ? 'bg-purple-500/20 border-purple-500/40 text-purple-200'
                                                                        : 'bg-slate-900 border-white/10 text-slate-400 hover:text-slate-200'
                                                                }`}
                                                            >
                                                                {runtimeItem.name}
                                                            </button>
                                                        ))}
                                                    </div>
                                                </div>
                                                <p className="text-xs text-slate-400 leading-relaxed">
                                                    Exact model identifier installed in your local runner (used for local chat and connection tests; never a provider alias).
                                                </p>
                                                <input
                                                    id="installed-local-model-input"
                                                    aria-label="Installed Local Model ID"
                                                    type="text"
                                                    value={localModel}
                                                    onChange={(event) => setLocalModel(event.target.value)}
                                                    placeholder="llama3.2:latest"
                                                    className="obs-touch-target-standard min-h-[44px] w-full bg-slate-900 border border-white/10 rounded-lg px-3.5 py-2.5 text-slate-200 text-xs focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                />
                                            </div>
                                        </div>
                                    </div>

                                    {/* Cloud Provider API Keys Card */}
                                    <div className="obs-canvas-section p-5 sm:p-6 space-y-5">
                                        <div className="flex items-center justify-between border-b border-white/[0.07] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
                                                    <Key size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Cloud Provider API Keys</h3>
                                                    <p className="text-xs text-slate-400">Encrypted credentials for Google Gemini, OpenAI, and Anthropic Claude.</p>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="divide-y divide-white/[0.07]">
                                            {/* Google Gemini API Key */}
                                            <div className={`py-4 first:pt-0 last:pb-0 space-y-3 transition-colors ${activeProvider === 'gemini' ? 'bg-amber-500/[0.04] -mx-5 sm:-mx-6 px-5 sm:px-6 rounded-lg' : ''}`}>
                                                <div className="flex flex-wrap items-center justify-between gap-2">
                                                    <div>
                                                        <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                            <Key size={15} className="text-amber-400" /> {t('apiKeyTitle')}
                                                        </label>
                                                        <p className="text-xs text-slate-400 leading-relaxed mt-0.5">
                                                            Get your API key from <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:text-indigo-300 underline">Google AI Studio</a>.
                                                        </p>
                                                    </div>
                                                    <span className={`text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${apiKey ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' : 'bg-slate-800 text-slate-400 border-white/10'}`}>
                                                        {apiKey ? 'Key Configured' : 'Not Configured'}
                                                    </span>
                                                </div>
                                                <div className="flex flex-col sm:flex-row gap-2.5">
                                                    <div className="relative flex-1">
                                                        <input
                                                            type={showApiKey ? 'text' : 'password'}
                                                            value={apiKey}
                                                            onChange={(event) => setApiKey(event.target.value)}
                                                            placeholder={t('apiKeyPlaceholder')}
                                                            className="obs-touch-target-standard min-h-[44px] w-full bg-slate-900 border border-white/10 rounded-lg px-4 py-2.5 pr-11 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                        />
                                                        <button
                                                            type="button"
                                                            onClick={() => setShowApiKey(!showApiKey)}
                                                            aria-label={showApiKey ? 'Hide Gemini API key' : 'Show Gemini API key'}
                                                            aria-pressed={showApiKey}
                                                            className="obs-touch-target-standard absolute right-1 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors flex items-center justify-center"
                                                        >
                                                            {showApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                                                        </button>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleTestConnection('gemini')}
                                                        disabled={isTesting || !apiKey}
                                                        className="obs-touch-target-standard min-h-[44px] obs-gpu-120hz-interactive px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-lg text-xs font-semibold text-slate-200 transition-colors flex items-center justify-center gap-2 shrink-0"
                                                    >
                                                        {isTesting ? (
                                                            <><div className="w-3 h-3 border-2 border-slate-400/30 border-t-slate-400 rounded-full animate-spin"></div> {t('testing')}</>
                                                        ) : (
                                                            <><Sparkles size={14} className="text-amber-400" /> Test Gemini</>
                                                        )}
                                                    </button>
                                                </div>
                                            </div>

                                            {/* OpenAI API Key */}
                                            <div className={`py-4 first:pt-0 last:pb-0 space-y-3 transition-colors ${activeProvider === 'openai' ? 'bg-emerald-500/[0.04] -mx-5 sm:-mx-6 px-5 sm:px-6 rounded-lg' : ''}`}>
                                                <div className="flex flex-wrap items-center justify-between gap-2">
                                                    <div>
                                                        <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                            <Key size={15} className="text-emerald-400" /> OpenAI API Key
                                                        </label>
                                                        <p className="text-xs text-slate-400 leading-relaxed mt-0.5">Connect to OpenAI for GPT-6 and GPT-6.1 model families.</p>
                                                    </div>
                                                    <span className={`text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${openaiApiKey ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' : 'bg-slate-800 text-slate-400 border-white/10'}`}>
                                                        {openaiApiKey ? 'Key Configured' : 'Not Configured'}
                                                    </span>
                                                </div>
                                                <div className="flex flex-col sm:flex-row gap-2.5">
                                                    <div className="relative flex-1">
                                                        <input
                                                            type={showOpenaiApiKey ? 'text' : 'password'}
                                                            value={openaiApiKey}
                                                            onChange={(event) => setOpenaiApiKey(event.target.value)}
                                                            placeholder="sk-proj-..."
                                                            className="obs-touch-target-standard min-h-[44px] w-full bg-slate-900 border border-white/10 rounded-lg px-4 py-2.5 pr-11 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                        />
                                                        <button
                                                            type="button"
                                                            onClick={() => setShowOpenaiApiKey(!showOpenaiApiKey)}
                                                            aria-label={showOpenaiApiKey ? 'Hide OpenAI API key' : 'Show OpenAI API key'}
                                                            aria-pressed={showOpenaiApiKey}
                                                            className="obs-touch-target-standard absolute right-1 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors flex items-center justify-center"
                                                        >
                                                            {showOpenaiApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                                                        </button>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleTestConnection('openai')}
                                                        disabled={isTesting || !openaiApiKey}
                                                        className="obs-touch-target-standard min-h-[44px] obs-gpu-120hz-interactive px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-lg text-xs font-semibold text-slate-200 transition-colors flex items-center justify-center gap-2 shrink-0"
                                                    >
                                                        {isTesting ? (
                                                            <><div className="w-3 h-3 border-2 border-slate-400/30 border-t-slate-400 rounded-full animate-spin"></div> {t('testing')}</>
                                                        ) : (
                                                            <><Sparkles size={14} className="text-emerald-400" /> Test OpenAI</>
                                                        )}
                                                    </button>
                                                </div>
                                            </div>

                                            {/* Anthropic API Key */}
                                            <div className={`py-4 first:pt-0 last:pb-0 space-y-3 transition-colors ${activeProvider === 'anthropic' ? 'bg-orange-500/[0.04] -mx-5 sm:-mx-6 px-5 sm:px-6 rounded-lg' : ''}`}>
                                                <div className="flex flex-wrap items-center justify-between gap-2">
                                                    <div>
                                                        <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                            <Key size={15} className="text-orange-400" /> Anthropic API Key
                                                        </label>
                                                        <p className="text-xs text-slate-400 leading-relaxed mt-0.5">Connect to Anthropic for Claude Fable 5.1, Opus 5.5, Sonnet 5.5, and Haiku 5.5 models.</p>
                                                    </div>
                                                    <span className={`text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${anthropicApiKey ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' : 'bg-slate-800 text-slate-400 border-white/10'}`}>
                                                        {anthropicApiKey ? 'Key Configured' : 'Not Configured'}
                                                    </span>
                                                </div>
                                                <div className="flex flex-col sm:flex-row gap-2.5">
                                                    <div className="relative flex-1">
                                                        <input
                                                            type={showAnthropicApiKey ? 'text' : 'password'}
                                                            value={anthropicApiKey}
                                                            onChange={(event) => setAnthropicApiKey(event.target.value)}
                                                            placeholder="sk-ant-..."
                                                            className="obs-touch-target-standard min-h-[44px] w-full bg-slate-900 border border-white/10 rounded-lg px-4 py-2.5 pr-11 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                        />
                                                        <button
                                                            type="button"
                                                            onClick={() => setShowAnthropicApiKey(!showAnthropicApiKey)}
                                                            aria-label={showAnthropicApiKey ? 'Hide Anthropic API key' : 'Show Anthropic API key'}
                                                            aria-pressed={showAnthropicApiKey}
                                                            className="obs-touch-target-standard absolute right-1 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors flex items-center justify-center"
                                                        >
                                                            {showAnthropicApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                                                        </button>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleTestConnection('anthropic')}
                                                        disabled={isTesting || (!anthropicApiKey && !anthropicEndpoint)}
                                                        className="obs-touch-target-standard min-h-[44px] obs-gpu-120hz-interactive px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-lg text-xs font-semibold text-slate-200 transition-colors flex items-center justify-center gap-2 shrink-0"
                                                    >
                                                        {isTesting ? (
                                                            <><div className="w-3 h-3 border-2 border-slate-400/30 border-t-slate-400 rounded-full animate-spin"></div> {t('testing')}</>
                                                        ) : (
                                                            <><Sparkles size={14} className="text-orange-400" /> Test Anthropic</>
                                                        )}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Local & Self-Hosted AI Endpoints Card */}
                                    <div className="obs-canvas-section p-5 sm:p-6 space-y-5">
                                        <div className="flex items-center justify-between border-b border-white/[0.07] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
                                                    <Radio size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Local & Custom AI Endpoints</h3>
                                                    <p className="text-xs text-slate-400">Self-hosted inference servers (LM Studio, Ollama) and custom proxy base URLs.</p>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                            <div className="p-4 rounded-lg bg-slate-950/40 border border-white/[0.07] space-y-2.5">
                                                <label className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                                                    <Radio size={14} className="text-purple-400" /> LM-Studio Endpoint
                                                </label>
                                                <input
                                                    type="text"
                                                    value={lmStudioEndpoint}
                                                    onChange={(event) => setLmStudioEndpoint(event.target.value)}
                                                    placeholder="http://localhost:1234"
                                                    className="obs-touch-target-standard min-h-[44px] w-full bg-slate-900 border border-white/10 rounded-lg px-3.5 py-2.5 text-slate-200 text-xs focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                />
                                                <button
                                                    type="button"
                                                    onClick={() =>
                                                        handleTestConnection('localai', {
                                                            local_provider: 'lm-studio',
                                                            endpoint: lmStudioEndpoint || 'http://localhost:1234',
                                                            model: localModel.trim() || effectiveLocalModel,
                                                        })
                                                    }
                                                    disabled={isTesting}
                                                    className="obs-touch-target-standard min-h-[44px] obs-gpu-120hz-interactive w-full py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-lg text-xs font-semibold text-slate-300 transition-colors flex items-center justify-center gap-2"
                                                >
                                                    <Radio size={13} className="text-purple-400" /> Test LM Studio
                                                </button>
                                            </div>

                                            <div className="p-4 rounded-lg bg-slate-950/40 border border-white/[0.07] space-y-2.5">
                                                <label className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                                                    <Radio size={14} className="text-pink-400" /> Ollama Endpoint
                                                </label>
                                                <input
                                                    type="text"
                                                    value={ollamaEndpoint}
                                                    onChange={(event) => setOllamaEndpoint(event.target.value)}
                                                    placeholder="http://localhost:11434"
                                                    className="obs-touch-target-standard min-h-[44px] w-full bg-slate-900 border border-white/10 rounded-lg px-3.5 py-2.5 text-slate-200 text-xs focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                />
                                                <button
                                                    type="button"
                                                    onClick={() =>
                                                        handleTestConnection('localai', {
                                                            local_provider: 'ollama',
                                                            endpoint: ollamaEndpoint || 'http://localhost:11434',
                                                            model: localModel.trim() || effectiveLocalModel,
                                                        })
                                                    }
                                                    disabled={isTesting}
                                                    className="obs-touch-target-standard min-h-[44px] obs-gpu-120hz-interactive w-full py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-lg text-xs font-semibold text-slate-300 transition-colors flex items-center justify-center gap-2"
                                                >
                                                    <Radio size={13} className="text-pink-400" /> Test Ollama
                                                </button>
                                            </div>
                                        </div>

                                        <div className="pt-4 border-t border-white/[0.07] space-y-2">
                                            <label className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                                                <Radio size={14} className="text-orange-400" /> Anthropic Custom Endpoint
                                            </label>
                                            <p className="text-xs text-slate-400 leading-relaxed">Override the default Anthropic API URL if using an enterprise gateway or local simulator.</p>
                                            <input
                                                type="text"
                                                value={anthropicEndpoint}
                                                onChange={(event) => setAnthropicEndpoint(event.target.value)}
                                                placeholder="https://api.anthropic.com/v1/"
                                                className="obs-touch-target-standard min-h-[44px] w-full bg-slate-900 border border-white/10 rounded-lg px-3.5 py-2.5 text-slate-200 text-xs focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* RIGHT COLUMN: FlowAI Engine Architecture & System Prompt Guardrails */}
                                <div className="lg:col-span-5 divide-y divide-white/[0.07] min-w-0">
                                    {/* FlowAI Engine Architecture & Capabilities Card */}
                                    <div className="obs-canvas-section p-5 sm:p-6 space-y-5">
                                        <div className="flex items-center justify-between border-b border-white/[0.07] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                                    <Sparkles size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">FlowAI Engine Architecture</h3>
                                                    <p className="text-xs text-slate-400">Live runtime summary & autonomous capabilities.</p>
                                                </div>
                                            </div>
                                            <span className={`px-2.5 py-1 rounded-md text-xs font-bold uppercase tracking-wider border ${
                                                isActiveProviderConfigured
                                                    ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                                                    : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                            }`}>
                                                {isActiveProviderConfigured ? 'Engine Ready' : 'Needs Credentials'}
                                            </span>
                                        </div>

                                        <div className="grid grid-cols-2 gap-3">
                                            <div className="p-3.5 rounded-lg bg-slate-950/50 border border-white/[0.07]">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">Selected Provider</span>
                                                <span className="text-sm font-bold text-slate-100 mt-1 block capitalize">{activeProvider}</span>
                                            </div>
                                            <div className="p-3.5 rounded-lg bg-slate-950/50 border border-white/[0.07]">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">Default Model</span>
                                                <span className="text-sm font-bold text-indigo-300 mt-1 block break-words [overflow-wrap:anywhere]">{activeModelDef.name}</span>
                                            </div>
                                            <div className="p-3.5 rounded-lg bg-slate-950/50 border border-white/[0.07] col-span-2">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">Active Endpoint Route</span>
                                                <span className="text-xs font-mono text-slate-300 mt-1 block break-words [overflow-wrap:anywhere]">{activeEndpointSummary}</span>
                                            </div>
                                        </div>

                                        <div className="space-y-2.5 pt-1">
                                            <div className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.07] text-xs">
                                                <span className="text-slate-300 flex items-center gap-2 font-medium">
                                                    <CheckCircle2 size={14} className="text-emerald-400" /> Approval Inbox Action Queueing
                                                </span>
                                                <span className="text-xs font-mono uppercase text-emerald-400">Enabled</span>
                                            </div>
                                            <div className="flex items-center justify-between p-3 rounded-lg bg-white/[0.02] border border-white/[0.07] text-xs">
                                                <span className="text-slate-300 flex items-center gap-2 font-medium">
                                                    <Layers size={14} className="text-indigo-400" /> Live Telemetry & Log Context Injection
                                                </span>
                                                <span className="text-xs font-mono uppercase text-indigo-400">Active</span>
                                            </div>
                                        </div>

                                        <button
                                            type="button"
                                            onClick={() => setActiveMainTab('ai')}
                                            className="obs-touch-target-standard min-h-[44px] obs-gpu-120hz-interactive w-full py-3 px-4 rounded-lg bg-indigo-500/15 hover:bg-indigo-500/25 border border-indigo-500/30 text-indigo-300 text-xs font-bold transition-all flex items-center justify-center gap-2"
                                        >
                                            <Sparkles size={15} />
                                            <span>Launch FlowAI Assistant</span>
                                            <ArrowUpRight size={15} />
                                        </button>
                                    </div>

                                    {/* System Prompt Guardrails Card */}
                                    <div className="obs-canvas-section p-5 sm:p-6 space-y-4">
                                        <div className="flex items-center justify-between border-b border-white/[0.07] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
                                                    <Terminal size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">System Prompt Guardrails</h3>
                                                    <p className="text-xs text-slate-400">{t('defaultPrompt')}</p>
                                                </div>
                                            </div>
                                        </div>

                                        <p className="text-xs text-slate-400 leading-relaxed">
                                            Tune the system instructions injected at the start of every FlowAI session to control operational strictness, response formatting, and infrastructure safety boundaries.
                                        </p>

                                        <textarea
                                            aria-label="Custom System Prompt"
                                            value={prompt}
                                            onChange={(event) => setPrompt(event.target.value)}
                                            rows={6}
                                            className="w-full bg-slate-900 border border-white/10 rounded-lg px-4 py-3 text-slate-200 text-xs leading-relaxed font-mono focus:outline-none focus:border-indigo-500/50 transition-colors min-h-[140px] resize-y"
                                        />
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* -----------------------------
                            TAB: System Updates 
                        ------------------------------- */}
                        {activeTab === 'system' && (
                            <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-white/[0.07] border-b border-white/[0.07] w-full min-w-0 animate-fade-in">
                                {/* LEFT CARD: Release Channel & Update Status */}
                                <div className="obs-canvas-section p-5 sm:p-6 space-y-6 relative z-20 min-w-0 max-w-full">
                                    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] pb-4">
                                        <div className="flex items-center gap-3">
                                            <div className="p-2.5 rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                                                <DownloadCloud size={18} />
                                            </div>
                                            <div>
                                                <h3 className="text-base font-bold text-slate-100">Release Channel & Update Engine</h3>
                                                <p className="text-xs text-slate-400">Manage AetherFlow Core release tracking and over-the-air upgrades.</p>
                                            </div>
                                        </div>
                                        <button
                                            type="button"
                                            onClick={handleCheckForUpdates}
                                            disabled={isCheckingUpdate}
                                            className="obs-touch-target-standard min-h-[44px] obs-gpu-120hz-interactive bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/20 rounded-lg px-3.5 py-2 text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
                                        >
                                            <RefreshCw size={14} className={isCheckingUpdate ? "animate-spin" : ""} />
                                            {isCheckingUpdate ? 'Checking...' : 'Check for Updates'}
                                        </button>
                                    </div>

                                    <div className="py-4 border-b border-white/[0.07] space-y-2.5 relative z-30">
                                        <div className="flex items-center justify-between">
                                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                <Radio size={15} className="text-indigo-400" /> Update Channel
                                            </label>
                                            <span
                                                className={`text-xs font-mono font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border ${
                                                    UPDATE_CHANNEL_PILL_STYLES[updateChannel] ?? UPDATE_CHANNEL_PILL_STYLES.stable
                                                }`}
                                            >
                                                {updateChannel}
                                            </span>
                                        </div>
                                        <p className="text-xs text-slate-400 leading-relaxed">Select the release branch. Save configuration to apply channel changes.</p>
                                        <GlassSelect
                                            value={updateChannel}
                                            onChange={setUpdateChannel}
                                            options={UPDATE_CHANNEL_OPTIONS}
                                            ariaLabel="Update Channel"
                                        />
                                    </div>

                                    <div className="space-y-4 text-sm text-slate-400">
                                                <div className="flex flex-col gap-3 p-4 bg-slate-950/50 rounded-lg border border-white/[0.07]">
                                                    <div className="flex justify-between items-center">
                                                        <span className="text-xs font-semibold text-slate-400">Current Version</span>
                                                        <span className="font-mono text-xs font-bold text-slate-200 px-2.5 py-1 rounded-md bg-white/5 border border-white/5 break-all">{updateStatus?.currentVersion || updateData?.currentVersion || 'Unknown'}</span>
                                                    </div>
                                                    <div className="flex justify-between items-center">
                                                        <span className="text-xs font-semibold text-slate-400">Latest Upstream Version</span>
                                                        <span className="font-mono text-xs font-bold text-indigo-300 px-2.5 py-1 rounded-md bg-indigo-500/10 border border-indigo-500/20 break-all">{updateData?.latestVersion || 'Unknown'}</span>
                                                    </div>
                                                    <div className="flex justify-between items-center gap-3">
                                                        <span className="text-xs font-semibold text-slate-400">Runner Version</span>
                                                        <span className="font-mono text-xs text-slate-200 break-all">{updateStatus?.runnerVersion || 'Unknown'}</span>
                                                    </div>
                                                    {updateStatus?.selectedVersion && (
                                                        <div className="flex justify-between items-center gap-3">
                                                            <span className="text-xs font-semibold text-slate-400">Selected Release</span>
                                                            <span className="font-mono text-xs text-slate-200 break-all">{updateStatus.selectedVersion}</span>
                                                        </div>
                                                    )}
                                                    {updateStatus?.operationId && (
                                                        <div className="text-xs text-slate-400 leading-relaxed break-all">Operation: {updateStatus.operationId}</div>
                                                    )}
                                                    {updateStatus?.phase && (
                                                        <div className="text-xs text-slate-400 break-words">Last phase: {updateStatus.phase}</div>
                                                    )}
                                                    {updateData?.url && !updateData.latestVersion?.includes('Unknown') && (
                                                        <div className="pt-1 border-t border-white/5 flex justify-end">
                                                            <a href={updateData.url} target="_blank" rel="noopener noreferrer" className="text-xs text-indigo-400 hover:text-indigo-300 underline transition-colors">
                                                                View release details &rarr;
                                                            </a>
                                                        </div>
                                                    )}
                                                </div>

                                                <div
                                                    role={updateView.kind === 'failed' || updateView.kind === 'interrupted' ? 'alert' : 'status'}
                                                    aria-live="polite"
                                                    className={`flex items-start gap-2 p-4 rounded-lg border text-xs font-semibold break-words ${
                                                        updateView.isLatest
                                                            ? 'bg-emerald-500/5 border-emerald-500/15 text-emerald-400'
                                                            : updateView.kind === 'failed' || updateView.kind === 'interrupted'
                                                            ? 'bg-red-500/10 border-red-500/20 text-red-400'
                                                            : 'bg-amber-500/5 border-amber-500/20 text-amber-300'
                                                    }`}
                                                >
                                                    {updateView.isLatest ? <CheckCircle2 size={15} className="shrink-0" />
                                                        : updateView.isBusy ? <RefreshCw size={15} className="shrink-0 animate-spin" />
                                                        : <AlertCircle size={15} className="shrink-0" />}
                                                    <span className="min-w-0">{updateView.message}</span>
                                                </div>
                                                {updateMessage && (
                                                    <div
                                                        data-testid="system-update-status"
                                                        data-status={updateOutcome}
                                                        className={`text-xs break-words ${updateOutcome === 'error' ? 'text-red-400' : updateOutcome === 'success' ? 'text-emerald-400' : 'text-amber-300'}`}
                                                    >
                                                        {updateMessage}
                                                    </div>
                                                )}
                                                {(updateData?.updateAvailable === true || updateView.isBusy) && (
                                                    <div className="pt-2">
                                                        <button
                                                            type="button"
                                                            data-testid="run-system-update-button"
                                                            onClick={() => void handleRunUpdate(Date.now())}
                                                            disabled={!updateView.canLaunch}
                                                            className="obs-touch-target-standard min-h-[44px] obs-gpu-120hz-interactive w-full px-4 py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-600/50 disabled:cursor-not-allowed text-white font-bold rounded-lg transition-colors text-center"
                                                        >
                                                            {updateView.isBusy ? 'Updating System...' : `Update to ${updateData?.latestVersion || 'release'}`}
                                                        </button>
                                                    </div>
                                                )}
                                    </div>
                                </div>

                                {/* RIGHT CARD: Update Policy & Build Telemetry Overview */}
                                <div className="obs-canvas-section p-5 sm:p-6 flex flex-col justify-between space-y-6">
                                    <div className="space-y-5">
                                        <div className="flex items-center justify-between border-b border-white/[0.07] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                                    <Shield size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Update Policy & Build Telemetry</h3>
                                                    <p className="text-xs text-slate-400">Release notes, rollback guarantees, and daemon upgrade lifecycle.</p>
                                                </div>
                                            </div>
                                            {updateView.updateAvailable && (
                                                <span className="bg-blue-500/20 text-blue-400 text-xs font-bold px-2.5 py-1 rounded-full uppercase tracking-wider animate-pulse border border-blue-500/30">
                                                    {t('updateAvailable')}
                                                </span>
                                            )}
                                        </div>

                                        {updateData?.message ? (
                                            <details open={updateView.isLatest || updateView.kind === 'available'} className="space-y-2">
                                                <summary className="obs-touch-target-standard min-h-[44px] cursor-pointer py-2 text-xs font-bold uppercase tracking-wider text-slate-400 focus-visible:outline-2 focus-visible:outline-indigo-400">
                                                    {updateView.isLatest || updateView.kind === 'available' ? 'Upstream Release Notes & Diagnostics' : 'Last received upstream response (unverified)'}
                                                </summary>
                                                {!updateView.isLatest && updateView.kind !== 'available' && (
                                                    <p className="text-xs leading-relaxed text-amber-300">Historical diagnostics only, not a current release-status confirmation. Use the update status above and Check for Updates to verify.</p>
                                                )}
                                                <div className={`${updateData.latestVersion?.includes('Unknown') ? 'text-amber-400' : 'text-slate-300'} bg-slate-950/50 border border-white/[0.07] p-4 rounded-lg overflow-y-auto max-h-64 break-words custom-scrollbar`}>
                                                    <FlowAiMarkdown
                                                        content={String(updateData.message)
                                                            .replace(/^\uFEFF/, '')
                                                            .replace(/Release Notes \? /g, 'Release Notes \u2014 ')}
                                                        className={updateData.latestVersion?.includes('Unknown') ? 'text-xs text-amber-400' : 'text-xs'}
                                                    />
                                                </div>
                                            </details>
                                        ) : (
                                            <div className="p-4 rounded-lg bg-slate-950/40 border border-white/[0.07] text-xs text-slate-400 leading-relaxed">
                                                AetherFlow performs atomic binary verification and database schema snapshotting prior to applying any release channel updates.
                                            </div>
                                        )}

                                        <div className="rounded-xl border border-white/[0.08] divide-y sm:divide-y-0 sm:divide-x divide-white/[0.07] grid grid-cols-1 sm:grid-cols-2 overflow-hidden bg-transparent">
                                            <div className="p-3.5 bg-transparent">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">Pre-Update Snapshot</span>
                                                <span className="text-xs font-semibold text-emerald-400 mt-1 block">Automatic SQLite Backup</span>
                                            </div>
                                            <div className="p-3.5 bg-transparent">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-400 block">Service Continuity</span>
                                                <span className="text-xs font-semibold text-slate-200 mt-1 block">Zero-Downtime Container Keepalive</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Action Footer Bar */}
                        <div className="obs-canvas-section p-4 px-5 sm:px-6 border-t border-white/[0.07] flex flex-wrap items-center justify-between gap-4">
                            <p className="text-xs text-slate-400">
                                Changes to <span className="text-slate-200 font-semibold">{activeTab === 'preferences' ? 'Interface Preferences' : activeTab === 'ai' ? 'FlowAI Engine' : 'System Updates'}</span> are persisted immediately to the AetherFlow Core database upon saving.
                            </p>
                        </div>
                    </form>
                </div>
            ) : (
                <div className="relative z-10 w-full">
                    {activeTab === 'dashboard' && <DashboardSettingsTab />}
                    {activeTab === 'backups' && <BackupTab />}
                    {activeTab === 'security' && <SecurityTab />}
                    {activeTab === 'profile' && <ProfileTab />}
                    {activeTab === 'oidc-clients' && <OIDCClientsTab />}
                    {activeTab === 'notifications' && <NotificationsSettingsTab />}
                    {activeTab === 'mcbrowser' && <McBrowserSettingsTab />}
                </div>
            )}
        </div>
    );
}
