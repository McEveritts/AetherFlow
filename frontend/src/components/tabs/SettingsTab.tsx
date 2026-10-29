import { Settings, Sparkles, ChevronRight, DownloadCloud, AlertCircle, Eye, EyeOff, Key, Monitor, Globe, Clock, LayoutDashboard, Radio, HardDriveDownload, Shield, KeyRound, RefreshCw, UserCircle, Bell, Cpu, CheckCircle2, ArrowUpRight, Terminal, Layers, Save } from 'lucide-react';
import { AI_MODELS, ALL_MODEL_IDS, resolveProviderForModel } from '@/lib/ai-models';
import type { AIProviderID } from '@/lib/ai-models';
import { useState, FormEvent } from 'react';
import useSWR from 'swr';
import dynamic from 'next/dynamic';

const BackupTab = dynamic(() => import('@/components/tabs/BackupTab'), { ssr: false });
const SecurityTab = dynamic(() => import('@/components/tabs/SecurityTab'), { ssr: false });
const ProfileTab = dynamic(() => import('@/components/tabs/ProfileTab'), { ssr: false });
const DashboardSettingsTab = dynamic(() => import('@/components/tabs/DashboardSettingsTab'), { ssr: false });
const OIDCClientsTab = dynamic(() => import('@/components/tabs/OIDCClientsTab'), { ssr: false });
const NotificationsSettingsTab = dynamic(() => import('@/components/tabs/NotificationsSettingsTab'), { ssr: false });
import { useToast } from '@/contexts/ToastContext';
import { useSystemStore } from '@/store/useSystemStore';
import { useTranslations } from 'next-intl';
import { SettingsSkeleton } from '@/components/layout/SkeletonBox';
import { apiFetch } from '@/lib/fetcher';
import { useConnectionStore } from '@/store/useConnectionStore';

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
        subtitle: 'GPT 5.4 & GPT 4o Series',
        accent: 'text-emerald-400',
        activeBorder: 'border-emerald-500/40',
        activeBg: 'bg-emerald-500/10',
    },
    {
        id: 'anthropic',
        label: 'Anthropic Claude',
        subtitle: 'Claude Opus & Sonnet 4.6',
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

export default function SettingsTab() {
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
    const { preferredMode, setPreferredMode, pollInterval, setPollInterval } = useConnectionStore();
    
    // Config State
    const [model, setModel] = useState('gemini-4-argon');
    const [prompt, setPrompt] = useState("You are FlowAI, a highly intelligent infrastructure assistant connected to a local Next.js + Go Nexus environment. Always prioritize safe and performant configurations.");
    const [apiKey, setApiKey] = useState('');
    const [openaiApiKey, setOpenaiApiKey] = useState('');
    const [anthropicApiKey, setAnthropicApiKey] = useState('');
    const [lmStudioEndpoint, setLmStudioEndpoint] = useState('');
    const [ollamaEndpoint, setOllamaEndpoint] = useState('');
    const [anthropicEndpoint, setAnthropicEndpoint] = useState('');
    const [timezone, setTimezone] = useState('UTC');
    const [updateChannel, setUpdateChannel] = useState('stable');
    const [defaultDashboard, setDefaultDashboard] = useState('overview');
    const [baseDomain, setBaseDomain] = useState('');

    // UI state
    const [showApiKey, setShowApiKey] = useState(false);
    const [showOpenaiApiKey, setShowOpenaiApiKey] = useState(false);
    const [showAnthropicApiKey, setShowAnthropicApiKey] = useState(false);
    const [isSaving, setIsSaving] = useState(false);
    const [isUpdating, setIsUpdating] = useState(false);
    const [updateMessage, setUpdateMessage] = useState('');
    const [isTesting, setIsTesting] = useState(false);

    const handleTestConnection = async (providerOverride?: string, extraPayload?: Record<string, string>) => {
        const testProvider = providerOverride || resolveProviderForModel(model);
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

    const { data: updateData, error: updateError, isValidating: isCheckingUpdate, mutate: mutateUpdateData } = useSWR(
        '/api/v1/auth/system/update/check',
        { refreshInterval: 60000 }
    );

    const { data: settingsData, isLoading, mutate: mutateSettings } = useSWR(
        '/api/v1/auth/settings',
        {
            onSuccess: (data: Record<string, string>) => {
                if (data.aiModel) {
                    setModel(ALL_MODEL_IDS.includes(data.aiModel) ? data.aiModel : 'gemini-4-argon');
                }
                if (data.systemPrompt) setPrompt(data.systemPrompt);
                if (data.geminiApiKey) setApiKey(data.geminiApiKey);
                if (data.openaiApiKey) setOpenaiApiKey(data.openaiApiKey);
                if (data.anthropicApiKey) setAnthropicApiKey(data.anthropicApiKey);
                if (data.lmStudioEndpoint) setLmStudioEndpoint(data.lmStudioEndpoint);
                if (data.ollamaEndpoint) setOllamaEndpoint(data.ollamaEndpoint);
                if (data.anthropicEndpoint) setAnthropicEndpoint(data.anthropicEndpoint);
                if (data.timezone) setTimezone(data.timezone);
                if (data.updateChannel) setUpdateChannel(data.updateChannel);
                if (data.defaultDashboard) setDefaultDashboard(data.defaultDashboard);
                if (typeof data.baseDomain === 'string') setBaseDomain(data.baseDomain);
            }
        }
    );

    if (isLoading) return <SettingsSkeleton />;

    const activeProvider = resolveProviderForModel(model);
    const activeProviderModels = AI_MODELS[activeProvider] || [];
    const activeModelDef = Object.values(AI_MODELS).flat().find(m => m.id === model) || {
        id: model,
        name: model,
        tier: 'latest' as const,
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
            : model === 'ollama'
            ? ollamaEndpoint || 'http://localhost:11434'
            : model === 'anthropic-local'
            ? anthropicEndpoint || 'http://localhost:8000'
            : lmStudioEndpoint || 'http://localhost:1234';

    const handleSave = async (e: FormEvent) => {
        e.preventDefault();
        setIsSaving(true);

        const payload = {
            aiModel: model,
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

        const prevData = settingsData;
        mutateSettings({ ...settingsData, ...payload }, false);

        try {
            const res = await apiFetch('/api/v1/admin/settings', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                addToast('Configuration synced to AetherFlow Engine', 'success');
                mutateSettings();
            } else {
                mutateSettings(prevData, false);
                const errData = await res.json().catch(() => ({ message: `HTTP ${res.status}` }));
                addToast(errData.message || errData.error || `Configuration sync rejected (${res.status})`, 'error');
            }
        } catch (_err) {
            mutateSettings(prevData, false);
            addToast('API dispatch failure: Configuration flush.', 'error');
        } finally {
            setIsSaving(false);
        }
    };

    const handleRunUpdate = async () => {
        setIsUpdating(true);
        setUpdateMessage('Initiating update sequence...');
        try {
            const res = await apiFetch('/api/v1/admin/system/update/run', {
                method: 'POST'
            });
            const data = await res.json();
            if (res.ok) {
                setUpdateMessage(data.message || 'Update started.');
            } else {
                setUpdateMessage(data.error || 'Daemon update sequence rejected.');
                setIsUpdating(false);
            }
        } catch (_err) {
            setUpdateMessage('API dispatch failure: Daemon update trigger.');
            setIsUpdating(false);
        }
    };

    const handleCheckForUpdates = async () => {
        if (!mutateUpdateData) return;
        addToast('Checking for updates...', 'success');
        await mutateUpdateData();
    };

    return (
        <div className="space-y-6 animate-fade-in relative pb-12 w-full min-w-0">
            {/* Open Top Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-2 border-b border-white/[0.06] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400">
                        <Settings size={20} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">System &amp; Workspace Settings</h2>
                            <span className="text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
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
                            type="button"
                            onClick={handleSave}
                            disabled={isSaving}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-bold transition-all shadow-lg shadow-indigo-500/20 disabled:opacity-50"
                        >
                            <Save size={13} />
                            <span>{isSaving ? 'Saving...' : 'Save Configuration'}</span>
                        </button>
                    )}
                </div>
            </div>

            {/* Horizontal Navigation Pills (flex-wrap so all 9 tabs fit cleanly without clipping) */}
            <div className="flex flex-wrap gap-2 border-b border-white/[0.06] pb-4 relative z-10 obs-touch-pills">
                <button 
                    type="button" 
                    onClick={() => setActiveTab('preferences')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 border whitespace-nowrap ${activeTab === 'preferences' ? 'border-indigo-500/40 text-indigo-300 bg-indigo-500/15 shadow-sm shadow-indigo-500/10' : 'border-white/5 bg-white/[0.02] text-slate-400 hover:bg-white/[0.06] hover:text-slate-200'}`}
                >
                    <Monitor size={15} /> {t('interfacePreferences')}
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('ai')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 border whitespace-nowrap ${activeTab === 'ai' ? 'border-indigo-500/40 text-indigo-300 bg-indigo-500/15 shadow-sm shadow-indigo-500/10' : 'border-white/5 bg-white/[0.02] text-slate-400 hover:bg-white/[0.06] hover:text-slate-200'}`}
                >
                    <Sparkles size={15} /> {t('flowAIEngine')}
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('system')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 border whitespace-nowrap ${activeTab === 'system' ? 'border-indigo-500/40 text-indigo-300 bg-indigo-500/15 shadow-sm shadow-indigo-500/10' : 'border-white/5 bg-white/[0.02] text-slate-400 hover:bg-white/[0.06] hover:text-slate-200'}`}
                >
                    <DownloadCloud size={15} /> {t('systemUpdates')}
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('backups')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 border whitespace-nowrap ${activeTab === 'backups' ? 'border-indigo-500/40 text-indigo-300 bg-indigo-500/15 shadow-sm shadow-indigo-500/10' : 'border-white/5 bg-white/[0.02] text-slate-400 hover:bg-white/[0.06] hover:text-slate-200'}`}
                >
                    <HardDriveDownload size={15} /> Backups
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('security')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 border whitespace-nowrap ${activeTab === 'security' ? 'border-indigo-500/40 text-indigo-300 bg-indigo-500/15 shadow-sm shadow-indigo-500/10' : 'border-white/5 bg-white/[0.02] text-slate-400 hover:bg-white/[0.06] hover:text-slate-200'}`}
                >
                    <Shield size={15} /> Security
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('dashboard')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 border whitespace-nowrap ${activeTab === 'dashboard' ? 'border-indigo-500/40 text-indigo-300 bg-indigo-500/15 shadow-sm shadow-indigo-500/10' : 'border-white/5 bg-white/[0.02] text-slate-400 hover:bg-white/[0.06] hover:text-slate-200'}`}
                >
                    <LayoutDashboard size={15} /> Dashboard
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('profile')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 border whitespace-nowrap ${activeTab === 'profile' ? 'border-indigo-500/40 text-indigo-300 bg-indigo-500/15 shadow-sm shadow-indigo-500/10' : 'border-white/5 bg-white/[0.02] text-slate-400 hover:bg-white/[0.06] hover:text-slate-200'}`}
                >
                    <UserCircle size={15} /> Profile
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('oidc-clients')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 border whitespace-nowrap ${activeTab === 'oidc-clients' ? 'border-indigo-500/40 text-indigo-300 bg-indigo-500/15 shadow-sm shadow-indigo-500/10' : 'border-white/5 bg-white/[0.02] text-slate-400 hover:bg-white/[0.06] hover:text-slate-200'}`}
                >
                    <KeyRound size={15} /> OIDC Clients
                </button>
                <button 
                    type="button" 
                    onClick={() => setActiveTab('notifications')}
                    className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3.5 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 border whitespace-nowrap ${activeTab === 'notifications' ? 'border-indigo-500/40 text-indigo-300 bg-indigo-500/15 shadow-sm shadow-indigo-500/10' : 'border-white/5 bg-white/[0.02] text-slate-400 hover:bg-white/[0.06] hover:text-slate-200'}`}
                >
                    <Bell size={15} /> Notifications
                </button>
            </div>

            {['preferences', 'ai', 'system'].includes(activeTab) ? (
                <div className="space-y-8 relative z-10 w-full">
                    <form onSubmit={handleSave} className="space-y-8 w-full">
                        
                        {/* -----------------------------
                            TAB: General Preferences 
                        ------------------------------- */}
                        {activeTab === 'preferences' && (
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-fade-in w-full">
                                {/* LEFT CARD: Navigation & Localization */}
                                <div className="glass-panel p-6 rounded-2xl border border-white/[0.06] flex flex-col justify-between space-y-6">
                                    <div className="space-y-6">
                                        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-xl bg-indigo-500/15 text-indigo-400 border border-indigo-500/20">
                                                    <LayoutDashboard size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Navigation & Localization</h3>
                                                    <p className="text-xs text-slate-400">Default workspace landing view, regional clock, and display language.</p>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="space-y-5">
                                            {/* Default Dashboard */}
                                            <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-2.5">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <LayoutDashboard size={15} className="text-indigo-400" /> Default Dashboard
                                                    </label>
                                                    <span className="text-xs font-mono uppercase tracking-wider text-slate-500">Post-Login Route</span>
                                                </div>
                                                <p className="text-xs text-slate-500">Select the default view presented immediately after authentication.</p>
                                                <div className="relative">
                                                    <select
                                                        value={defaultDashboard}
                                                        onChange={(e) => setDefaultDashboard(e.target.value)}
                                                        className="obs-touch-target-standard w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                                    >
                                                        <option value="overview">Overview / Metrics</option>
                                                        <option value="services">Services</option>
                                                        <option value="marketplace">Marketplace</option>
                                                        <option value="fileshare">Cloud Files</option>
                                                        <option value="ai">AI Chat</option>
                                                        <option value="backups">Backups</option>
                                                        <option value="security">Security</option>
                                                    </select>
                                                    <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                                </div>
                                            </div>

                                            {/* Timezone */}
                                            <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-2.5">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <Clock size={15} className="text-blue-400" /> Timezone
                                                    </label>
                                                    <span className="text-xs font-mono uppercase tracking-wider text-slate-500">{timezone}</span>
                                                </div>
                                                <p className="text-xs text-slate-500">Set your local timezone for system telemetry, cron schedules, and audit logs.</p>
                                                <div className="relative">
                                                    <select
                                                        value={timezone}
                                                        onChange={(e) => setTimezone(e.target.value)}
                                                        className="obs-touch-target-standard w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                                    >
                                                        <option value="UTC">UTC (Default)</option>
                                                        <option value="America/New_York">America/New_York (EST/EDT)</option>
                                                        <option value="America/Chicago">America/Chicago (CST/CDT)</option>
                                                        <option value="America/Denver">America/Denver (MST/MDT)</option>
                                                        <option value="America/Los_Angeles">America/Los_Angeles (PST/PDT)</option>
                                                        <option value="Europe/London">Europe/London (GMT/BST)</option>
                                                        <option value="Europe/Berlin">Europe/Berlin (CET/CEST)</option>
                                                        <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
                                                        <option value="Australia/Sydney">Australia/Sydney (AEST/AEDT)</option>
                                                    </select>
                                                    <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                                </div>
                                            </div>

                                            {/* Language */}
                                            <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-2.5">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <Globe size={15} className="text-emerald-400" /> {t('language')}
                                                    </label>
                                                    <span className="text-xs font-mono uppercase tracking-wider text-slate-500">{language.toUpperCase()}</span>
                                                </div>
                                                <p className="text-xs text-slate-500">Determine the primary display language of the AetherFlow interface.</p>
                                                <div className="relative">
                                                    <select
                                                        value={language}
                                                        onChange={(e) => setLanguage(e.target.value)}
                                                        className="obs-touch-target-standard w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                                    >
                                                        <option value="en">English</option>
                                                        <option value="zh">中文 (Chinese)</option>
                                                        <option value="es">Español (Spanish)</option>
                                                        <option value="de">Deutsch (German)</option>
                                                        <option value="fr">Français (French)</option>
                                                        <option value="dk">Dansk (Danish)</option>
                                                    </select>
                                                    <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* RIGHT CARD: Connectivity & Telemetry */}
                                <div className="glass-panel p-6 rounded-2xl border border-white/[0.06] flex flex-col justify-between space-y-6">
                                    <div className="space-y-6">
                                        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-xl bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
                                                    <Radio size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Connectivity & Telemetry</h3>
                                                    <p className="text-xs text-slate-400">Reverse-proxy domain routing, realtime transport protocol, and heartbeat cadence.</p>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="space-y-5">
                                            {/* Server Base Domain */}
                                            <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-2.5">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <Globe size={15} className="text-indigo-400" /> Server Base Domain
                                                    </label>
                                                    <span className="text-xs font-mono uppercase tracking-wider text-indigo-400">Apache2 / Caddy Auto-Route</span>
                                                </div>
                                                <p className="text-xs text-slate-500">
                                                    Automatically assigns <span className="font-mono text-indigo-300">jellyfin.{baseDomain.trim().replace(/^\*\./, '') || 'domain.com'}</span> via Apache2 / Caddy reverse proxy when installing apps.
                                                </p>
                                                <input
                                                    type="text"
                                                    value={baseDomain}
                                                    onChange={(e) => setBaseDomain(e.target.value)}
                                                    placeholder="domain.com"
                                                    className="obs-touch-target-standard w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm font-mono focus:outline-none focus:border-indigo-500/50 transition-colors"
                                                />
                                            </div>

                                            {/* Preferred Mode */}
                                            <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-2.5">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <Radio size={15} className="text-indigo-400" /> Preferred Connectivity
                                                    </label>
                                                    <span className="text-xs font-mono uppercase tracking-wider text-emerald-400">{preferredMode}</span>
                                                </div>
                                                <p className="text-xs text-slate-500">Choose between full-duplex WebSockets or stateless REST Polling.</p>
                                                <div className="relative">
                                                    <select
                                                        value={preferredMode}
                                                        onChange={(e) => setPreferredMode(e.target.value as 'websocket' | 'poll')}
                                                        className="obs-touch-target-standard w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                                    >
                                                        <option value="websocket">Auto-Connect (WebSockets)</option>
                                                        <option value="poll">Nexus Link (REST Polling)</option>
                                                    </select>
                                                    <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                                </div>
                                            </div>

                                            {/* Polling Interval */}
                                            <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-2.5">
                                                <div className="flex items-center justify-between">
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <Clock size={15} className="text-blue-400" /> Refresh Heartbeat
                                                    </label>
                                                    <span className="text-xs font-mono uppercase tracking-wider text-slate-400">{pollInterval / 1000}s</span>
                                                </div>
                                                <p className="text-xs text-slate-500">Set the telemetry synchronization frequency for the dashboard.</p>
                                                <div className="relative">
                                                    <select
                                                        value={pollInterval}
                                                        onChange={(e) => setPollInterval(Number(e.target.value))}
                                                        className="obs-touch-target-standard w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                                    >
                                                        <option value={1000}>1 Second (Hyper)</option>
                                                        <option value={2000}>2 Seconds (Fast)</option>
                                                        <option value={5000}>5 Seconds (Normal)</option>
                                                        <option value={10000}>10 Seconds (Stable)</option>
                                                        <option value={30000}>30 Seconds (Eco)</option>
                                                    </select>
                                                    <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                                </div>
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
                            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 animate-fade-in w-full">
                                {/* LEFT/MAIN COLUMN: Active Provider, Model Selector, and Credentials */}
                                <div className="lg:col-span-7 space-y-6">
                                    {/* Active Provider & Default Model Card */}
                                    <div className="glass-panel p-6 rounded-2xl border border-white/[0.06] space-y-6">
                                        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-xl bg-indigo-500/15 text-indigo-400 border border-indigo-500/20">
                                                    <Cpu size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Active Provider & Model Configuration</h3>
                                                    <p className="text-xs text-slate-400">Select your primary AI ecosystem and default inference model.</p>
                                                </div>
                                            </div>
                                            <span className="px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                                                {activeModelDef.name}
                                            </span>
                                        </div>

                                        {/* Provider Selector Cards */}
                                        <div>
                                            <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-3">
                                                Inference Provider Ecosystem
                                            </label>
                                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                                                {PROVIDER_CARDS.map((prov) => {
                                                    const isSelected = activeProvider === prov.id;
                                                    return (
                                                        <button
                                                            key={prov.id}
                                                            type="button"
                                                            onClick={() => {
                                                                if (activeProvider !== prov.id && AI_MODELS[prov.id]?.[0]?.id) {
                                                                    setModel(AI_MODELS[prov.id][0].id);
                                                                }
                                                            }}
                                                            className={`obs-touch-target-standard obs-gpu-120hz-interactive p-3.5 rounded-xl border text-left transition-all flex flex-col justify-between gap-2 ${
                                                                isSelected
                                                                    ? `${prov.activeBg} ${prov.activeBorder} shadow-lg`
                                                                    : 'bg-slate-950/50 border-white/[0.06] hover:bg-white/[0.04] hover:border-white/15'
                                                            }`}
                                                        >
                                                            <div className="flex items-center justify-between">
                                                                <Sparkles size={15} className={isSelected ? prov.accent : 'text-slate-500'} />
                                                                <span className={`h-2 w-2 rounded-full ${isSelected ? 'bg-indigo-400 shadow-[0_0_8px_rgba(129,140,248,0.8)]' : 'bg-slate-700'}`} />
                                                            </div>
                                                            <div>
                                                                <div className="text-xs font-bold text-slate-100 leading-tight">{prov.label}</div>
                                                                <div className="text-xs text-slate-500 mt-0.5 line-clamp-1">{prov.subtitle}</div>
                                                            </div>
                                                        </button>
                                                    );
                                                })}
                                            </div>
                                        </div>

                                        {/* Default AI Model Selector */}
                                        <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-3">
                                            <div className="flex flex-wrap items-center justify-between gap-2">
                                                <div>
                                                    <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                        <Monitor size={15} className="text-blue-400" /> {t('defaultModel')}
                                                    </label>
                                                    <p className="text-xs text-slate-500 mt-0.5">Default model loaded when launching FlowAI Assistant. Can be switched per-chat.</p>
                                                </div>
                                                <span className="text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                                                    Tier: {activeModelDef.tier}
                                                </span>
                                            </div>

                                            {/* Quick Model Pills for Active Provider */}
                                            <div className="flex flex-wrap gap-2 pt-1">
                                                {activeProviderModels.map((m) => (
                                                    <button
                                                        key={m.id}
                                                        type="button"
                                                        onClick={() => setModel(m.id)}
                                                        className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all border flex items-center gap-2 ${
                                                            model === m.id
                                                                ? 'bg-indigo-500/20 border-indigo-500/40 text-indigo-200 shadow-sm'
                                                                : 'bg-slate-900/80 border-white/10 text-slate-400 hover:text-slate-200 hover:bg-white/5'
                                                        }`}
                                                    >
                                                        <span>{m.name}</span>
                                                        <span className="text-xs uppercase tracking-wider px-1.5 py-0.2 rounded bg-black/30 text-slate-400">
                                                            {m.tier}
                                                        </span>
                                                    </button>
                                                ))}
                                            </div>

                                            <div className="relative pt-1">
                                                <select
                                                    value={model}
                                                    onChange={(e) => setModel(e.target.value)}
                                                    className="obs-touch-target-standard w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                                >
                                                    {Object.entries(AI_MODELS).map(([providerId, models]) => (
                                                        <optgroup key={providerId} label={providerId.charAt(0).toUpperCase() + providerId.slice(1)}>
                                                            {models.map((m) => (
                                                                <option key={m.id} value={m.id}>{m.name}</option>
                                                            ))}
                                                        </optgroup>
                                                    ))}
                                                </select>
                                                <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                            </div>
                                        </div>
                                    </div>

                                    {/* Cloud Provider API Keys Card */}
                                    <div className="glass-panel p-6 rounded-2xl border border-white/[0.06] space-y-5">
                                        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-xl bg-amber-500/15 text-amber-400 border border-amber-500/20">
                                                    <Key size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Cloud Provider API Keys</h3>
                                                    <p className="text-xs text-slate-400">Encrypted credentials for Google Gemini, OpenAI, and Anthropic Claude.</p>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="space-y-4">
                                            {/* Google Gemini API Key */}
                                            <div className={`p-4 rounded-xl border transition-colors space-y-3 ${activeProvider === 'gemini' ? 'bg-amber-500/[0.04] border-amber-500/25' : 'bg-slate-950/50 border-white/[0.06]'}`}>
                                                <div className="flex flex-wrap items-center justify-between gap-2">
                                                    <div>
                                                        <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                            <Key size={15} className="text-amber-400" /> {t('apiKeyTitle')}
                                                        </label>
                                                        <p className="text-xs text-slate-500 mt-0.5">
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
                                                            onChange={(e) => setApiKey(e.target.value)}
                                                            placeholder={t('apiKeyPlaceholder')}
                                                            className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-2.5 pr-11 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                        />
                                                        <button
                                                            type="button"
                                                            onClick={() => setShowApiKey(!showApiKey)}
                                                            className="obs-touch-target-standard absolute right-1 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors flex items-center justify-center"
                                                        >
                                                            {showApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                                                        </button>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleTestConnection('gemini')}
                                                        disabled={isTesting || !apiKey}
                                                        className="obs-touch-target-standard obs-gpu-120hz-interactive px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-xl text-xs font-semibold text-slate-200 transition-colors flex items-center justify-center gap-2 shrink-0"
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
                                            <div className={`p-4 rounded-xl border transition-colors space-y-3 ${activeProvider === 'openai' ? 'bg-emerald-500/[0.04] border-emerald-500/25' : 'bg-slate-950/50 border-white/[0.06]'}`}>
                                                <div className="flex flex-wrap items-center justify-between gap-2">
                                                    <div>
                                                        <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                            <Key size={15} className="text-emerald-400" /> OpenAI API Key
                                                        </label>
                                                        <p className="text-xs text-slate-500 mt-0.5">Connect to OpenAI for GPT 5.4 and GPT-4o model families.</p>
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
                                                            onChange={(e) => setOpenaiApiKey(e.target.value)}
                                                            placeholder="sk-proj-..."
                                                            className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-2.5 pr-11 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                        />
                                                        <button
                                                            type="button"
                                                            onClick={() => setShowOpenaiApiKey(!showOpenaiApiKey)}
                                                            className="obs-touch-target-standard absolute right-1 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors flex items-center justify-center"
                                                        >
                                                            {showOpenaiApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                                                        </button>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleTestConnection('openai')}
                                                        disabled={isTesting || !openaiApiKey}
                                                        className="obs-touch-target-standard obs-gpu-120hz-interactive px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-xl text-xs font-semibold text-slate-200 transition-colors flex items-center justify-center gap-2 shrink-0"
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
                                            <div className={`p-4 rounded-xl border transition-colors space-y-3 ${activeProvider === 'anthropic' ? 'bg-orange-500/[0.04] border-orange-500/25' : 'bg-slate-950/50 border-white/[0.06]'}`}>
                                                <div className="flex flex-wrap items-center justify-between gap-2">
                                                    <div>
                                                        <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                            <Key size={15} className="text-orange-400" /> Anthropic API Key
                                                        </label>
                                                        <p className="text-xs text-slate-500 mt-0.5">Connect to Anthropic for Claude Opus and Sonnet models.</p>
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
                                                            onChange={(e) => setAnthropicApiKey(e.target.value)}
                                                            placeholder="sk-ant-..."
                                                            className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-2.5 pr-11 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                        />
                                                        <button
                                                            type="button"
                                                            onClick={() => setShowAnthropicApiKey(!showAnthropicApiKey)}
                                                            className="obs-touch-target-standard absolute right-1 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors flex items-center justify-center"
                                                        >
                                                            {showAnthropicApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                                                        </button>
                                                    </div>
                                                    <button
                                                        type="button"
                                                        onClick={() => handleTestConnection('anthropic')}
                                                        disabled={isTesting || !anthropicApiKey}
                                                        className="obs-touch-target-standard obs-gpu-120hz-interactive px-4 py-2.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-xl text-xs font-semibold text-slate-200 transition-colors flex items-center justify-center gap-2 shrink-0"
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
                                    <div className="glass-panel p-6 rounded-2xl border border-white/[0.06] space-y-5">
                                        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-xl bg-purple-500/15 text-purple-400 border border-purple-500/20">
                                                    <Radio size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Local & Custom AI Endpoints</h3>
                                                    <p className="text-xs text-slate-400">Self-hosted inference servers (LM Studio, Ollama) and custom proxy base URLs.</p>
                                                </div>
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                            <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-2.5">
                                                <label className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                                                    <Radio size={14} className="text-purple-400" /> LM-Studio Endpoint
                                                </label>
                                                <input
                                                    type="text"
                                                    value={lmStudioEndpoint}
                                                    onChange={(e) => setLmStudioEndpoint(e.target.value)}
                                                    placeholder="http://localhost:1234"
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-3.5 py-2.5 text-slate-200 text-xs focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                />
                                                <button
                                                    type="button"
                                                    onClick={() => handleTestConnection('localai', { endpoint: lmStudioEndpoint || 'http://localhost:1234' })}
                                                    disabled={isTesting}
                                                    className="obs-touch-target-standard obs-gpu-120hz-interactive w-full py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-lg text-xs font-semibold text-slate-300 transition-colors flex items-center justify-center gap-2"
                                                >
                                                    <Radio size={13} className="text-purple-400" /> Test LM Studio
                                                </button>
                                            </div>

                                            <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-2.5">
                                                <label className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                                                    <Radio size={14} className="text-pink-400" /> Ollama Endpoint
                                                </label>
                                                <input
                                                    type="text"
                                                    value={ollamaEndpoint}
                                                    onChange={(e) => setOllamaEndpoint(e.target.value)}
                                                    placeholder="http://localhost:11434"
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-3.5 py-2.5 text-slate-200 text-xs focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                />
                                                <button
                                                    type="button"
                                                    onClick={() => handleTestConnection('localai', { endpoint: ollamaEndpoint || 'http://localhost:11434' })}
                                                    disabled={isTesting}
                                                    className="obs-touch-target-standard obs-gpu-120hz-interactive w-full py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-lg text-xs font-semibold text-slate-300 transition-colors flex items-center justify-center gap-2"
                                                >
                                                    <Radio size={13} className="text-pink-400" /> Test Ollama
                                                </button>
                                            </div>
                                        </div>

                                        <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-2">
                                            <label className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                                                <Radio size={14} className="text-orange-400" /> Anthropic Custom Endpoint
                                            </label>
                                            <p className="text-xs text-slate-500">Override the default Anthropic API URL if using an enterprise gateway or local simulator.</p>
                                            <input
                                                type="text"
                                                value={anthropicEndpoint}
                                                onChange={(e) => setAnthropicEndpoint(e.target.value)}
                                                placeholder="https://api.anthropic.com/v1/"
                                                className="w-full bg-slate-900 border border-white/10 rounded-xl px-3.5 py-2.5 text-slate-200 text-xs focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                            />
                                        </div>
                                    </div>
                                </div>

                                {/* RIGHT COLUMN: FlowAI Engine Architecture & System Prompt Guardrails */}
                                <div className="lg:col-span-5 space-y-6">
                                    {/* FlowAI Engine Architecture & Capabilities Card */}
                                    <div className="glass-panel p-6 rounded-2xl border border-white/[0.06] space-y-5">
                                        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-xl bg-indigo-500/15 text-indigo-400 border border-indigo-500/20">
                                                    <Sparkles size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">FlowAI Engine Architecture</h3>
                                                    <p className="text-xs text-slate-400">Live runtime summary & autonomous capabilities.</p>
                                                </div>
                                            </div>
                                            <span className={`px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${
                                                isActiveProviderConfigured
                                                    ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                                                    : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                            }`}>
                                                {isActiveProviderConfigured ? 'Engine Ready' : 'Needs Credentials'}
                                            </span>
                                        </div>

                                        <div className="grid grid-cols-2 gap-3">
                                            <div className="p-3.5 rounded-xl bg-slate-950/60 border border-white/[0.05]">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">Selected Provider</span>
                                                <span className="text-sm font-bold text-slate-100 mt-1 block capitalize">{activeProvider}</span>
                                            </div>
                                            <div className="p-3.5 rounded-xl bg-slate-950/60 border border-white/[0.05]">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">Default Model</span>
                                                <span className="text-sm font-bold text-indigo-300 mt-1 block truncate">{activeModelDef.name}</span>
                                            </div>
                                            <div className="p-3.5 rounded-xl bg-slate-950/60 border border-white/[0.05] col-span-2">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">Active Endpoint Route</span>
                                                <span className="text-xs font-mono text-slate-300 mt-1 block truncate">{activeEndpointSummary}</span>
                                            </div>
                                        </div>

                                        <div className="space-y-2.5 pt-1">
                                            <div className="flex items-center justify-between p-3 rounded-xl bg-white/[0.02] border border-white/[0.05] text-xs">
                                                <span className="text-slate-300 flex items-center gap-2 font-medium">
                                                    <CheckCircle2 size={14} className="text-emerald-400" /> Approval Inbox Action Queueing
                                                </span>
                                                <span className="text-xs font-mono uppercase text-emerald-400">Enabled</span>
                                            </div>
                                            <div className="flex items-center justify-between p-3 rounded-xl bg-white/[0.02] border border-white/[0.05] text-xs">
                                                <span className="text-slate-300 flex items-center gap-2 font-medium">
                                                    <Layers size={14} className="text-indigo-400" /> Live Telemetry & Log Context Injection
                                                </span>
                                                <span className="text-xs font-mono uppercase text-indigo-400">Active</span>
                                            </div>
                                        </div>

                                        <button
                                            type="button"
                                            onClick={() => setActiveMainTab('ai')}
                                            className="obs-touch-target-standard obs-gpu-120hz-interactive w-full py-3 px-4 rounded-xl bg-indigo-500/15 hover:bg-indigo-500/25 border border-indigo-500/30 text-indigo-300 text-xs font-bold transition-all flex items-center justify-center gap-2"
                                        >
                                            <Sparkles size={15} />
                                            <span>Launch FlowAI Assistant</span>
                                            <ArrowUpRight size={15} />
                                        </button>
                                    </div>

                                    {/* System Prompt Guardrails Card */}
                                    <div className="glass-panel p-6 rounded-2xl border border-white/[0.06] space-y-4">
                                        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-xl bg-purple-500/15 text-purple-400 border border-purple-500/20">
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
                                            value={prompt}
                                            onChange={(e) => setPrompt(e.target.value)}
                                            rows={6}
                                            className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-xs leading-relaxed font-mono focus:outline-none focus:border-indigo-500/50 transition-colors min-h-[140px] resize-y"
                                        />
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* -----------------------------
                            TAB: System Updates 
                        ------------------------------- */}
                        {activeTab === 'system' && (
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 animate-fade-in w-full">
                                {/* LEFT CARD: Release Channel & Update Status */}
                                <div className="glass-panel p-6 rounded-2xl border border-white/[0.06] space-y-6">
                                    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] pb-4">
                                        <div className="flex items-center gap-3">
                                            <div className="p-2.5 rounded-xl bg-indigo-500/15 text-indigo-400 border border-indigo-500/20">
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
                                            className="obs-touch-target-standard obs-gpu-120hz-interactive bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/20 rounded-xl px-3.5 py-2 text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
                                        >
                                            <RefreshCw size={14} className={isCheckingUpdate ? "animate-spin" : ""} />
                                            {isCheckingUpdate ? 'Checking...' : 'Check for Updates'}
                                        </button>
                                    </div>

                                    <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] space-y-2.5">
                                        <div className="flex items-center justify-between">
                                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                <Radio size={15} className="text-indigo-400" /> Update Channel
                                            </label>
                                            <span className="text-xs font-mono uppercase tracking-wider text-indigo-400">{updateChannel}</span>
                                        </div>
                                        <p className="text-xs text-slate-500">Select the release branch. Save configuration to apply channel changes.</p>
                                        <div className="relative">
                                            <select
                                                value={updateChannel}
                                                onChange={(e) => setUpdateChannel(e.target.value)}
                                                className="obs-touch-target-standard w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                            >
                                                <option value="stable">Stable (Recommended)</option>
                                                <option value="beta">Beta (Early Access)</option>
                                                <option value="nightly">Nightly (Unstable)</option>
                                            </select>
                                            <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                        </div>
                                    </div>

                                    <div className="space-y-4 text-sm text-slate-400">
                                        {updateError ? (
                                            <div className="flex items-center gap-2 text-red-400 bg-red-500/10 border border-red-500/20 p-4 rounded-xl">
                                                <AlertCircle size={16} /> Could not fetch update status.
                                            </div>
                                        ) : !updateData ? (
                                            <div className="flex items-center gap-2 text-slate-500 p-4 border border-white/5 rounded-xl bg-white/[0.01]">
                                                <div className="w-4 h-4 border-2 border-slate-500/30 border-t-slate-500 rounded-full animate-spin"></div>
                                                {t('checkingUpdates')}
                                            </div>
                                        ) : (
                                            <>
                                                <div className="flex flex-col gap-3 p-4 bg-slate-950/60 rounded-xl border border-white/[0.06]">
                                                    <div className="flex justify-between items-center">
                                                        <span className="text-xs font-semibold text-slate-400">Current Version</span>
                                                        <span className="font-mono text-xs font-bold text-slate-200 px-2.5 py-1 rounded-lg bg-white/5 border border-white/5">{updateData.currentVersion}</span>
                                                    </div>
                                                    <div className="flex justify-between items-center">
                                                        <span className="text-xs font-semibold text-slate-400">Latest Upstream Version</span>
                                                        <span className="font-mono text-xs font-bold text-indigo-300 px-2.5 py-1 rounded-lg bg-indigo-500/10 border border-indigo-500/20">{updateData.latestVersion}</span>
                                                    </div>
                                                    {updateData.url && !updateData.latestVersion?.includes('Unknown') && (
                                                        <div className="pt-1 border-t border-white/5 flex justify-end">
                                                            <a href={updateData.url} target="_blank" rel="noopener noreferrer" className="text-xs text-indigo-400 hover:text-indigo-300 underline transition-colors">
                                                                View release details →
                                                            </a>
                                                        </div>
                                                    )}
                                                </div>

                                                {updateData.updateAvailable ? (
                                                    <div className="pt-2">
                                                        <button
                                                            type="button"
                                                            onClick={handleRunUpdate}
                                                            disabled={isUpdating}
                                                            className="obs-touch-target-standard obs-gpu-120hz-interactive w-full px-4 py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-600/50 disabled:cursor-not-allowed text-white font-bold rounded-xl transition-colors shadow-lg shadow-blue-500/20 text-center"
                                                        >
                                                            {isUpdating ? 'Updating System...' : `Update to ${updateData.latestVersion}`}
                                                        </button>
                                                        {updateMessage && (
                                                            <div className={`mt-3 text-xs text-center ${updateMessage.includes('error') || updateMessage.includes('Failed') ? 'text-red-400' : 'text-emerald-400'}`}>
                                                                {updateMessage}
                                                            </div>
                                                        )}
                                                    </div>
                                                ) : (
                                                    <div className="flex items-center justify-center gap-2 p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/15 text-emerald-400 text-xs font-semibold">
                                                        <CheckCircle2 size={15} />
                                                        <span>Your system is running the latest release on the {updateChannel} channel.</span>
                                                    </div>
                                                )}
                                            </>
                                        )}
                                    </div>
                                </div>

                                {/* RIGHT CARD: Update Policy & Build Telemetry Overview */}
                                <div className="glass-panel p-6 rounded-2xl border border-white/[0.06] flex flex-col justify-between space-y-6">
                                    <div className="space-y-5">
                                        <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2.5 rounded-xl bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
                                                    <Shield size={18} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-bold text-slate-100">Update Policy & Build Telemetry</h3>
                                                    <p className="text-xs text-slate-400">Release notes, rollback guarantees, and daemon upgrade lifecycle.</p>
                                                </div>
                                            </div>
                                            {updateData && updateData.updateAvailable && (
                                                <span className="bg-blue-500/20 text-blue-400 text-xs font-bold px-2.5 py-1 rounded-full uppercase tracking-wider animate-pulse border border-blue-500/30">
                                                    {t('updateAvailable')}
                                                </span>
                                            )}
                                        </div>

                                        {updateData?.message ? (
                                            <div className="space-y-2">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">Upstream Release Notes & Diagnostics</span>
                                                <div className={`text-xs ${updateData.latestVersion?.includes('Unknown') ? 'text-amber-400' : 'text-slate-300'} bg-slate-950/60 border border-white/[0.06] p-4 rounded-xl overflow-y-auto max-h-56 break-words whitespace-pre-wrap font-mono leading-relaxed`}>
                                                    {updateData.message}
                                                </div>
                                            </div>
                                        ) : (
                                            <div className="p-4 rounded-xl bg-slate-950/50 border border-white/[0.06] text-xs text-slate-400 leading-relaxed">
                                                AetherFlow performs atomic binary verification and database schema snapshotting prior to applying any release channel updates.
                                            </div>
                                        )}

                                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                            <div className="p-3.5 rounded-xl bg-slate-950/50 border border-white/[0.06]">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">Pre-Update Snapshot</span>
                                                <span className="text-xs font-semibold text-emerald-400 mt-1 block">Automatic SQLite Backup</span>
                                            </div>
                                            <div className="p-3.5 rounded-xl bg-slate-950/50 border border-white/[0.06]">
                                                <span className="text-xs font-bold uppercase tracking-wider text-slate-500 block">Service Continuity</span>
                                                <span className="text-xs font-semibold text-slate-200 mt-1 block">Zero-Downtime Container Keepalive</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Action Footer Bar */}
                        <div className="glass-panel p-4 px-6 rounded-2xl border border-white/[0.06] flex flex-wrap items-center justify-between gap-4">
                            <p className="text-xs text-slate-400">
                                Changes to <span className="text-slate-200 font-semibold">{activeTab === 'preferences' ? 'Interface Preferences' : activeTab === 'ai' ? 'FlowAI Engine' : 'System Updates'}</span> are persisted immediately to the AetherFlow Core database upon saving.
                            </p>
                            <button
                                type="submit"
                                disabled={isSaving}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-500/50 rounded-xl text-xs font-bold text-white transition-all shadow-lg shadow-indigo-500/20 flex items-center gap-2"
                            >
                                <Save size={15} />
                                {isSaving ? t('saving') : t('saveConfig')}
                            </button>
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
                </div>
            )}
        </div>
    );
}
