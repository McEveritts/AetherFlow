import { Settings, Sparkles, ChevronRight, DownloadCloud, AlertCircle, Eye, EyeOff, Key, Monitor, Globe, Clock, LayoutDashboard, Radio, HardDriveDownload, Shield, KeyRound } from 'lucide-react';
import { useState, FormEvent } from 'react';
import useSWR from 'swr';
import dynamic from 'next/dynamic';

const BackupTab = dynamic(() => import('@/components/tabs/BackupTab'), { ssr: false });
const SecurityTab = dynamic(() => import('@/components/tabs/SecurityTab'), { ssr: false });
const OIDCClientsTab = dynamic(() => import('@/components/tabs/OIDCClientsTab'), { ssr: false });
import { useToast } from '@/contexts/ToastContext';
import { useSystemStore } from '@/store/useSystemStore';
import { useTranslations } from 'next-intl';
import { SettingsSkeleton } from '@/components/layout/SkeletonBox';
import { apiFetch } from '@/lib/fetcher';

export default function SettingsTab() {
    const t = useTranslations('Settings');
    const { addToast } = useToast();
    const { theme, setTheme, language, setLanguage, ambientColor1, setAmbientColor1, ambientColor2, setAmbientColor2 } = useSystemStore();
    
    // Tab State
    const [activeTab, setActiveTab] = useState<'preferences' | 'ai' | 'system' | 'backups' | 'security' | 'oidc-clients'>('preferences');
    
    // Config State
    const [model, setModel] = useState('gemini-3.1-pro-preview');
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

    // UI state
    const [showApiKey, setShowApiKey] = useState(false);
    const [showOpenaiApiKey, setShowOpenaiApiKey] = useState(false);
    const [showAnthropicApiKey, setShowAnthropicApiKey] = useState(false);
    const [isSaving, setIsSaving] = useState(false);
    const [isUpdating, setIsUpdating] = useState(false);
    const [updateMessage, setUpdateMessage] = useState('');
    const [isTesting, setIsTesting] = useState(false);

    const handleTestConnection = async () => {
        if (!apiKey) {
            addToast('Constraint failure: Missing API token.', 'error');
            return;
        }
        setIsTesting(true);
        try {
            const res = await apiFetch('/api/v1/admin/settings/test-ai', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ gemini_api_key: apiKey }),
            });
            const data = await res.json();
            if (res.ok) {
                addToast(data.message || 'Connection successful!', 'success');
            } else {
                addToast(data.error || 'Remote connection refused.', 'error');
            }
        } catch (_err) {
            addToast('API dispatch failure: Remote connection test.', 'error');
        } finally {
            setIsTesting(false);
        }
    };

    const { data: updateData, error: updateError } = useSWR(
        '/api/v1/auth/system/update/check',
        { refreshInterval: 60000 }
    );

    const { data: settingsData, isLoading, mutate: mutateSettings } = useSWR(
        '/api/v1/auth/settings',
        {
            onSuccess: (data: Record<string, string>) => {
                if (data.aiModel) setModel(data.aiModel);
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
            }
        }
    );

    if (isLoading) return <SettingsSkeleton />;

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
            defaultDashboard: defaultDashboard
        };

        // Optimistic update
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
                mutateSettings(); // revalidate from server
            } else {
                mutateSettings(prevData, false); // rollback
                addToast('Configuration sync rejected', 'error');
            }
        } catch (_err) {
            mutateSettings(prevData, false); // rollback
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

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full">
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-6 md:p-10 backdrop-blur-xl relative overflow-hidden">
                {/* Background glow for settings */}
                <div className="absolute top-0 right-0 w-[400px] h-[400px] bg-slate-500/10 rounded-full blur-[100px] pointer-events-none -translate-y-1/2 translate-x-1/3"></div>

                <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-6 mb-8 relative z-10">
                    <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
                        <Settings size={28} className="text-slate-400" />
                        {t('title')}
                    </h2>
                </div>

                {/* Horizontal Tabs */}
                <div className="flex gap-2 mb-8 border-b border-white/5 pb-4 overflow-x-auto relative z-10 hide-scrollbar">
                    <button 
                        type="button" 
                        onClick={() => setActiveTab('preferences')}
                        className={`px-4 py-2 rounded-lg text-sm font-semibold transition-colors flex -mt-px border-b-2 items-center gap-2 whitespace-nowrap ${activeTab === 'preferences' ? 'border-indigo-500 text-indigo-400 bg-indigo-500/10' : 'border-transparent text-slate-400 hover:bg-white/5 hover:text-slate-200'}`}
                    >
                        <Monitor size={16} /> {t('interfacePreferences')}
                    </button>
                    <button 
                        type="button" 
                        onClick={() => setActiveTab('ai')}
                        className={`px-4 py-2 rounded-lg text-sm font-semibold transition-colors flex -mt-px border-b-2 items-center gap-2 whitespace-nowrap ${activeTab === 'ai' ? 'border-indigo-500 text-indigo-400 bg-indigo-500/10' : 'border-transparent text-slate-400 hover:bg-white/5 hover:text-slate-200'}`}
                    >
                        <Sparkles size={16} /> {t('flowAIEngine')}
                    </button>
                    <button 
                        type="button" 
                        onClick={() => setActiveTab('system')}
                        className={`px-4 py-2 rounded-lg text-sm font-semibold transition-colors flex -mt-px border-b-2 items-center gap-2 whitespace-nowrap ${activeTab === 'system' ? 'border-indigo-500 text-indigo-400 bg-indigo-500/10' : 'border-transparent text-slate-400 hover:bg-white/5 hover:text-slate-200'}`}
                    >
                        <DownloadCloud size={16} /> {t('systemUpdates')}
                    </button>
                    <button 
                        type="button" 
                        onClick={() => setActiveTab('backups')}
                        className={`px-4 py-2 rounded-lg text-sm font-semibold transition-colors flex -mt-px border-b-2 items-center gap-2 whitespace-nowrap ${activeTab === 'backups' ? 'border-indigo-500 text-indigo-400 bg-indigo-500/10' : 'border-transparent text-slate-400 hover:bg-white/5 hover:text-slate-200'}`}
                    >
                        <HardDriveDownload size={16} /> Backups
                    </button>
                    <button 
                        type="button" 
                        onClick={() => setActiveTab('security')}
                        className={`px-4 py-2 rounded-lg text-sm font-semibold transition-colors flex -mt-px border-b-2 items-center gap-2 whitespace-nowrap ${activeTab === 'security' ? 'border-indigo-500 text-indigo-400 bg-indigo-500/10' : 'border-transparent text-slate-400 hover:bg-white/5 hover:text-slate-200'}`}
                    >
                        <Shield size={16} /> Security
                    </button>
                    <button 
                        type="button" 
                        onClick={() => setActiveTab('oidc-clients')}
                        className={`px-4 py-2 rounded-lg text-sm font-semibold transition-colors flex -mt-px border-b-2 items-center gap-2 whitespace-nowrap ${activeTab === 'oidc-clients' ? 'border-indigo-500 text-indigo-400 bg-indigo-500/10' : 'border-transparent text-slate-400 hover:bg-white/5 hover:text-slate-200'}`}
                    >
                        <KeyRound size={16} /> OIDC Clients
                    </button>
                </div>

                {['preferences', 'ai', 'system'].includes(activeTab) ? (
                <div className="max-w-2xl space-y-8 relative z-10 w-full">
                    <form onSubmit={handleSave} className="space-y-8">
                        
                        {/* -----------------------------
                            TAB: General Preferences 
                        ------------------------------- */}
                        {activeTab === 'preferences' && (
                            <div className="space-y-8 animate-fade-in">
                                {/* CATEGORY: Navigation & Behavior */}
                                <div>
                                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">Navigation & Behavior</h4>
                                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl divide-y divide-white/10 overflow-hidden">
                                        
                                        {/* Default Dashboard */}
                                        <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <LayoutDashboard size={16} className="text-indigo-400" /> Default Dashboard
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1">Select the default view presented after login.</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 relative">
                                                <select
                                                    value={defaultDashboard}
                                                    onChange={(e) => setDefaultDashboard(e.target.value)}
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
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

                                    </div>
                                </div>

                                {/* CATEGORY: Localization */}
                                <div>
                                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">Localization</h4>
                                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl divide-y divide-white/10 overflow-hidden">
                                        
                                        {/* Timezone */}
                                        <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Clock size={16} className="text-blue-400" /> Timezone
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1">Set your local timezone for metrics and logs.</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 relative">
                                                <select
                                                    value={timezone}
                                                    onChange={(e) => setTimezone(e.target.value)}
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
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
                                        <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Globe size={16} className="text-emerald-400" /> {t('language')}
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1">Determine the display language of the system.</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 relative">
                                                <select
                                                    value={language}
                                                    onChange={(e) => setLanguage(e.target.value)}
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
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

                                {/* CATEGORY: Appearance */}
                                <div>
                                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">Appearance</h4>
                                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl divide-y divide-white/10 overflow-hidden">
                                        
                                        {/* Theme */}
                                        <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Monitor size={16} className="text-purple-400" /> {t('displayTheme')}
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1">Adjust the visual theme of the UI.</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 relative">
                                                <select
                                                    value={theme}
                                                    onChange={(e) => setTheme(e.target.value as 'light' | 'dark' | 'system')}
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                                >
                                                    <option value="system">{t('themeSystem')}</option>
                                                    <option value="dark">{t('themeDark')}</option>
                                                    <option value="light">{t('themeLight')}</option>
                                                </select>
                                                <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                            </div>
                                        </div>

                                        {/* Ambient Blends */}
                                        <div className="p-5 flex flex-col md:flex-row justify-between gap-6 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Sparkles size={16} className="text-pink-400" /> Ambient Light Blends
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1">Customize the background lighting gradients globally.</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 flex gap-3">
                                                <div className="flex-1 flex items-center gap-2 bg-slate-900 border border-white/10 rounded-xl px-3 py-2">
                                                    <input 
                                                        type="color" 
                                                        value={ambientColor1} 
                                                        onChange={(e) => setAmbientColor1(e.target.value)}
                                                        className="w-6 h-6 rounded cursor-pointer bg-transparent border-none p-0"
                                                    />
                                                    <span className="text-xs text-slate-300 font-mono">{ambientColor1}</span>
                                                </div>
                                                <div className="flex-1 flex items-center gap-2 bg-slate-900 border border-white/10 rounded-xl px-3 py-2">
                                                    <input 
                                                        type="color" 
                                                        value={ambientColor2} 
                                                        onChange={(e) => setAmbientColor2(e.target.value)}
                                                        className="w-6 h-6 rounded cursor-pointer bg-transparent border-none p-0"
                                                    />
                                                    <span className="text-xs text-slate-300 font-mono">{ambientColor2}</span>
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
                            <div className="space-y-8 animate-fade-in">
                                
                                {/* CATEGORY: Authentication */}
                                <div>
                                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">Authentication</h4>
                                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl divide-y divide-white/10 overflow-hidden">
                                        <div className="p-5 flex flex-col md:flex-row justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Key size={16} className="text-amber-400" /> {t('apiKeyTitle')}
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1 max-w-sm">Get your API key from <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:text-indigo-300 underline">Google AI Studio</a>. Connect to ensure full access to AI features.</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 space-y-3">
                                                <div className="relative">
                                                    <input
                                                        type={showApiKey ? 'text' : 'password'}
                                                        value={apiKey}
                                                        onChange={(e) => setApiKey(e.target.value)}
                                                        placeholder={t('apiKeyPlaceholder')}
                                                        className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 pr-12 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                    />
                                                    <button
                                                        type="button"
                                                        onClick={() => setShowApiKey(!showApiKey)}
                                                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                                                    >
                                                        {showApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                                                    </button>
                                                </div>
                                                <button
                                                    type="button"
                                                    onClick={handleTestConnection}
                                                    disabled={isTesting || !apiKey}
                                                    className="w-full py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-lg text-xs font-semibold text-slate-300 transition-colors flex items-center justify-center gap-2"
                                                >
                                                    {isTesting ? (
                                                        <><div className="w-3 h-3 border-2 border-slate-400/30 border-t-slate-400 rounded-full animate-spin"></div> {t('testing')}</>
                                                    ) : (
                                                        <><Sparkles size={14} className="text-amber-400" /> {t('testApi')}</>
                                                    )}
                                                </button>
                                            </div>
                                        </div>
                                        {/* OpenAI API Key */}
                                        <div className="p-5 flex flex-col md:flex-row justify-between gap-4 hover:bg-white/[0.02] transition-colors border-t border-white/10">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Key size={16} className="text-emerald-400" /> OpenAI API Key
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1 max-w-sm">Connect to the OpenAI ecosystem for access to GPT models. Your key is stored securely.</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 space-y-3">
                                                <div className="relative">
                                                    <input
                                                        type={showOpenaiApiKey ? 'text' : 'password'}
                                                        value={openaiApiKey}
                                                        onChange={(e) => setOpenaiApiKey(e.target.value)}
                                                        placeholder="sk-proj-..."
                                                        className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 pr-12 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                    />
                                                    <button
                                                        type="button"
                                                        onClick={() => setShowOpenaiApiKey(!showOpenaiApiKey)}
                                                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                                                    >
                                                        {showOpenaiApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                        {/* Anthropic API Key */}
                                        <div className="p-5 flex flex-col md:flex-row justify-between gap-4 hover:bg-white/[0.02] transition-colors border-t border-white/10">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Key size={16} className="text-orange-400" /> Anthropic API Key
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1 max-w-sm">Connect to the Anthropic ecosystem for Claude model access. Your key is stored securely.</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 space-y-3">
                                                <div className="relative">
                                                    <input
                                                        type={showAnthropicApiKey ? 'text' : 'password'}
                                                        value={anthropicApiKey}
                                                        onChange={(e) => setAnthropicApiKey(e.target.value)}
                                                        placeholder="sk-ant-..."
                                                        className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 pr-12 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                    />
                                                    <button
                                                        type="button"
                                                        onClick={() => setShowAnthropicApiKey(!showAnthropicApiKey)}
                                                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                                                    >
                                                        {showAnthropicApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* CATEGORY: Local Engines */}
                                <div>
                                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">Local AI Engines</h4>
                                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl divide-y divide-white/10 overflow-hidden">
                                        <div className="p-5 flex flex-col md:flex-row justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Radio size={16} className="text-purple-400" /> LM-Studio Endpoint
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1 max-w-sm">URL to your LM-Studio local server (e.g., http://localhost:1234)</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 space-y-3">
                                                <input
                                                    type="text"
                                                    value={lmStudioEndpoint}
                                                    onChange={(e) => setLmStudioEndpoint(e.target.value)}
                                                    placeholder="http://localhost:1234"
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                />
                                            </div>
                                        </div>
                                        <div className="p-5 flex flex-col md:flex-row justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Radio size={16} className="text-pink-400" /> Ollama Endpoint
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1 max-w-sm">URL to your Ollama service (e.g., http://localhost:11434)</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 space-y-3">
                                                <input
                                                    type="text"
                                                    value={ollamaEndpoint}
                                                    onChange={(e) => setOllamaEndpoint(e.target.value)}
                                                    placeholder="http://localhost:11434"
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                />
                                            </div>
                                        </div>
                                        <div className="p-5 flex flex-col md:flex-row justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Radio size={16} className="text-orange-400" /> Anthropic Custom Endpoint
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1 max-w-sm">Override the default Anthropic API URL if using a proxy or local simulator.</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 space-y-3">
                                                <input
                                                    type="text"
                                                    value={anthropicEndpoint}
                                                    onChange={(e) => setAnthropicEndpoint(e.target.value)}
                                                    placeholder="https://api.anthropic.com/v1/"
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                                />
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* CATEGORY: Model Configuration */}
                                <div>
                                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">Model Configuration</h4>
                                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl divide-y divide-white/10 overflow-hidden">
                                        
                                        {/* Model Selector */}
                                        <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Monitor size={16} className="text-blue-400" /> {t('defaultModel')}
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1">Default model for FlowAI. Can be overridden per-chat.</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 relative">
                                                <select
                                                    value={model}
                                                    onChange={(e) => setModel(e.target.value)}
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                                >
                                                    <optgroup label="Google Primary">
                                                        <option value="gemini-3.1-pro-preview">Gemini 3.1 Pro Preview</option>
                                                        <option value="gemini-3-flash-preview">Gemini 3.0 Flash Preview</option>
                                                        <option value="gemini-3.1-flash-lite-preview">Gemini 3.1 Flash Lite Preview</option>
                                                    </optgroup>
                                                    <optgroup label="OpenAI Base">
                                                        <option value="gpt-4o">GPT-4o</option>
                                                        <option value="gpt-4o-mini">GPT-4o Mini</option>
                                                        <option value="gpt-4-turbo">GPT-4 Turbo</option>
                                                    </optgroup>
                                                    <optgroup label="Anthropic">
                                                        <option value="claude-4-6-sonnet">Claude 4.6 Sonnet</option>
                                                        <option value="claude-4-6-haiku">Claude 4.6 Haiku</option>
                                                        <option value="claude-4-5-opus">Claude 4.5 Opus</option>
                                                    </optgroup>
                                                    <optgroup label="Local Hosted">
                                                        <option value="lm-studio">LM Studio (Local)</option>
                                                        <option value="ollama">Ollama (Local)</option>
                                                    </optgroup>
                                                </select>
                                                <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                            </div>
                                        </div>

                                        {/* System Prompt */}
                                        <div className="p-5 flex flex-col gap-3 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Settings size={16} className="text-purple-400" /> {t('defaultPrompt')}
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1">Tune the prompt to modify the assistant&apos;s behavior and strictness.</p>
                                            </div>
                                            <div className="w-full">
                                                <textarea
                                                    value={prompt}
                                                    onChange={(e) => setPrompt(e.target.value)}
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors min-h-[100px] resize-none"
                                                />
                                            </div>
                                        </div>

                                    </div>
                                </div>

                            </div>
                        )}

                        {/* -----------------------------
                            TAB: System Updates 
                        ------------------------------- */}
                        {activeTab === 'system' && (
                            <div className="space-y-8 animate-fade-in">
                                
                                {/* CATEGORY: Core System */}
                                <div>
                                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">Core System</h4>
                                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl divide-y divide-white/10 overflow-hidden">
                                        <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                                            <div>
                                                <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                                    <Radio size={16} className="text-blue-400" /> Update Channel
                                                </label>
                                                <p className="text-xs text-slate-500 mt-1">Determines which branch of AetherFlow the updater pulls from. Nightly builds may break functionality.</p>
                                            </div>
                                            <div className="shrink-0 w-full md:w-80 relative">
                                                <select
                                                    value={updateChannel}
                                                    onChange={(e) => setUpdateChannel(e.target.value)}
                                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                                >
                                                    <option value="stable">Stable (Recommended)</option>
                                                    <option value="beta">Beta (Early Access)</option>
                                                    <option value="nightly">Nightly (Unstable)</option>
                                                </select>
                                                <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* CATEGORY: Update Engine Controls */}
                                <div>
                                    <div className="flex items-center justify-between px-2 mb-3">
                                        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Update Engine Controls</h4>
                                        {updateData && updateData.updateAvailable && (
                                            <span className="bg-blue-500/20 text-blue-400 text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider animate-pulse">
                                                {t('updateAvailable')}
                                            </span>
                                        )}
                                    </div>
                                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl overflow-hidden p-5">
                                        <div className="space-y-4 text-sm text-slate-400">
                                            {updateError ? (
                                                <div className="flex items-center gap-2 text-red-400 bg-red-500/10 p-4 rounded-xl">
                                                    <AlertCircle size={16} /> Could not fetch update status.
                                                </div>
                                            ) : !updateData ? (
                                                <div className="flex items-center gap-2 text-slate-500">
                                                    <div className="w-4 h-4 border-2 border-slate-500/30 border-t-slate-500 rounded-full animate-spin"></div>
                                                    {t('checkingUpdates')}
                                                </div>
                                            ) : (
                                                <>
                                                    <div className="flex flex-col gap-2 p-4 bg-white/5 rounded-xl border border-white/5">
                                                        <div className="flex justify-between">
                                                            <span>Current Version:</span>
                                                            <span className="font-mono text-slate-300">{updateData.currentVersion}</span>
                                                        </div>
                                                        <div className="flex justify-between">
                                                            <span>Latest Version:</span>
                                                            <span className="font-mono text-slate-300">{updateData.latestVersion}</span>
                                                        </div>
                                                        {updateData.message && (
                                                            <div className={`mt-2 text-xs ${updateData.latestVersion?.includes('Unknown') ? 'text-amber-400' : 'text-slate-500'}`}>
                                                                {updateData.message}
                                                            </div>
                                                        )}
                                                        {updateData.url && !updateData.latestVersion?.includes('Unknown') && (
                                                            <div className="mt-2">
                                                                <a href={updateData.url} target="_blank" rel="noopener noreferrer" className="text-xs text-indigo-400 hover:text-indigo-300 underline transition-colors">
                                                                    View release details →
                                                                </a>
                                                            </div>
                                                        )}
                                                    </div>

                                                    {updateData.updateAvailable ? (
                                                        <div className="pt-4 border-t border-white/10">
                                                            <button
                                                                type="button"
                                                                onClick={handleRunUpdate}
                                                                disabled={isUpdating}
                                                                className="w-full px-4 py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-600/50 disabled:cursor-not-allowed text-white font-bold rounded-xl transition-colors shadow-lg shadow-blue-500/20 text-center"
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
                                                        <div className="text-center p-4">
                                                            <p className="text-slate-500">Your system is up to date.</p>
                                                        </div>
                                                    )}
                                                </>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        <div className="flex items-center gap-4 pt-4">
                            <button
                                type="submit"
                                disabled={isSaving}
                                className="px-8 py-3 bg-indigo-500 hover:bg-indigo-400 disabled:bg-indigo-500/50 rounded-xl text-sm font-bold text-white transition-all shadow-lg shadow-indigo-500/20 flex items-center gap-2"
                            >
                                {isSaving ? t('saving') : t('saveConfig')}
                            </button>
                        </div>
                    </form>
                </div>
                ) : (
                <div className="relative z-10 w-full">
                    {activeTab === 'backups' && <BackupTab />}
                    {activeTab === 'security' && <SecurityTab />}
                    {activeTab === 'oidc-clients' && <OIDCClientsTab />}
                </div>
                )}
            </div>
        </div>
    );
}
