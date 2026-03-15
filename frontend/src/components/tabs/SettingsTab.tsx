import { Settings, Sparkles, ChevronRight, DownloadCloud, AlertCircle, Eye, EyeOff, Key, Monitor, Globe } from 'lucide-react';
import { useState, FormEvent } from 'react';
import useSWR from 'swr';
import { useToast } from '@/contexts/ToastContext';
import { useSystemStore } from '@/store/useSystemStore';
import { useTranslations } from 'next-intl';
import { SettingsSkeleton } from '@/components/layout/SkeletonBox';

export default function SettingsTab() {
    const t = useTranslations('Settings');
    const { addToast } = useToast();
    const { theme, setTheme, language, setLanguage, ambientColor1, setAmbientColor1, ambientColor2, setAmbientColor2 } = useSystemStore();
    const [model, setModel] = useState('gemini-2.5-pro');
    const [prompt, setPrompt] = useState("You are FlowAI, a highly intelligent infrastructure assistant connected to a local Next.js + Go Nexus environment. Always prioritize safe and performant configurations.");
    const [apiKey, setApiKey] = useState('');
    const [showApiKey, setShowApiKey] = useState(false);
    const [isSaving, setIsSaving] = useState(false);
    const [isUpdating, setIsUpdating] = useState(false);
    const [updateMessage, setUpdateMessage] = useState('');
    const [isTesting, setIsTesting] = useState(false);

    const handleTestConnection = async () => {
        if (!apiKey) {
            addToast('Please enter an API key to test.', 'error');
            return;
        }
        setIsTesting(true);
        try {
            const res = await fetch('/api/settings/test-ai', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ gemini_api_key: apiKey }),
            });
            const data = await res.json();
            if (res.ok) {
                addToast(data.message || 'Connection successful!', 'success');
            } else {
                addToast(data.error || 'Connection failed.', 'error');
            }
        } catch (_err) {
            addToast('Network error testing connection.', 'error');
        } finally {
            setIsTesting(false);
        }
    };

    const { data: updateData, error: updateError } = useSWR(
        '/api/system/update/check',
        { refreshInterval: 60000 }
    );

    const { data: settingsData, isLoading, mutate: mutateSettings } = useSWR(
        '/api/settings',
        {
            onSuccess: (data: Record<string, string>) => {
                if (data.aiModel) setModel(data.aiModel);
                if (data.systemPrompt) setPrompt(data.systemPrompt);
                if (data.geminiApiKey) setApiKey(data.geminiApiKey);
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
            language: language,
            theme: theme,
            ambientColor1: ambientColor1,
            ambientColor2: ambientColor2,
            timezone: settingsData?.timezone || 'UTC',
            updateChannel: settingsData?.updateChannel || 'stable',
            defaultDashboard: settingsData?.defaultDashboard || 'overview'
        };

        // Optimistic update
        const prevData = settingsData;
        mutateSettings({ ...settingsData, ...payload }, false);

        try {
            const res = await fetch('/api/settings', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                addToast('Configuration synced to AetherFlow Engine', 'success');
                mutateSettings(); // revalidate from server
            } else {
                mutateSettings(prevData, false); // rollback
                addToast('Failed to sync configuration', 'error');
            }
        } catch (_err) {
            mutateSettings(prevData, false); // rollback
            addToast('Network error saving configuration', 'error');
        } finally {
            setIsSaving(false);
        }
    };

    const handleRunUpdate = async () => {
        setIsUpdating(true);
        setUpdateMessage('Initiating update sequence...');
        try {
            const res = await fetch('/api/system/update/run', {
                method: 'POST'
            });
            const data = await res.json();
            if (res.ok) {
                setUpdateMessage(data.message || 'Update started.');
            } else {
                setUpdateMessage(data.error || 'Failed to start update.');
                setIsUpdating(false);
            }
        } catch (_err) {
            setUpdateMessage('Network error triggering update.');
            setIsUpdating(false);
        }
    };

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full">
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-10 backdrop-blur-xl relative overflow-hidden">
                {/* Background glow for settings */}
                <div className="absolute top-0 right-0 w-[400px] h-[400px] bg-slate-500/10 rounded-full blur-[100px] pointer-events-none -translate-y-1/2 translate-x-1/3"></div>

                <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3 mb-8 pb-4 border-b border-white/5 relative z-10">
                    <Settings size={24} className="text-slate-400" />
                    {t('title')}
                </h2>

                <div className="max-w-2xl space-y-8 relative z-10">
                    <form onSubmit={handleSave} className="space-y-8">
                        {/* Preferences Block */}
                        <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6">
                            <h3 className="text-lg font-bold text-slate-200 mb-6 flex items-center gap-2">
                                <Monitor size={18} className="text-blue-400" /> {t('interfacePreferences')}
                            </h3>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                {/* Theme Selector */}
                                <div>
                                    <label className="block text-sm font-semibold text-slate-300 mb-2">{t('displayTheme')}</label>
                                    <div className="relative">
                                        <select
                                            value={theme}
                                            onChange={(e) => setTheme(e.target.value as 'light' | 'dark' | 'system')}
                                            className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3.5 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                        >
                                            <option value="system">{t('themeSystem')}</option>
                                            <option value="dark">{t('themeDark')}</option>
                                            <option value="light">{t('themeLight')}</option>
                                        </select>
                                        <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                    </div>
                                </div>

                                {/* Language Selector */}
                                <div>
                                    <label className="block text-sm font-semibold text-slate-300 mb-2 flex items-center gap-2">
                                        <Globe size={14} className="text-slate-400" /> {t('language')}
                                    </label>
                                    <div className="relative">
                                        <select
                                            value={language}
                                            onChange={(e) => setLanguage(e.target.value)}
                                            className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3.5 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
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

                                {/* Ambient Colors */}
                                <div className="col-span-1 md:col-span-2">
                                    <label className="block text-sm font-semibold text-slate-300 mb-2">Ambient Light Blends</label>
                                    <div className="flex gap-4">
                                        <div className="flex-1 flex items-center gap-3 bg-slate-900 border border-white/10 rounded-xl px-4 py-3">
                                            <input 
                                                type="color" 
                                                value={ambientColor1} 
                                                onChange={(e) => setAmbientColor1(e.target.value)}
                                                className="w-8 h-8 rounded cursor-pointer bg-transparent border-none p-0"
                                            />
                                            <span className="text-sm text-slate-300 font-mono">{ambientColor1}</span>
                                        </div>
                                        <div className="flex-1 flex items-center gap-3 bg-slate-900 border border-white/10 rounded-xl px-4 py-3">
                                            <input 
                                                type="color" 
                                                value={ambientColor2} 
                                                onChange={(e) => setAmbientColor2(e.target.value)}
                                                className="w-8 h-8 rounded cursor-pointer bg-transparent border-none p-0"
                                            />
                                            <span className="text-sm text-slate-300 font-mono">{ambientColor2}</span>
                                        </div>
                                    </div>
                                    <p className="text-xs text-slate-500 mt-2">Customize the ambient background lighting gradients. Changes preview instantly and apply globally.</p>
                                </div>
                            </div>
                        </div>

                        {/* FlowAI Config block */}
                        <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6">
                            <h3 className="text-lg font-bold text-slate-200 mb-6 flex items-center gap-2">
                                <Sparkles size={18} className="text-indigo-400" /> {t('flowAIEngine')}
                            </h3>
                            <div className="space-y-6">
                                {/* API Key */}
                                <div>
                                    <label className="block text-sm font-semibold text-slate-300 mb-2 flex items-center gap-2">
                                        <Key size={14} className="text-amber-400" /> {t('apiKeyTitle')}
                                    </label>
                                    <div className="relative">
                                        <input
                                            type={showApiKey ? 'text' : 'password'}
                                            value={apiKey}
                                            onChange={(e) => setApiKey(e.target.value)}
                                            placeholder={t('apiKeyPlaceholder')}
                                            className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3.5 pr-12 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors font-mono"
                                        />
                                        <button
                                            type="button"
                                            onClick={() => setShowApiKey(!showApiKey)}
                                            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                                        >
                                            {showApiKey ? <EyeOff size={16} /> : <Eye size={16} />}
                                        </button>
                                    </div>
                                    <p className="text-xs text-slate-500 mt-2">
                                        Get your key from <a href="https://aistudio.google.com/apikey" target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:text-indigo-300 underline">Google AI Studio</a>. Your Ultra plan key gives access to all models.
                                    </p>
                                    <div className="mt-3">
                                        <button
                                            type="button"
                                            onClick={handleTestConnection}
                                            disabled={isTesting || !apiKey}
                                            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-white/10 rounded-lg text-xs font-semibold text-slate-300 transition-colors flex items-center gap-2"
                                        >
                                            {isTesting ? (
                                                <><div className="w-3 h-3 border-2 border-slate-400/30 border-t-slate-400 rounded-full animate-spin"></div> {t('testing')}</>
                                            ) : (
                                                <><Sparkles size={14} className="text-amber-400" /> {t('testApi')}</>
                                            )}
                                        </button>
                                    </div>
                                </div>

                                {/* Model Selector */}
                                <div>
                                    <label className="block text-sm font-semibold text-slate-300 mb-2">{t('defaultModel')}</label>
                                    <div className="relative">
                                        <select
                                            value={model}
                                            onChange={(e) => setModel(e.target.value)}
                                            className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3.5 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                        >
                                            <optgroup label="Latest">
                                                <option value="gemini-2.5-pro">Gemini 2.5 Pro</option>
                                                <option value="gemini-2.5-flash">Gemini 2.5 Flash</option>
                                            </optgroup>
                                            <optgroup label="Stable">
                                                <option value="gemini-2.0-flash">Gemini 2.0 Flash</option>
                                                <option value="gemini-1.5-pro">Gemini 1.5 Pro</option>
                                                <option value="gemini-1.5-flash">Gemini 1.5 Flash</option>
                                            </optgroup>
                                        </select>
                                        <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                    </div>
                                    <p className="text-xs text-slate-500 mt-2">Default model for FlowAI. Can be overridden per-chat via the model selector.</p>
                                </div>

                                {/* System Prompt */}
                                <div>
                                    <label className="block text-sm font-semibold text-slate-300 mb-2">{t('defaultPrompt')}</label>
                                    <textarea
                                        value={prompt}
                                        onChange={(e) => setPrompt(e.target.value)}
                                        className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors min-h-[100px] resize-none"
                                    />
                                    <p className="text-xs text-slate-500 mt-2">Tune the prompt to modify the assistant&apos;s behavior and strictness.</p>
                                </div>
                            </div>
                        </div>

                        <div className="flex items-center gap-4">
                            <button
                                type="submit"
                                disabled={isSaving}
                                className="px-8 py-3 bg-indigo-500 hover:bg-indigo-400 disabled:bg-indigo-500/50 rounded-xl text-sm font-bold text-white transition-all shadow-lg shadow-indigo-500/20 flex items-center gap-2"
                            >
                                {isSaving ? t('saving') : t('saveConfig')}
                            </button>
                        </div>
                    </form>

                    {/* System Updates */}
                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2">
                                <DownloadCloud size={18} className="text-blue-400" /> {t('systemUpdates')}
                            </h3>
                            {updateData && updateData.updateAvailable && (
                                <span className="bg-blue-500/20 text-blue-400 text-xs font-bold px-3 py-1 rounded-full uppercase tracking-wider animate-pulse">
                                    {t('updateAvailable')}
                                </span>
                            )}
                        </div>

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
                                            <div className="text-amber-400 mt-2 text-xs">{updateData.message}</div>
                                        )}
                                    </div>

                                    {updateData.updateAvailable ? (
                                        <div className="pt-4 border-t border-white/10">
                                            <button
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
        </div>
    );
}
