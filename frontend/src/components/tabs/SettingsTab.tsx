import { Settings, Sparkles, ChevronRight, DownloadCloud, AlertCircle } from 'lucide-react';
import { useState, FormEvent } from 'react';
import useSWR from 'swr';
import { useToast } from '@/contexts/ToastContext';

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function SettingsTab() {
    const { addToast } = useToast();
    const [model, setModel] = useState('gemini-1.5-ultra');
    const [prompt, setPrompt] = useState("You are FlowAI, a highly intelligent infrastructure assistant connected to a local Next.js + Go Nexus environment. Always prioritize safe and performant configurations.");
    const [isSaving, setIsSaving] = useState(false);
    const [isUpdating, setIsUpdating] = useState(false);
    const [updateMessage, setUpdateMessage] = useState('');

    const { data: updateData, error: updateError } = useSWR(
        'http://localhost:8080/api/system/update/check',
        fetcher,
        { refreshInterval: 60000 } // Check every minute
    );

    const { data: settingsData } = useSWR(
        'http://localhost:8080/api/settings',
        fetcher,
        {
            revalidateOnFocus: false,
            onSuccess: (data) => {
                if (data.aiModel) setModel(data.aiModel);
                if (data.systemPrompt) setPrompt(data.systemPrompt);
            }
        }
    );

    const handleSave = async (e: FormEvent) => {
        e.preventDefault();
        setIsSaving(true);

        try {
            const payload = {
                aiModel: model,
                systemPrompt: prompt,
                language: settingsData?.language || 'en',
                timezone: settingsData?.timezone || 'UTC',
                updateChannel: settingsData?.updateChannel || 'stable',
                defaultDashboard: settingsData?.defaultDashboard || 'overview'
            };

            const res = await fetch('http://localhost:8080/api/settings', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                addToast('Configuration synced to AetherFlow Engine', 'success');
            } else {
                addToast('Failed to sync configuration', 'error');
            }
        } catch (_err) {
            addToast('Network error saving configuration', 'error');
        } finally {
            setIsSaving(false);
        }
    };

    const handleRunUpdate = async () => {
        setIsUpdating(true);
        setUpdateMessage('Initiating update sequence...');
        try {
            const res = await fetch('http://localhost:8080/api/system/update/run', {
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
                    System Settings & AI Configuration
                </h2>

                <div className="max-w-2xl space-y-8 relative z-10">
                    <form onSubmit={handleSave} className="space-y-8">
                        {/* FlowAI Config block */}
                        <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6">
                            <h3 className="text-lg font-bold text-slate-200 mb-6 flex items-center gap-2">
                                <Sparkles size={18} className="text-indigo-400" /> FlowAI Engine
                            </h3>
                            <div className="space-y-6">
                                <div>
                                    <label className="block text-sm font-semibold text-slate-300 mb-2">Active Language Model (Google OAuth)</label>
                                    <div className="relative">
                                        <select
                                            value={model}
                                            onChange={(e) => setModel(e.target.value)}
                                            className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3.5 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                                        >
                                            <option value="gemini-1.5-ultra">Gemini 1.5 Ultra (Google OAuth Connected)</option>
                                            <option value="gemini-1.5-pro">Gemini 1.5 Pro (Google OAuth Connected)</option>
                                            <option value="gemini-1.0-pro">Gemini 1.0 Pro</option>
                                        </select>
                                        <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                    </div>
                                    <p className="text-xs text-slate-500 mt-2">Select the underlying model for FlowAI computations. Ultra provides best performance for complex log analysis.</p>
                                </div>

                                <div>
                                    <label className="block text-sm font-semibold text-slate-300 mb-2">Default System Prompt</label>
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
                                {isSaving ? 'Saving...' : 'Save Configuration'}
                            </button>
                        </div>
                    </form>

                    {/* System Updates */}
                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6">
                        <div className="flex items-center justify-between mb-6">
                            <h3 className="text-lg font-bold text-slate-200 flex items-center gap-2">
                                <DownloadCloud size={18} className="text-blue-400" /> System Updates
                            </h3>
                            {updateData && updateData.updateAvailable && (
                                <span className="bg-blue-500/20 text-blue-400 text-xs font-bold px-3 py-1 rounded-full uppercase tracking-wider animate-pulse">
                                    Update Available
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
                                    Checking for updates...
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
