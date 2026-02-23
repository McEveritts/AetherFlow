'use client';

import { RefreshCw, Box, Settings, Globe, RotateCcw, Square, Play, Server, Cpu } from 'lucide-react';
import { useState } from 'react';
import useSWR from 'swr';
import { useToast } from '@/contexts/ToastContext';

const fetcher = (url: string) => fetch(url).then((res) => res.json());

interface ServiceInfo {
    status: string;
    version: string;
    uptime: string;
    managed_by?: string;
    process?: string;
}

export default function ServicesTab() {
    const { addToast } = useToast();
    const [loadingService, setLoadingService] = useState<string | null>(null);

    const { data: services, mutate, isLoading } = useSWR<Record<string, ServiceInfo>>(
        '/api/services',
        fetcher,
        { refreshInterval: 15000 }
    );

    const handleServiceControl = async (name: string, data: ServiceInfo, action: 'start' | 'stop' | 'restart') => {
        setLoadingService(name);
        try {
            const res = await fetch(`/api/services/${encodeURIComponent(name)}/control`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action,
                    managed_by: data.managed_by || 'systemd',
                    process: data.process || name,
                })
            });
            if (!res.ok) {
                const d = await res.json().catch(() => ({}));
                throw new Error(d.error || 'Failed to control service');
            }
            addToast(`Successfully executed '${action}' on ${name}.`, 'success');
            // Auto-refresh after a short delay to let the service state change
            setTimeout(() => mutate(), 1500);
        } catch (err: unknown) {
            addToast(err instanceof Error ? err.message : 'An unknown error occurred.', 'error');
        } finally {
            setLoadingService(null);
        }
    };

    const allEntries = Object.entries(services || {});

    // Separate core platform services from installed apps
    const coreServices = allEntries.filter(([, d]) => {
        const info = d as ServiceInfo;
        return info.managed_by === 'pm2' || ['apache2', 'nginx'].includes(info.process || '');
    });
    const appServices = allEntries.filter(([, d]) => {
        const info = d as ServiceInfo;
        return info.managed_by !== 'pm2' && !['apache2', 'nginx'].includes(info.process || '');
    });

    const runningCount = allEntries.filter(([, d]) => (d as ServiceInfo).status === 'running').length;

    const renderServiceCard = (name: string, rawData: unknown) => {
        const data = rawData as ServiceInfo;
        const isRunning = data.status === 'running';
        const isError = data.status === 'error';
        const isBusy = loadingService === name;

        return (
            <div key={name} className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-6 hover:bg-white/[0.04] transition-all hover:border-white/10 group cursor-default relative overflow-hidden">
                <div className={`absolute top-0 left-0 w-1 h-full ${isRunning ? 'bg-emerald-500/50' : (isError ? 'bg-red-500/50' : 'bg-slate-500/50')} transition-colors`}></div>

                <div className="flex justify-between items-start mb-6">
                    <div className="flex items-center gap-4">
                        <div className="h-12 w-12 rounded-2xl bg-slate-900 border border-white/10 flex items-center justify-center shadow-inner group-hover:scale-105 transition-transform">
                            {data.managed_by === 'pm2' ? (
                                <Cpu size={24} className={isRunning ? 'text-emerald-400' : (isError ? 'text-red-400' : 'text-slate-500')} />
                            ) : (
                                <Box size={24} className={isRunning ? 'text-emerald-400' : (isError ? 'text-red-400' : 'text-slate-500')} />
                            )}
                        </div>
                        <div>
                            <h3 className="text-base font-bold text-slate-200 group-hover:text-white transition-colors">{name}</h3>
                            <div className="flex items-center gap-2 mt-1">
                                <span className="relative flex h-2 w-2">
                                    {isRunning && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
                                    <span className={`relative inline-flex rounded-full h-2 w-2 ${isRunning ? 'bg-emerald-500' : (isError ? 'bg-red-500' : 'bg-slate-500')}`}></span>
                                </span>
                                <span className="text-xs font-medium text-slate-400 capitalize">{data.status}</span>
                                {data.managed_by && (
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-slate-500 border border-white/5 uppercase tracking-wider">
                                        {data.managed_by}
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>
                    <button className="p-2 text-slate-500 hover:text-slate-300 hover:bg-white/5 rounded-lg transition-colors">
                        <Settings size={18} />
                    </button>
                </div>

                <div className="grid grid-cols-2 gap-4 mb-6">
                    <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.02]">
                        <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Version</span>
                        <p className="text-sm font-medium text-slate-300 mt-0.5">{data.version || '-'}</p>
                    </div>
                    <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.02]">
                        <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Uptime</span>
                        <p className="text-sm font-medium text-slate-300 mt-0.5">{data.uptime || '-'}</p>
                    </div>
                </div>

                <div className="flex gap-2">
                    {isRunning ? (
                        <>
                            <button className="flex-1 py-2 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50" disabled={isBusy}>
                                <Globe size={14} /> Web UI
                            </button>
                            <button
                                onClick={() => handleServiceControl(name, data, 'restart')}
                                disabled={isBusy}
                                className="p-2 bg-slate-800/80 hover:bg-amber-500/20 hover:text-amber-400 text-slate-400 rounded-lg transition-colors disabled:opacity-50"
                            >
                                <RotateCcw size={16} className={isBusy ? 'animate-spin' : ''} />
                            </button>
                            <button
                                onClick={() => handleServiceControl(name, data, 'stop')}
                                disabled={isBusy}
                                className="p-2 bg-slate-800/80 hover:bg-red-500/20 hover:text-red-400 text-slate-400 rounded-lg transition-colors disabled:opacity-50"
                            >
                                <Square size={16} className="fill-current" />
                            </button>
                        </>
                    ) : (
                        <button
                            onClick={() => handleServiceControl(name, data, 'start')}
                            disabled={isBusy}
                            className="w-full py-2 bg-indigo-500/20 hover:bg-indigo-500 text-indigo-300 hover:text-white text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 border border-indigo-500/30 disabled:opacity-50"
                        >
                            <Play size={14} className="fill-current" /> {isBusy ? 'Starting...' : 'Start Service'}
                        </button>
                    )}
                </div>
            </div>
        );
    };

    if (isLoading) {
        return (
            <div className="flex items-center justify-center h-full min-h-[50vh]">
                <div className="flex flex-col items-center gap-4 text-slate-400">
                    <div className="w-10 h-10 border-4 border-indigo-500/20 border-t-indigo-500 rounded-full animate-spin"></div>
                    <p className="font-medium tracking-wide">Scanning Services...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-8 animate-fade-in">
            {/* Header */}
            <div className="flex justify-between items-end">
                <div>
                    <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
                        App Ecosystem
                        <span className="text-xs font-semibold px-2.5 py-1 bg-white/10 rounded-full text-slate-300 border border-white/5">{allEntries.length} Total</span>
                        <span className="text-xs font-semibold px-2.5 py-1 bg-emerald-500/10 rounded-full text-emerald-400 border border-emerald-500/20">{runningCount} Running</span>
                    </h2>
                    <p className="text-slate-400 text-sm mt-2">Manage and monitor containerized services within the nexus.</p>
                </div>
                <div className="flex gap-3">
                    <button
                        onClick={() => mutate()}
                        className="px-4 py-2 bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 rounded-lg text-sm font-medium text-slate-300 transition-all flex items-center gap-2"
                    >
                        <RefreshCw size={14} /> Sync All
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
        </div>
    );
}
