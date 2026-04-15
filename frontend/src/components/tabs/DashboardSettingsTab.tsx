'use client';

import React from 'react';
import { LayoutDashboard, Radio, Clock, Monitor, ChevronRight, Gauge, Layers } from 'lucide-react';
import { useConnectionStore } from '@/store/useConnectionStore';

export default function DashboardSettingsTab() {
    const { 
        preferredMode, setPreferredMode, 
        pollInterval, setPollInterval, 
        dashboardDensity, setDashboardDensity,
        showGpuWidget, setShowGpuWidget
    } = useConnectionStore();

    return (
        <div className="space-y-8 animate-fade-in">
            {/* CATEGORY: Layout & Density */}
            <div>
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">Visualization Density</h4>
                <div className="bg-slate-950/50 border border-white/10 rounded-2xl divide-y divide-white/10 overflow-hidden">
                    
                    {/* Density Picker */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Layers size={16} className="text-blue-400" /> Display Density
                            </label>
                            <p className="text-xs text-slate-500 mt-1">Choose between information-dense or visually immersive layouts.</p>
                        </div>
                        <div className="flex bg-slate-900 p-1 rounded-xl border border-white/5 w-full md:w-80">
                            <button
                                onClick={() => setDashboardDensity('compact')}
                                className={`flex-1 py-2 rounded-lg text-xs font-bold transition-all ${dashboardDensity === 'compact' ? 'bg-indigo-500 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200'}`}
                            >
                                Compact
                            </button>
                            <button
                                onClick={() => setDashboardDensity('immersive')}
                                className={`flex-1 py-2 rounded-lg text-xs font-bold transition-all ${dashboardDensity === 'immersive' ? 'bg-indigo-500 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200'}`}
                            >
                                Immersive
                            </button>
                        </div>
                    </div>

                    {/* GPU Visibility */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Monitor size={16} className="text-purple-400" /> GPU Visualization
                            </label>
                            <p className="text-xs text-slate-500 mt-1">Enable secondary hardware metric detection and rendering.</p>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="text-xs text-slate-500">{showGpuWidget ? 'Enabled' : 'Disabled'}</span>
                            <button
                                onClick={() => setShowGpuWidget(!showGpuWidget)}
                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none ${showGpuWidget ? 'bg-indigo-600' : 'bg-slate-700'}`}
                            >
                                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${showGpuWidget ? 'translate-x-6' : 'translate-x-1'}`} />
                            </button>
                        </div>
                    </div>

                </div>
            </div>

            {/* CATEGORY: Connectivity (Mirrored from Preferences for convenience) */}
            <div>
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">Telemetrics Engine</h4>
                <div className="bg-slate-950/50 border border-white/10 rounded-2xl divide-y divide-white/10 overflow-hidden">
                    
                    {/* Mode */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Radio size={16} className="text-emerald-400" /> Connection Mode
                            </label>
                            <p className="text-xs text-slate-500 mt-1">Primary protocol used for dashboard data updates.</p>
                        </div>
                        <div className="shrink-0 w-full md:w-80 relative">
                            <select
                                value={preferredMode}
                                onChange={(e) => setPreferredMode(e.target.value as 'websocket' | 'poll')}
                                className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                            >
                                <option value="websocket">Auto-Connect (WebSockets)</option>
                                <option value="poll">Nexus Link (REST Polling)</option>
                            </select>
                            <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                        </div>
                    </div>

                    {/* Poll Interval */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Clock size={16} className="text-amber-400" /> Refresh Heartbeat
                            </label>
                            <p className="text-xs text-slate-500 mt-1">Update frequency when WebSockets are unavailable or disabled.</p>
                        </div>
                        <div className="shrink-0 w-full md:w-80 relative">
                            <select
                                value={pollInterval}
                                onChange={(e) => setPollInterval(Number(e.target.value))}
                                disabled={preferredMode === 'websocket'}
                                className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
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

            <div className="bg-blue-500/5 border border-blue-500/10 rounded-2xl p-5 flex items-start gap-4">
                <Gauge size={20} className="text-blue-400 shrink-0 mt-0.5" />
                <div>
                    <h5 className="text-sm font-bold text-blue-200">AetherNexus Engine Tuning</h5>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                        These settings directly influence the render frequency and data throughput of the system. Immersive mode increases the graphical complexity—ensure your environment supports hardware acceleration for the smoothest experience.
                    </p>
                </div>
            </div>
        </div>
    );
}
