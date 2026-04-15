'use client';

import React from 'react';
import { Cpu, Zap, Activity, Monitor } from 'lucide-react';
import { GpuMetric } from '@/types/dashboard';

interface GpuWidgetProps {
    gpus: GpuMetric[];
    density: 'compact' | 'immersive';
}

export default function GpuWidget({ gpus, density }: GpuWidgetProps) {
    if (!gpus || gpus.length === 0) return null;

    const isImmersive = density === 'immersive';

    return (
        <div className={`bg-slate-900/40 border border-white/10 rounded-2xl overflow-hidden backdrop-blur-md transition-all duration-300 ${isImmersive ? 'p-6 space-y-4 shadow-blue-500/10 shadow-2xl' : 'p-4'}`}>
            <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-500/20 rounded-lg text-blue-400">
                        <Monitor size={isImmersive ? 24 : 18} />
                    </div>
                    <div>
                        <h3 className={`font-bold text-white tracking-tight ${isImmersive ? 'text-lg' : 'text-sm'}`}>
                            Compute Accelerators
                        </h3>
                        <p className="text-[10px] text-slate-500 font-mono uppercase tracking-widest">{gpus.length} Device(s) Detected</p>
                    </div>
                </div>
                {isImmersive && (
                    <div className="flex items-center gap-2 px-2 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-full">
                        <span className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse" />
                        <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-tighter">Active</span>
                    </div>
                )}
            </div>

            <div className={`grid gap-4 ${isImmersive && gpus.length > 1 ? 'grid-cols-2' : 'grid-cols-1'}`}>
                {gpus.map((gpu, idx) => (
                    <div key={idx} className="bg-white/[0.03] border border-white/5 rounded-xl p-4">
                        <div className="flex items-start justify-between mb-3">
                            <div className="space-y-1">
                                <p className="text-xs font-bold text-slate-200 truncate max-w-[180px]">{gpu.name}</p>
                                <p className="text-[10px] text-slate-500 font-medium">Index: {gpu.index}</p>
                            </div>
                            <div className="text-right">
                                <p className="text-xs font-black text-blue-400">#{gpu.index}</p>
                            </div>
                        </div>

                        {/* Real-time stats placeholders */}
                        <div className="space-y-3">
                            <div>
                                <div className="flex justify-between text-[10px] font-bold mb-1 uppercase tracking-tight">
                                    <span className="text-slate-400">Core Load</span>
                                    <span className="text-blue-400">{gpu.usage_pct || 0}%</span>
                                </div>
                                <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                                    <div 
                                        className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-500" 
                                        style={{ width: `${gpu.usage_pct || 0}%` }}
                                    />
                                </div>
                            </div>

                            {isImmersive && (
                                <div>
                                    <div className="flex justify-between text-[10px] font-bold mb-1 uppercase tracking-tight">
                                        <span className="text-slate-400">VRAM Usage</span>
                                        <span className="text-purple-400">Detecting...</span>
                                    </div>
                                    <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
                                        <div 
                                            className="h-full bg-gradient-to-r from-purple-500 to-pink-500 opacity-30 shadow-[0_0_10px_rgba(168,85,247,0.5)]" 
                                            style={{ width: '15%' }}
                                        />
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                ))}
            </div>
            
            {isImmersive && (
                <p className="text-[9px] text-slate-600 text-center italic mt-4">
                    Dynamic hardware detection active. Headless environments with no GPU will automatically hide this panel.
                </p>
            )}
        </div>
    );
}
