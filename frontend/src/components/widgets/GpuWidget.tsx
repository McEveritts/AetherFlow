'use client';

import React from 'react';
import { Monitor, Cpu } from 'lucide-react';
import { GpuMetric } from '@/types/dashboard';

interface GpuWidgetProps {
    gpus: GpuMetric[];
    density: 'compact' | 'immersive';
}

export default function GpuWidget({ gpus, density }: GpuWidgetProps) {
    if (!gpus || gpus.length === 0) return null;

    const isImmersive = density === 'immersive';

    return (
        <div className={`rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl relative overflow-hidden flex flex-col justify-between h-full ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div>
                {/* Header */}
                <div className="flex items-center justify-between gap-2 pb-3 mb-3.5 border-b border-white/[0.06]">
                    <div className="flex items-center gap-2.5">
                        <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shrink-0">
                            <Monitor size={16} />
                        </div>
                        <div>
                            <h3 className="text-sm font-bold text-slate-100 tracking-tight leading-none">
                                Compute Accelerators
                            </h3>
                            <p className="text-[11px] text-slate-500 mt-1">
                                {gpus.length} hardware engine{gpus.length !== 1 ? 's' : ''} detected
                            </p>
                        </div>
                    </div>
                    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/20 rounded-full text-[10px] font-bold text-emerald-400 uppercase tracking-wider">
                        <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse" />
                        Active
                    </span>
                </div>

                {/* Accelerator Cards */}
                <div className={`grid gap-3 ${isImmersive && gpus.length > 1 ? 'grid-cols-2' : 'grid-cols-1'}`}>
                    {gpus.map((gpu, idx) => {
                        const usagePct = Number(gpu.usage_pct || 0);
                        const hasDedicatedVram = Number(gpu.memory_total || 0) > 0;
                        const vramPct = hasDedicatedVram
                            ? Math.min(100, Math.max(0, (Number(gpu.memory_used || 0) / Number(gpu.memory_total)) * 100))
                            : 0;
                        const tempC = Number(gpu.temp || 0);
                        const lowerName = (gpu.name || '').toLowerCase();
                        const pipelineLabel = lowerName.includes('nvidia')
                            ? 'NVENC / CUDA'
                            : lowerName.includes('amd') || lowerName.includes('radeon')
                            ? 'VAAPI / AMF'
                            : 'VAAPI / QuickSync';

                        return (
                            <div key={idx} className="bg-black/30 border border-white/[0.04] rounded-xl p-3.5 space-y-3">
                                <div className="flex items-start justify-between gap-2">
                                    <div className="min-w-0 flex-1">
                                        <p className="text-xs font-bold text-slate-100 truncate">{gpu.name}</p>
                                        <div className="flex items-center gap-1.5 flex-wrap mt-1">
                                            <span className="text-[10px] font-mono text-slate-400 bg-white/[0.04] border border-white/[0.06] px-1.5 py-0.5 rounded">
                                                GPU #{gpu.index}
                                            </span>
                                            <span className="text-[10px] font-semibold text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 px-1.5 py-0.5 rounded">
                                                {pipelineLabel}
                                            </span>
                                            {!hasDedicatedVram && (
                                                <span className="text-[10px] font-medium text-slate-400">
                                                    Shared System Memory
                                                </span>
                                            )}
                                        </div>
                                    </div>
                                    {tempC > 0 && (
                                        <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded-lg border shrink-0 tabular-nums ${
                                            tempC >= 80
                                                ? 'text-rose-400 bg-rose-500/10 border-rose-500/20'
                                                : tempC >= 65
                                                    ? 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                                                    : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                                        }`}>
                                            {tempC.toFixed(0)}°C
                                        </span>
                                    )}
                                </div>

                                {/* Core & Memory Bars */}
                                <div className="space-y-2.5">
                                    <div>
                                        <div className="flex justify-between text-[10px] font-bold mb-1 uppercase tracking-wider">
                                            <span className="text-slate-400">Render Engine Load</span>
                                            <span className="text-blue-400 font-mono tabular-nums">{usagePct.toFixed(1)}%</span>
                                        </div>
                                        <div className="h-1.5 w-full bg-slate-800/90 rounded-full overflow-hidden">
                                            <div
                                                className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-300 rounded-full"
                                                style={{ width: `${usagePct > 0 ? Math.max(3, Math.min(100, usagePct)) : 0}%` }}
                                            />
                                        </div>
                                    </div>

                                    <div>
                                        <div className="flex justify-between text-[10px] font-bold mb-1 uppercase tracking-wider">
                                            <span className="text-slate-400">{hasDedicatedVram ? 'Dedicated VRAM' : 'Memory Architecture'}</span>
                                            <span className="text-purple-300 font-mono tabular-nums">
                                                {hasDedicatedVram
                                                    ? `${Math.round(gpu.memory_used || 0)} / ${Math.round(gpu.memory_total)} MB (${vramPct.toFixed(0)}%)`
                                                    : 'Dynamic Unified RAM'}
                                            </span>
                                        </div>
                                        {hasDedicatedVram && (
                                            <div className="h-1.5 w-full bg-slate-800/90 rounded-full overflow-hidden">
                                                <div
                                                    className="h-full bg-gradient-to-r from-purple-500 to-pink-500 transition-all duration-300 rounded-full"
                                                    style={{ width: `${Math.max(2, vramPct)}%` }}
                                                />
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* Hardware Acceleration Telemetry Footer */}
            <div className="grid grid-cols-2 gap-2.5 mt-3.5">
                <div className="bg-black/30 rounded-xl px-3 py-2 border border-white/[0.04] flex items-center justify-between">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
                        <Cpu size={12} className="text-indigo-400" /> Device Node
                    </span>
                    <span className="text-[11px] font-mono font-semibold text-slate-300">/dev/dri/renderD128</span>
                </div>
                <div className="bg-black/30 rounded-xl px-3 py-2 border border-white/[0.04] flex items-center justify-between">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Transcode API</span>
                    <span className="text-[11px] font-mono font-semibold text-emerald-400">Ready</span>
                </div>
            </div>
        </div>
    );
}
