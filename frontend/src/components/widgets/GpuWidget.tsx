'use client';

import React from 'react';
import { Monitor } from 'lucide-react';
import { GpuMetric } from '@/types/dashboard';

interface GpuWidgetProps {
    gpus: GpuMetric[];
    density: 'compact' | 'immersive';
}

export default function GpuWidget({ gpus, density }: GpuWidgetProps) {
    if (!gpus || gpus.length === 0) return null;

    const isImmersive = density === 'immersive';

    return (
        <div className={`obs-telemetry-surface relative overflow-hidden flex flex-col ${isImmersive ? 'p-6' : 'p-5'}`}>
            <div className="flex items-center justify-between gap-2 pb-3 mb-3.5 border-b border-white/[0.06]">
                <div className="flex items-center gap-2.5">
                    <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shrink-0">
                        <Monitor size={16} />
                    </div>
                    <div>
                        <h3 className="text-sm font-bold text-slate-100 tracking-tight leading-none">
                            Compute Accelerators
                        </h3>
                        <p className="text-xs text-slate-400 mt-1">
                            {gpus.length} hardware engine{gpus.length !== 1 ? 's' : ''} detected
                        </p>
                    </div>
                </div>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-full text-xs font-bold text-emerald-400 uppercase tracking-wider">
                    <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse" />
                    Active
                </span>
            </div>

            <div className="divide-y divide-white/[0.06]">
                {gpus.map((gpuItem, gpuItemIndex) => {
                    const usagePercentage = Number(gpuItem.usage_pct || 0);
                    const hasDedicatedVram = Number(gpuItem.memory_total || 0) > 0;
                    const vramPercentage = hasDedicatedVram
                        ? Math.min(100, Math.max(0, (Number(gpuItem.memory_used || 0) / Number(gpuItem.memory_total)) * 100))
                        : 0;
                    const temperatureCelsius = Number(gpuItem.temp || 0);
                    const lowerName = (gpuItem.name || '').toLowerCase();
                    const pipelineLabel = lowerName.includes('nvidia')
                        ? 'NVENC / CUDA'
                        : lowerName.includes('amd') || lowerName.includes('radeon')
                        ? 'VAAPI / AMF'
                        : 'VAAPI / QuickSync';

                    return (
                        <div key={gpuItemIndex} className="py-3.5 first:pt-0 last:pb-0 space-y-3">
                            <div className="flex items-start justify-between gap-2">
                                <div className="min-w-0 flex-1">
                                    <p className="text-xs font-bold text-slate-100 truncate">{gpuItem.name}</p>
                                    <div className="flex items-center gap-1.5 flex-wrap mt-1">
                                        <span className="text-xs font-mono text-slate-400">
                                            GPU #{gpuItem.index}
                                        </span>
                                        <span className="text-xs font-semibold text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 px-2 py-0.5 rounded">
                                            {pipelineLabel}
                                        </span>
                                        {!hasDedicatedVram && (
                                            <span className="text-xs font-medium text-slate-300">
                                                Shared System Memory
                                            </span>
                                        )}
                                    </div>
                                </div>
                                {temperatureCelsius > 0 && (
                                    <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded-lg border shrink-0 tabular-nums ${
                                        temperatureCelsius >= 80
                                            ? 'text-rose-400 bg-rose-500/10 border-rose-500/20'
                                            : temperatureCelsius >= 65
                                                ? 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                                                : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
                                    }`}>
                                        {temperatureCelsius.toFixed(0)}&deg;C
                                    </span>
                                )}
                            </div>

                            <div className="space-y-2.5">
                                <div>
                                    <div className="flex justify-between text-xs font-semibold mb-1 uppercase tracking-wider">
                                        <span className="text-slate-300">Render Engine Load</span>
                                        <span className="text-blue-400 font-mono tabular-nums">{usagePercentage.toFixed(1)}%</span>
                                    </div>
                                    <div className="h-1.5 w-full bg-white/[0.06] rounded-full overflow-hidden">
                                        <div
                                            className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all duration-300 rounded-full"
                                            style={{ width: `${usagePercentage > 0 ? Math.max(3, Math.min(100, usagePercentage)) : 0}%` }}
                                        />
                                    </div>
                                </div>

                                <div>
                                    <div className="flex justify-between text-xs font-semibold mb-1 uppercase tracking-wider">
                                        <span className="text-slate-300">{hasDedicatedVram ? 'Dedicated VRAM' : 'Memory Architecture'}</span>
                                        <span className="text-purple-300 font-mono tabular-nums">
                                            {hasDedicatedVram
                                                ? `${Math.round(gpuItem.memory_used || 0)} / ${Math.round(gpuItem.memory_total)} MB (${vramPercentage.toFixed(0)}%)`
                                                : 'Dynamic Unified RAM'}
                                        </span>
                                    </div>
                                    {hasDedicatedVram && (
                                        <div className="h-1.5 w-full bg-white/[0.06] rounded-full overflow-hidden">
                                            <div
                                                className="h-full bg-gradient-to-r from-purple-500 to-pink-500 transition-all duration-300 rounded-full"
                                                style={{ width: `${vramPercentage > 0 ? Math.max(2, vramPercentage) : 0}%` }}
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
    );
}
