'use client';

import React from 'react';
import { 
    Radio, 
    Clock, 
    Monitor, 
    ChevronRight, 
    Maximize2, 
    Layers, 
    Sparkles, 
    Sliders, 
    Eye, 
    Activity,
    Zap,
    Smartphone,
    Vibrate
} from 'lucide-react';
import { useConnectionStore } from '@/store/useConnectionStore';
import { useSystemStore } from '@/store/useSystemStore';
import { triggerHaptic } from '@/lib/design';

export default function DashboardSettingsTab() {
    const { 
        preferredMode, setPreferredMode, 
        pollInterval, setPollInterval, 
        dashboardDensity, setDashboardDensity,
        showGpuWidget, setShowGpuWidget,
        showDataUsageWidget, setShowDataUsageWidget
    } = useConnectionStore();

    const {
        auroraOpacity, setAuroraOpacity,
        auroraAnimation, setAuroraAnimation,
        grainDisplay, setGrainDisplay,
        cardLift, setCardLift,
        highRefreshMode, setHighRefreshMode,
        detectedRefreshRate,
        touchMode, setTouchMode,
        detectedTouchDevice,
        hapticFeedback, setHapticFeedback,
    } = useSystemStore();

    const is120HzActive = highRefreshMode === '120hz' || (highRefreshMode === 'auto' && detectedRefreshRate >= 90);
    const isTouchActive = touchMode === 'enabled' || (touchMode === 'auto' && detectedTouchDevice);

    // Atmosphere preferences are automatically persisted in localStorage via useSystemStore theme settings
    return (
        <div className="space-y-8 animate-fade-in">
            {/* CATEGORY: 120Hz ProMotion & Touchscreen Engine */}
            <div>
                <div className="flex flex-wrap items-center justify-between gap-2 mb-3 px-2">
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                        <Zap size={14} className="text-cyan-400" />
                        120Hz High-Refresh & Touchscreen Engine
                    </h4>
                    <div className="flex items-center gap-2">
                        <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase tracking-wider border ${
                            is120HzActive
                                ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30 shadow-[0_0_10px_rgba(34,211,238,0.2)]'
                                : 'bg-slate-800/80 text-slate-300 border-white/10'
                        }`}>
                            Display: {detectedRefreshRate}Hz {is120HzActive ? 'ProMotion' : 'Standard'}
                        </span>
                        <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase tracking-wider border ${
                            isTouchActive
                                ? 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30'
                                : 'bg-slate-800/80 text-slate-300 border-white/10'
                        }`}>
                            Input: {isTouchActive ? 'Touch Optimized (≥44px)' : 'Fine Pointer'}
                        </span>
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl divide-y divide-white/[0.04] overflow-hidden">
                    {/* 120Hz High-Refresh Motion Cadence */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Zap size={16} className="text-cyan-400" /> 120Hz Frame-Paced Motion Physics
                            </label>
                            <p className="text-xs text-slate-400 mt-1">
                                Tunes GPU spring curves (8.33ms frame budget, 110ms interactive / 150ms surface transitions) for high-refresh displays.
                            </p>
                        </div>
                        <div className="flex bg-black/60 p-1 rounded-xl border border-white/10 w-full md:w-80">
                            {([
                                { id: 'auto', label: `Auto (${detectedRefreshRate}Hz)` },
                                { id: '120hz', label: '120Hz Pro' },
                                { id: 'standard', label: '60Hz' },
                            ] as const).map((opt) => (
                                <button
                                    key={opt.id}
                                    type="button"
                                    onClick={() => {
                                        triggerHaptic(6, hapticFeedback);
                                        setHighRefreshMode(opt.id);
                                    }}
                                    className={`flex-1 py-2 px-2 rounded-lg text-xs font-bold obs-gpu-120hz-interactive obs-touch-target-standard ${
                                        highRefreshMode === opt.id
                                            ? 'bg-indigo-500 text-white shadow-lg'
                                            : 'text-slate-400 hover:text-slate-200'
                                    }`}
                                >
                                    {opt.label}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Touchscreen Ergonomics Mode */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Smartphone size={16} className="text-indigo-400" /> Touchscreen Ergonomics & Hit Targets
                            </label>
                            <p className="text-xs text-slate-400 mt-1">
                                Enforces WCAG 2.2 AAA ≥ 44px touch targets, swipe gestures, and reveals hover-gated controls on touchscreens.
                            </p>
                        </div>
                        <div className="flex bg-black/60 p-1 rounded-xl border border-white/10 w-full md:w-80">
                            {([
                                { id: 'auto', label: `Auto (${detectedTouchDevice ? 'Touch' : 'Mouse'})` },
                                { id: 'enabled', label: 'Touch On' },
                                { id: 'desktop', label: 'Desktop' },
                            ] as const).map((opt) => (
                                <button
                                    key={opt.id}
                                    type="button"
                                    onClick={() => {
                                        triggerHaptic(6, hapticFeedback);
                                        setTouchMode(opt.id);
                                    }}
                                    className={`flex-1 py-2 px-2 rounded-lg text-xs font-bold obs-gpu-120hz-interactive obs-touch-target-standard ${
                                        touchMode === opt.id
                                            ? 'bg-indigo-500 text-white shadow-lg'
                                            : 'text-slate-400 hover:text-slate-200'
                                    }`}
                                >
                                    {opt.label}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Tactile Haptic Feedback Toggle */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Vibrate size={16} className="text-emerald-400" /> Tactile Haptic Micro-Pulses
                            </label>
                            <p className="text-xs text-slate-400 mt-1">
                                Emits subtle vibration pulses when tapping navigation docks, toggles, and service actions on supported touch devices.
                            </p>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="text-xs text-slate-400">{hapticFeedback ? 'Enabled' : 'Disabled'}</span>
                            <button
                                type="button"
                                onClick={() => {
                                    const next = !hapticFeedback;
                                    setHapticFeedback(next);
                                    if (next) triggerHaptic(10, true);
                                }}
                                className={`relative inline-flex h-7 w-12 items-center rounded-full transition-colors focus:outline-none obs-touch-target-standard ${
                                    hapticFeedback ? 'bg-indigo-600' : 'bg-slate-800'
                                }`}
                                aria-label="Toggle Haptic Feedback"
                            >
                                <span className={`inline-block h-5 w-5 transform rounded-full bg-white transition-transform ${
                                    hapticFeedback ? 'translate-x-6' : 'translate-x-1'
                                }`} />
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            {/* CATEGORY: Obsidian V2 Atmosphere Engine */}
            <div>
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2 flex items-center gap-2">
                    <Sparkles size={14} className="text-indigo-400" />
                    Obsidian V2 Atmosphere & Visual Tuning
                </h4>
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl divide-y divide-white/[0.04] overflow-hidden">
                    
                    {/* Aurora Intensity / Opacity Slider */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Sliders size={16} className="text-indigo-400" /> Aurora Intensity & Opacity
                            </label>
                            <p className="text-xs text-slate-400 mt-1">
                                Controls the luminance of the 3-orb radial cosmic aurora on the pure black canvas.
                            </p>
                        </div>
                        <div className="flex items-center gap-4 w-full md:w-80">
                            <input
                                type="range"
                                min="0"
                                max="1"
                                step="0.05"
                                value={auroraOpacity}
                                onChange={(e) => setAuroraOpacity(parseFloat(e.target.value))}
                                className="w-full accent-indigo-500 h-2 bg-slate-900 rounded-lg appearance-none cursor-pointer"
                            />
                            <span className="text-xs font-mono font-bold text-indigo-300 w-12 text-right">
                                {Math.round(auroraOpacity * 100)}%
                            </span>
                        </div>
                    </div>

                    {/* Static vs Animated 3D Aurora Oscillation */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Activity size={16} className="text-fuchsia-400" /> 120Hz Aurora Animation
                            </label>
                            <p className="text-xs text-slate-400 mt-1">
                                Toggle between static 120Hz GPU hardware-cached aurora and live continuous 3D oscillation.
                            </p>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="text-xs text-slate-400">
                                {auroraAnimation ? 'Animated (Oscillating)' : 'Static (120Hz GPU Cached)'}
                            </span>
                            <button
                                onClick={() => setAuroraAnimation(!auroraAnimation)}
                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none obs-touch-target-standard ${
                                    auroraAnimation ? 'bg-indigo-600' : 'bg-slate-800'
                                }`}
                                aria-label="Toggle Aurora Animation"
                            >
                                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                                    auroraAnimation ? 'translate-x-6' : 'translate-x-1'
                                }`} />
                            </button>
                        </div>
                    </div>

                    {/* Tactile Micro-Grain Toggle */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Eye size={16} className="text-cyan-400" /> SVG Fractal Micro-Grain & Vignette
                            </label>
                            <p className="text-xs text-slate-400 mt-1">
                                Renders high-frequency noise texture and spatial edge vignette for analog physical depth.
                            </p>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="text-xs text-slate-400">{grainDisplay ? 'Enabled' : 'Disabled'}</span>
                            <button
                                onClick={() => setGrainDisplay(!grainDisplay)}
                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none obs-touch-target-standard ${
                                    grainDisplay ? 'bg-indigo-600' : 'bg-slate-800'
                                }`}
                                aria-label="Toggle Micro-Grain"
                            >
                                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                                    grainDisplay ? 'translate-x-6' : 'translate-x-1'
                                }`} />
                            </button>
                        </div>
                    </div>

                    {/* Spring Hover Lift Physics */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Maximize2 size={16} className="text-emerald-400" /> Card Hover Spring Lift
                            </label>
                            <p className="text-xs text-slate-400 mt-1">
                                Elevates glass cards along the Z-axis with 120Hz cubic-bezier spring physics on pointer hover.
                            </p>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="text-xs text-slate-400">{cardLift !== 0 ? '-4px (Spring)' : 'Flat (0px)'}</span>
                            <button
                                onClick={() => setCardLift(cardLift !== 0 ? 0 : -4)}
                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none obs-touch-target-standard ${
                                    cardLift !== 0 ? 'bg-indigo-600' : 'bg-slate-800'
                                }`}
                                aria-label="Toggle Card Hover Lift"
                            >
                                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                                    cardLift !== 0 ? 'translate-x-6' : 'translate-x-1'
                                }`} />
                            </button>
                        </div>
                    </div>

                </div>
            </div>

            {/* CATEGORY: Layout & Density */}
            <div>
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">Visualization Density</h4>
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl divide-y divide-white/[0.04] overflow-hidden">
                    
                    {/* Density Picker */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Layers size={16} className="text-blue-400" /> Display Density
                            </label>
                            <p className="text-xs text-slate-400 mt-1">Choose between information-dense or visually immersive layouts.</p>
                        </div>
                        <div className="flex bg-black/60 p-1 rounded-xl border border-white/10 w-full md:w-80">
                            <button
                                onClick={() => setDashboardDensity('compact')}
                                className={`flex-1 py-2 rounded-lg text-xs font-bold transition-all obs-touch-target-standard ${
                                    dashboardDensity === 'compact' ? 'bg-indigo-500 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200'
                                }`}
                            >
                                Compact
                            </button>
                            <button
                                onClick={() => setDashboardDensity('immersive')}
                                className={`flex-1 py-2 rounded-lg text-xs font-bold transition-all obs-touch-target-standard ${
                                    dashboardDensity === 'immersive' ? 'bg-indigo-500 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200'
                                }`}
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
                            <p className="text-xs text-slate-400 mt-1">Enable secondary hardware metric detection and rendering.</p>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="text-xs text-slate-400">{showGpuWidget ? 'Enabled' : 'Disabled'}</span>
                            <button
                                onClick={() => setShowGpuWidget(!showGpuWidget)}
                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none obs-touch-target-standard ${
                                    showGpuWidget ? 'bg-indigo-600' : 'bg-slate-800'
                                }`}
                                aria-label="Toggle GPU Visualization"
                            >
                                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                                    showGpuWidget ? 'translate-x-6' : 'translate-x-1'
                                }`} />
                            </button>
                        </div>
                    </div>

                    {/* Data Usage History Visibility */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Layers size={16} className="text-emerald-400" /> 90-Day Data Usage History
                            </label>
                            <p className="text-xs text-slate-400 mt-1">Show a persistent chart of bandwidth usage trends natively on the dashboard.</p>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="text-xs text-slate-400">{showDataUsageWidget ? 'Enabled' : 'Disabled'}</span>
                            <button
                                onClick={() => setShowDataUsageWidget(!showDataUsageWidget)}
                                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none obs-touch-target-standard ${
                                    showDataUsageWidget ? 'bg-indigo-600' : 'bg-slate-800'
                                }`}
                                aria-label="Toggle Data Usage History"
                            >
                                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                                    showDataUsageWidget ? 'translate-x-6' : 'translate-x-1'
                                }`} />
                            </button>
                        </div>
                    </div>

                </div>
            </div>

            {/* CATEGORY: Connectivity */}
            <div>
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 px-2">Telemetrics Engine</h4>
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl divide-y divide-white/[0.04] overflow-hidden">
                    
                    {/* Mode */}
                    <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-white/[0.02] transition-colors">
                        <div>
                            <label className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                                <Radio size={16} className="text-emerald-400" /> Connection Mode
                            </label>
                            <p className="text-xs text-slate-400 mt-1">Primary protocol used for dashboard data updates.</p>
                        </div>
                        <div className="shrink-0 w-full md:w-80 relative">
                            <select
                                value={preferredMode}
                                onChange={(e) => setPreferredMode(e.target.value as 'websocket' | 'poll')}
                                className="w-full glass-input px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer"
                            >
                                <option value="websocket" className="bg-slate-900 text-white">Auto-Connect (WebSockets)</option>
                                <option value="poll" className="bg-slate-900 text-white">Nexus Link (REST Polling)</option>
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
                            <p className="text-xs text-slate-400 mt-1">Update frequency for dashboard visual updates.</p>
                        </div>
                        <div className="shrink-0 w-full md:w-80 relative">
                            <select
                                value={pollInterval}
                                onChange={(e) => setPollInterval(Number(e.target.value))}
                                className="w-full glass-input px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer disabled:opacity-30 disabled:cursor-not-allowed"
                            >
                                <option value={1000} className="bg-slate-900 text-white">1 Second (Hyper)</option>
                                <option value={2000} className="bg-slate-900 text-white">2 Seconds (Fast)</option>
                                <option value={5000} className="bg-slate-900 text-white">5 Seconds (Normal)</option>
                                <option value={10000} className="bg-slate-900 text-white">10 Seconds (Stable)</option>
                                <option value={30000} className="bg-slate-900 text-white">30 Seconds (Eco)</option>
                            </select>
                            <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                        </div>
                    </div>

                </div>
            </div>

            <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 flex items-start gap-4">
                <Maximize2 size={20} className="text-indigo-400 shrink-0 mt-0.5" />
                <div>
                    <h5 className="text-sm font-bold text-indigo-200">Obsidian V2 Architecture</h5>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                        The visual system operates on pure #000000 obsidian black with hardware-cached GPU radial auroras, tactile micro-grain, and 120Hz high-refresh spring physics. Modifying these settings updates CSS custom properties in real time across all glass surfaces.
                    </p>
                </div>
            </div>
        </div>
    );
}
