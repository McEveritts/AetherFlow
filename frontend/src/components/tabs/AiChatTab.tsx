import { Sparkles, Settings, Bot, User, ChevronRight, Lock, ChevronDown, Wrench, Activity, FileText, Layers, Cpu, ShieldAlert, HardDrive, Zap } from 'lucide-react';
import { useState, useRef, useEffect, FormEvent } from 'react';
import useSWR from 'swr';
import { useSystemStore } from '@/store/useSystemStore';
import { apiFetch } from '@/lib/fetcher';
import { useMetrics } from '@/hooks/useMetrics';
import { useToast } from '@/contexts/ToastContext';
import { AI_PROVIDERS, AI_MODELS, ALL_MODEL_IDS, resolveProviderForModel } from '@/lib/ai-models';
import type { AIProviderID } from '@/lib/ai-models';

interface ChatMessage {
    role: 'user' | 'assistant';
    text: string;
    payload?: Record<string, unknown>;
}

const CONTEXT_MODES = [
    { id: 'full', name: 'Full Context', icon: Layers, description: 'Logs + System Metrics' },
    { id: 'logs', name: 'Logs Only', icon: FileText, description: 'Recent system logs' },
    { id: 'metrics', name: 'Metrics Only', icon: Activity, description: 'Live system metrics' },
];

const STARTER_PROMPTS = [
    {
        icon: Cpu,
        label: 'Analyze resource telemetry',
        prompt: 'Analyze current CPU, memory, and disk utilization and highlight any potential bottlenecks.',
    },
    {
        icon: ShieldAlert,
        label: 'Check service health',
        prompt: 'Check the health of my running services and let me know if any containers or daemons need attention.',
    },
    {
        icon: HardDrive,
        label: 'Storage & media optimization',
        prompt: 'Recommend storage and media pipeline optimizations based on my current system state.',
    },
    {
        icon: Zap,
        label: 'Draft maintenance workflow',
        prompt: 'Draft a safe maintenance workflow to clean up stale caches and optimize service performance.',
    },
];

export default function AiChatTab() {
    const { setActiveTab, setActiveSettingsTab } = useSystemStore();
    const { metrics } = useMetrics();
    const { toasts, addToast } = useToast();
    const [messages, setMessages] = useState<ChatMessage[]>([
        { 
            role: 'assistant', 
            text: "Hello! I am FlowAI, your localized infrastructure management assistant. I'm connected to your system metrics, service health monitors, and media pipelines.\n\nI can analyze issues and even draft maintenance workflows directly into your Approval Inbox. How can I help you today?" 
        }
    ]);
    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const [selectedProvider, setSelectedProvider] = useState<AIProviderID>('gemini');
    const [selectedModel, setSelectedModel] = useState('gemini-3.8-flash');
    const [showModelPicker, setShowModelPicker] = useState(false);
    const [supportMode, setSupportMode] = useState(false);
    const [contextMode, setContextMode] = useState('full');
    const [showContextPicker, setShowContextPicker] = useState(false);
    const scrollRef = useRef<HTMLDivElement>(null);
    const modelPickerRef = useRef<HTMLDivElement>(null);
    const contextPickerRef = useRef<HTMLDivElement>(null);
    const userSelectedModelRef = useRef(false);

    const { data: settingsData } = useSWR<Record<string, string>>('/api/v1/auth/settings');

    // Sync default model & provider from saved user settings unless manually overridden in this session
    useEffect(() => {
        if (!settingsData || userSelectedModelRef.current) return;
        if (settingsData.aiModel && ALL_MODEL_IDS.includes(settingsData.aiModel)) {
            setSelectedModel(settingsData.aiModel);
            setSelectedProvider(resolveProviderForModel(settingsData.aiModel));
        } else if (settingsData.aiProvider && AI_PROVIDERS.some(p => p.id === settingsData.aiProvider)) {
            const prov = settingsData.aiProvider as AIProviderID;
            setSelectedProvider(prov);
            if (AI_MODELS[prov]?.[0]?.id) {
                setSelectedModel(AI_MODELS[prov][0].id);
            }
        }
    }, [settingsData]);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [messages, isTyping]);

    // Close pickers when clicking or tapping outside
    useEffect(() => {
        const handleClickOutside = (e: PointerEvent) => {
            if (modelPickerRef.current && !modelPickerRef.current.contains(e.target as Node)) {
                setShowModelPicker(false);
            }
            if (contextPickerRef.current && !contextPickerRef.current.contains(e.target as Node)) {
                setShowContextPicker(false);
            }
        };
        document.addEventListener('pointerdown', handleClickOutside);
        return () => document.removeEventListener('pointerdown', handleClickOutside);
    }, []);

    const activeModels = AI_MODELS[selectedProvider] || [];
    const currentModel = activeModels.find(m => m.id === selectedModel) || activeModels[0] || { name: 'Unknown', tier: 'unknown' };
    const currentContext = CONTEXT_MODES.find(m => m.id === contextMode) || CONTEXT_MODES[0];

    const dispatchMessage = async (rawText: string) => {
        const text = rawText.trim();
        if (!text || isTyping) return;

        setInput('');
        setMessages(prev => [...prev, { role: 'user', text }]);
        setIsTyping(true);

        try {
            const endpoint = supportMode ? '/api/v1/auth/ai/support' : '/api/v1/auth/ai/chat';
            const body: Record<string, unknown> = {
                message: text,
                history: messages,
                model: selectedModel,
                provider: selectedProvider,
            };
            if (supportMode) {
                body.context_mode = contextMode;
                if (contextMode === 'full' || contextMode === 'metrics') {
                    body.metrics_snapshot = metrics;
                }
                if (contextMode === 'full' || contextMode === 'logs') {
                    body.system_logs = toasts;
                }
            }

            const res = await apiFetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            const data = await res.json();

            const assistantReply = data.reply || 'No response received.';
            const actionPayload = data.proposed_action || undefined;

            setMessages(prev => [...prev, { role: 'assistant', text: assistantReply, payload: actionPayload }]);
        } catch {
            setMessages(prev => [...prev, { role: 'assistant', text: "Connection error: Unable to reach the FlowAI backend service." }]);
        } finally {
            setIsTyping(false);
        }
    };

    const handleSendMessage = async (e?: FormEvent) => {
        if (e) e.preventDefault();
        await dispatchMessage(input);
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSendMessage();
        }
    };

    return (
        <div className="h-[calc(100vh-8.5rem)] flex flex-col relative animate-fade-in">
            {/* Top Toolbar (z-30 so dropdown menus always stack above the scrollable chat stream) */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-2 border-b border-white/[0.06] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className={`h-10 w-10 rounded-xl flex items-center justify-center border transition-colors duration-300 ${supportMode ? 'bg-amber-500/20 border-amber-500/30 shadow-[0_0_20px_rgba(245,158,11,0.15)]' : 'bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)]'}`}>
                        {supportMode ? <Wrench size={20} className="text-amber-400" /> : <Sparkles size={20} className="text-indigo-400" />}
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">
                                {supportMode ? 'FlowAI Support' : 'FlowAI Assistant'}
                            </h2>
                            <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${
                                supportMode
                                    ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                                    : 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30'
                            }`}>
                                {selectedProvider}
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5">
                                <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${supportMode ? 'bg-amber-400 animate-ping' : 'bg-emerald-400'}`}></span>
                                <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${supportMode ? 'bg-amber-500' : 'bg-emerald-500'}`}></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide">
                                {supportMode ? `Live Diagnostics · ${currentContext.name}` : `Active Engine · ${currentModel.name}`}
                            </span>
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    {/* Support Mode Toggle */}
                    <button
                        type="button"
                        onClick={() => setSupportMode(!supportMode)}
                        className={`obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition-all border ${supportMode
                            ? 'bg-amber-500/20 border-amber-500/30 text-amber-300 shadow-lg shadow-amber-500/10'
                            : 'bg-white/[0.04] border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white'
                            }`}
                    >
                        <Wrench size={14} />
                        <span>Support Mode</span>
                    </button>

                    {/* Context Mode Selector (only visible in support mode) */}
                    {supportMode && (
                        <div className="relative" ref={contextPickerRef}>
                            <button
                                type="button"
                                onClick={() => setShowContextPicker(!showContextPicker)}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-2 bg-amber-500/10 border border-amber-500/20 rounded-xl text-xs font-semibold text-amber-300 hover:bg-amber-500/20 transition-all"
                            >
                                <currentContext.icon size={14} />
                                <span>{currentContext.name}</span>
                                <ChevronDown size={14} className={`text-amber-500 transition-transform ${showContextPicker ? 'rotate-180' : ''}`} />
                            </button>

                            {showContextPicker && (
                                <div className="absolute right-0 top-full mt-2 w-64 bg-slate-900/95 backdrop-blur-2xl border border-white/15 rounded-2xl shadow-2xl z-50 overflow-hidden">
                                    <div className="p-2.5 border-b border-white/[0.06]">
                                        <p className="text-[10px] uppercase tracking-wider text-slate-400 font-bold px-2 py-0.5">Context Source</p>
                                    </div>
                                    <div className="p-1.5 space-y-0.5">
                                        {CONTEXT_MODES.map((mode) => (
                                            <button
                                                key={mode.id}
                                                type="button"
                                                onClick={() => { setContextMode(mode.id); setShowContextPicker(false); }}
                                                className={`obs-touch-target-standard w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm transition-all ${contextMode === mode.id
                                                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                                    : 'text-slate-300 hover:bg-white/[0.06] border border-transparent'
                                                    }`}
                                            >
                                                <div className="flex items-center gap-2.5">
                                                    <mode.icon size={14} className={contextMode === mode.id ? 'text-amber-400' : 'text-slate-500'} />
                                                    <div className="text-left">
                                                        <span className="font-medium block text-xs">{mode.name}</span>
                                                        <span className="text-[10px] text-slate-500">{mode.description}</span>
                                                    </div>
                                                </div>
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Model Selector */}
                    <div className="relative" ref={modelPickerRef}>
                        <button
                            type="button"
                            onClick={() => setShowModelPicker(!showModelPicker)}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-2 bg-white/[0.04] border border-white/10 rounded-xl text-xs font-semibold text-slate-200 hover:bg-white/[0.08] hover:border-indigo-500/30 transition-all"
                        >
                            <Sparkles size={14} className="text-indigo-400" />
                            <span>{currentModel.name}</span>
                            <ChevronDown size={14} className={`text-slate-400 transition-transform ${showModelPicker ? 'rotate-180' : ''}`} />
                        </button>

                        {showModelPicker && (
                            <div className="absolute right-0 top-full mt-2 w-72 bg-slate-900/95 backdrop-blur-2xl border border-white/15 rounded-2xl shadow-2xl z-50 overflow-hidden">
                                <div className="p-2.5 border-b border-white/[0.06] flex items-center justify-between gap-2">
                                    <p className="text-[10px] uppercase tracking-wider text-slate-400 font-bold px-2 py-0.5">AI Provider & Model</p>
                                    <select
                                        className="obs-touch-target-standard bg-slate-800 text-xs text-slate-200 font-semibold rounded-lg border border-white/10 px-2.5 py-1 outline-none focus:border-indigo-500/50 cursor-pointer"
                                        value={selectedProvider}
                                        onChange={(e) => {
                                            const newProvider = e.target.value as AIProviderID;
                                            userSelectedModelRef.current = true;
                                            setSelectedProvider(newProvider);
                                            setSelectedModel(AI_MODELS[newProvider]?.[0]?.id || '');
                                        }}
                                        onClick={(e) => e.stopPropagation()}
                                    >
                                        {AI_PROVIDERS.map((p) => (
                                            <option key={p.id} value={p.id}>{p.name}</option>
                                        ))}
                                    </select>
                                </div>
                                <div className="p-1.5 space-y-1 max-h-72 overflow-y-auto custom-scrollbar">
                                    {activeModels.map((model) => (
                                        <button
                                            key={model.id}
                                            type="button"
                                            onClick={() => {
                                                userSelectedModelRef.current = true;
                                                setSelectedModel(model.id);
                                                setShowModelPicker(false);
                                            }}
                                            className={`obs-touch-target-standard w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm transition-all cursor-pointer ${selectedModel === model.id
                                                    ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                                                    : 'text-slate-300 hover:bg-white/[0.06] border border-transparent'
                                                }`}
                                        >
                                            <div className="flex items-center gap-2.5">
                                                <div className={`h-2 w-2 rounded-full ${selectedModel === model.id ? 'bg-indigo-400 shadow-[0_0_8px_rgba(129,140,248,0.8)]' : 'bg-slate-600'}`}></div>
                                                <span className="font-medium text-xs">{model.name}</span>
                                            </div>
                                            <span className={`text-[10px] uppercase tracking-wider font-bold px-2 py-0.5 rounded-md ${model.tier === 'latest'
                                                    ? 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/20'
                                                    : 'bg-slate-800 text-slate-400 border border-white/5'
                                                }`}>
                                                {model.tier}
                                            </span>
                                        </button>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Settings Gear -> Navigates directly to FlowAI Engine tab */}
                    <button
                        type="button"
                        title="Configure FlowAI Engine"
                        onClick={() => {
                            setActiveSettingsTab('ai');
                            setActiveTab('settings');
                        }}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 text-slate-400 hover:text-white bg-white/[0.04] hover:bg-white/10 border border-white/10 rounded-xl transition-colors flex items-center justify-center"
                    >
                        <Settings size={16} />
                    </button>
                </div>
            </div>

            {/* Support Mode Banner */}
            {supportMode && (
                <div className="max-w-4xl mx-auto w-full mt-2 px-4 py-2.5 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-center gap-3 relative z-20 shrink-0">
                    <div className="relative flex items-center justify-center">
                        <div className="w-2 h-2 rounded-full bg-amber-400 animate-ping absolute"></div>
                        <div className="w-2 h-2 rounded-full bg-amber-500 relative"></div>
                    </div>
                    <span className="text-xs text-amber-300 font-medium">
                        Support Mode Active — FlowAI is inspecting live {contextMode === 'full' ? 'logs & system metrics' : contextMode === 'logs' ? 'system logs' : 'system metrics'} to diagnose issues
                    </span>
                </div>
            )}

            {/* Open Chat Messages Stream */}
            <div ref={scrollRef} className="flex-1 overflow-y-auto py-6 space-y-6 relative z-10 custom-scrollbar scroll-smooth">
                <div className="max-w-4xl mx-auto w-full px-2 md:px-4 space-y-6">
                    {messages.map((msg, index) => (
                        <div key={index} className={`flex gap-4 ${msg.role === 'user' ? 'ml-auto justify-end max-w-2xl' : 'max-w-3xl'}`}>
                            {msg.role === 'assistant' && (
                                <div className={`h-9 w-9 rounded-xl border flex items-center justify-center shrink-0 mt-0.5 shadow-md ${supportMode ? 'bg-amber-500/20 border-amber-500/30' : 'bg-indigo-500/20 border-indigo-500/30'}`}>
                                    {supportMode ? <Wrench size={16} className="text-amber-400" /> : <Bot size={16} className="text-indigo-400" />}
                                </div>
                            )}

                            <div className={`p-5 rounded-2xl text-sm leading-relaxed whitespace-pre-wrap ${msg.role === 'user'
                                ? 'bg-gradient-to-br from-indigo-600 to-indigo-500 text-white rounded-tr-sm font-medium shadow-lg shadow-indigo-500/15 border border-indigo-400/20'
                                : 'glass-panel bg-slate-900/60 backdrop-blur-xl border border-white/[0.07] text-slate-200 rounded-tl-sm shadow-xl'
                                }`}>
                                {msg.text}

                                {/* Render Contextual Payload if present */}
                                {msg.payload && msg.payload.type === 'system_action' && (
                                    <div className="mt-4 bg-slate-950/80 border border-indigo-500/30 rounded-xl p-4 shadow-[0_0_15px_rgba(99,102,241,0.1)]">
                                        <div className="flex items-center gap-3 mb-2">
                                            <div className="bg-indigo-500/20 p-2 rounded-lg text-indigo-400">
                                                <Wrench size={16} />
                                            </div>
                                            <span className="font-bold text-slate-100 flex-1">{msg.payload.title as string}</span>
                                            <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded border ${
                                                msg.payload.danger_level === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                                                msg.payload.danger_level === 'warn' ? 'bg-amber-500/20 text-amber-400 border-amber-500/30' :
                                                'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                                            }`}>
                                                {msg.payload.danger_level as string}
                                            </span>
                                        </div>
                                        <p className="text-slate-400 text-xs mb-4 border-l-2 border-white/10 pl-3 ml-1">{msg.payload.description as string}</p>
                                        <div className="flex items-center justify-between pt-2 border-t border-white/5">
                                            <span className="text-[10px] text-slate-500 font-mono">
                                                {msg.payload.action_id ? `Action #${msg.payload.action_id as string} queued` : 'Queued for approval'}
                                            </span>
                                            <button 
                                                type="button"
                                                onClick={() => {
                                                    addToast(`Action #${(msg.payload?.action_id as string) || '?'} is waiting in your Approval Inbox.`, 'success');
                                                    setActiveTab('inbox');
                                                }}
                                                className="obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 bg-indigo-500 hover:bg-indigo-400 text-white text-xs font-semibold rounded-lg transition-colors flex items-center gap-2 shadow-sm"
                                            >
                                                Review in Inbox <ChevronRight size={14} />
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {msg.role === 'user' && (
                                <div className="h-9 w-9 rounded-xl bg-slate-800/80 border border-white/10 flex items-center justify-center shrink-0 mt-0.5">
                                    <User size={16} className="text-slate-300" />
                                </div>
                            )}
                        </div>
                    ))}

                    {/* Quick Starter Prompt Chips when conversation just started */}
                    {messages.length <= 1 && !isTyping && (
                        <div className="pt-2 pl-0 md:pl-13">
                            <p className="text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-3">
                                Suggested Infrastructure Prompts
                            </p>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                {STARTER_PROMPTS.map((item) => (
                                    <button
                                        key={item.label}
                                        type="button"
                                        onClick={() => dispatchMessage(item.prompt)}
                                        className="obs-touch-target-standard obs-gpu-120hz-interactive group text-left p-3.5 rounded-2xl bg-white/[0.02] hover:bg-white/[0.05] border border-white/[0.06] hover:border-indigo-500/30 transition-all flex items-start gap-3"
                                    >
                                        <div className="p-2 rounded-xl bg-indigo-500/10 text-indigo-400 group-hover:bg-indigo-500/20 transition-colors shrink-0 mt-0.5">
                                            <item.icon size={15} />
                                        </div>
                                        <div className="min-w-0 flex-1">
                                            <div className="text-xs font-semibold text-slate-200 group-hover:text-indigo-300 transition-colors flex items-center justify-between gap-2">
                                                <span>{item.label}</span>
                                                <ChevronRight size={13} className="text-slate-600 group-hover:text-indigo-400 group-hover:translate-x-0.5 transition-all shrink-0" />
                                            </div>
                                            <p className="text-[11px] text-slate-500 line-clamp-1 mt-0.5">{item.prompt}</p>
                                        </div>
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}

                    {isTyping && (
                        <div className="flex gap-4 max-w-3xl">
                            <div className={`h-9 w-9 rounded-xl border flex items-center justify-center shrink-0 mt-0.5 ${supportMode ? 'bg-amber-500/20 border-amber-500/30' : 'bg-indigo-500/20 border-indigo-500/30'}`}>
                                {supportMode ? <Wrench size={16} className="text-amber-400" /> : <Bot size={16} className="text-indigo-400" />}
                            </div>
                            <div className="glass-panel bg-slate-900/60 border border-white/[0.07] p-5 rounded-2xl rounded-tl-sm text-slate-200 flex items-center gap-2">
                                <span className={`w-2 h-2 rounded-full animate-bounce cursor-default ${supportMode ? 'bg-amber-500' : 'bg-indigo-500'}`} style={{ animationDelay: '0ms' }}></span>
                                <span className={`w-2 h-2 rounded-full animate-bounce cursor-default ${supportMode ? 'bg-amber-500' : 'bg-indigo-500'}`} style={{ animationDelay: '150ms' }}></span>
                                <span className={`w-2 h-2 rounded-full animate-bounce cursor-default ${supportMode ? 'bg-amber-500' : 'bg-indigo-500'}`} style={{ animationDelay: '300ms' }}></span>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Floating Bottom Prompt Bar */}
            <div className="pt-3 pb-1 relative z-20 shrink-0 w-full">
                <div className="max-w-4xl mx-auto w-full">
                    <form
                        onSubmit={handleSendMessage}
                        className={`glass-panel relative flex items-end overflow-hidden rounded-2xl bg-slate-900/75 backdrop-blur-2xl border transition-all shadow-2xl ${
                            supportMode
                                ? 'border-amber-500/25 focus-within:border-amber-500/50'
                                : 'border-white/[0.08] focus-within:border-indigo-500/50'
                        }`}
                    >
                        <textarea
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            onKeyDown={handleKeyDown}
                            placeholder={supportMode ? "Describe the issue you're troubleshooting..." : `Message ${currentModel.name}...`}
                            className="w-full bg-transparent py-4 pl-5 pr-24 text-slate-100 placeholder:text-slate-500 focus:outline-none resize-none overflow-hidden min-h-[56px] max-h-32 text-sm"
                            rows={1}
                            disabled={isTyping}
                        />
                        <div className="absolute right-2.5 bottom-2 flex items-center gap-1.5">
                            <button
                                type="button"
                                title="End-to-end local context isolation"
                                className="obs-touch-target-standard p-2 text-slate-400 hover:text-slate-200 hover:bg-white/5 rounded-xl transition-colors flex items-center justify-center"
                            >
                                <Lock size={16} />
                            </button>
                            <button
                                type="submit"
                                disabled={!input.trim() || isTyping}
                                className={`obs-touch-target-standard obs-gpu-120hz-interactive p-2.5 rounded-xl text-white shadow-md transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center ${
                                    supportMode ? 'bg-amber-500 hover:bg-amber-400' : 'bg-indigo-600 hover:bg-indigo-500'
                                }`}
                            >
                                <ChevronRight size={18} />
                            </button>
                        </div>
                    </form>
                    <div className="flex items-center justify-between px-2 mt-2">
                        <p className="text-[10px] text-slate-500 font-medium">
                            FlowAI can make mistakes. Critical system actions require explicit sign-off in your Approval Inbox.
                        </p>
                        <span className="text-[10px] text-slate-500 font-mono hidden sm:inline">
                            {currentModel.name} · Enter to send
                        </span>
                    </div>
                </div>
            </div>
        </div>
    );
}
