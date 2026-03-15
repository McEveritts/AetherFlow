import { Sparkles, Settings, Bot, User, ChevronRight, Lock, ChevronDown, Wrench, Activity, FileText, Layers } from 'lucide-react';
import { useState, useRef, useEffect, FormEvent } from 'react';
import { useSystemStore } from '@/store/useSystemStore';

interface ChatMessage {
    role: 'user' | 'assistant';
    text: string;
}

const AI_MODELS = [
    { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro', tier: 'latest' },
    { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', tier: 'latest' },
    { id: 'gemini-2.0-flash', name: 'Gemini 2.0 Flash', tier: 'stable' },
    { id: 'gemini-1.5-pro', name: 'Gemini 1.5 Pro', tier: 'stable' },
    { id: 'gemini-1.5-flash', name: 'Gemini 1.5 Flash', tier: 'stable' },
];

const CONTEXT_MODES = [
    { id: 'full', name: 'Full Context', icon: Layers, description: 'Logs + System Metrics' },
    { id: 'logs', name: 'Logs Only', icon: FileText, description: 'Recent system logs' },
    { id: 'metrics', name: 'Metrics Only', icon: Activity, description: 'Live system metrics' },
];

export default function AiChatTab() {
    const { setActiveTab } = useSystemStore();
    const [messages, setMessages] = useState<ChatMessage[]>([
        { role: 'assistant', text: "Hello! I am FlowAI, your localized infrastructure management assistant. I'm connected to your system metrics, docker containers, and media pipelines.\n\nHow can I help you today?" }
    ]);
    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const [selectedModel, setSelectedModel] = useState('gemini-2.5-pro');
    const [showModelPicker, setShowModelPicker] = useState(false);
    const [supportMode, setSupportMode] = useState(false);
    const [contextMode, setContextMode] = useState('full');
    const [showContextPicker, setShowContextPicker] = useState(false);
    const scrollRef = useRef<HTMLDivElement>(null);
    const modelPickerRef = useRef<HTMLDivElement>(null);
    const contextPickerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [messages, isTyping]);

    // Close pickers when clicking outside
    useEffect(() => {
        const handleClickOutside = (e: MouseEvent) => {
            if (modelPickerRef.current && !modelPickerRef.current.contains(e.target as Node)) {
                setShowModelPicker(false);
            }
            if (contextPickerRef.current && !contextPickerRef.current.contains(e.target as Node)) {
                setShowContextPicker(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const currentModel = AI_MODELS.find(m => m.id === selectedModel) || AI_MODELS[0];
    const currentContext = CONTEXT_MODES.find(m => m.id === contextMode) || CONTEXT_MODES[0];

    const handleSendMessage = async (e?: FormEvent) => {
        if (e) e.preventDefault();

        const text = input.trim();
        if (!text || isTyping) return;

        setInput('');
        setMessages(prev => [...prev, { role: 'user', text }]);
        setIsTyping(true);

        try {
            const endpoint = supportMode ? '/api/ai/support' : '/api/ai/chat';
            const body: Record<string, unknown> = {
                message: text,
                history: messages,
                model: selectedModel,
            };
            if (supportMode) {
                body.context_mode = contextMode;
            }

            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            if (!res.ok) throw new Error('Failed to get response');
            const data = await res.json();

            setMessages(prev => [...prev, { role: 'assistant', text: data.reply }]);
        } catch (_err) {
            setMessages(prev => [...prev, { role: 'assistant', text: "Connection error: Unable to reach the FlowAI backend service." }]);
        } finally {
            setIsTyping(false);
        }
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSendMessage();
        }
    };

    return (
        <div className="h-[calc(100vh-10rem)] flex flex-col bg-white/[0.01] border border-white/[0.03] rounded-3xl relative overflow-hidden animate-fade-in shadow-2xl backdrop-blur-xl">

            {/* Background gradient effects */}
            <div className={`absolute top-0 left-0 w-[500px] h-[500px] rounded-full blur-[100px] pointer-events-none -translate-x-1/2 -translate-y-1/2 transition-colors duration-700 ${supportMode ? 'bg-amber-500/10' : 'bg-indigo-500/10'}`}></div>
            <div className={`absolute bottom-0 right-0 w-[600px] h-[600px] rounded-full blur-[120px] pointer-events-none translate-x-1/3 translate-y-1/3 transition-colors duration-700 ${supportMode ? 'bg-orange-500/5' : 'bg-blue-500/5'}`}></div>

            <div className="flex items-center justify-between p-6 border-b border-white/[0.05] bg-slate-900/50 relative z-10 backdrop-blur-md">
                <div className="flex items-center gap-4">
                    <div className={`h-10 w-10 rounded-xl flex items-center justify-center border transition-colors duration-300 ${supportMode ? 'bg-amber-500/20 border-amber-500/30' : 'bg-indigo-500/20 border-indigo-500/30'}`}>
                        {supportMode ? <Wrench size={20} className="text-amber-400" /> : <Sparkles size={20} className="text-indigo-400" />}
                    </div>
                    <div>
                        <h2 className="text-lg font-bold text-slate-200 tracking-tight">
                            {supportMode ? 'FlowAI Support' : 'FlowAI Assistant'}
                        </h2>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5">
                                <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${supportMode ? 'bg-amber-400 animate-ping' : 'bg-indigo-400'}`}></span>
                                <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${supportMode ? 'bg-amber-500' : 'bg-indigo-500'}`}></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide">
                                {supportMode ? `Support · ${currentContext.name}` : `Ready · ${currentModel.name}`}
                            </span>
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    {/* Support Mode Toggle */}
                    <button
                        onClick={() => setSupportMode(!supportMode)}
                        className={`flex items-center gap-2 px-3 py-2 rounded-xl text-sm font-medium transition-all border ${supportMode
                            ? 'bg-amber-500/20 border-amber-500/30 text-amber-300 shadow-lg shadow-amber-500/10'
                            : 'bg-white/[0.04] border-white/10 text-slate-400 hover:bg-white/[0.08] hover:text-slate-300'
                            }`}
                    >
                        <Wrench size={14} />
                        <span>Support</span>
                    </button>

                    {/* Context Mode Selector (only visible in support mode) */}
                    {supportMode && (
                        <div className="relative" ref={contextPickerRef}>
                            <button
                                onClick={() => setShowContextPicker(!showContextPicker)}
                                className="flex items-center gap-2 px-3 py-2 bg-amber-500/10 border border-amber-500/20 rounded-xl text-sm text-amber-300 hover:bg-amber-500/20 transition-all"
                            >
                                <currentContext.icon size={14} />
                                <span className="font-medium">{currentContext.name}</span>
                                <ChevronDown size={14} className={`text-amber-500 transition-transform ${showContextPicker ? 'rotate-180' : ''}`} />
                            </button>

                            {showContextPicker && (
                                <div className="absolute right-0 top-full mt-2 w-64 bg-slate-900/95 backdrop-blur-xl border border-white/10 rounded-xl shadow-2xl z-50 overflow-hidden">
                                    <div className="p-2 border-b border-white/[0.05]">
                                        <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold px-2 py-1">Context Source</p>
                                    </div>
                                    <div className="p-1.5">
                                        {CONTEXT_MODES.map((mode) => (
                                            <button
                                                key={mode.id}
                                                onClick={() => { setContextMode(mode.id); setShowContextPicker(false); }}
                                                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm transition-all ${contextMode === mode.id
                                                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                                    : 'text-slate-300 hover:bg-white/[0.06] border border-transparent'
                                                    }`}
                                            >
                                                <div className="flex items-center gap-2.5">
                                                    <mode.icon size={14} className={contextMode === mode.id ? 'text-amber-400' : 'text-slate-500'} />
                                                    <div className="text-left">
                                                        <span className="font-medium block">{mode.name}</span>
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
                            onClick={() => setShowModelPicker(!showModelPicker)}
                            className="flex items-center gap-2 px-3 py-2 bg-white/[0.04] border border-white/10 rounded-xl text-sm text-slate-300 hover:bg-white/[0.08] hover:border-indigo-500/30 transition-all"
                        >
                            <Sparkles size={14} className="text-indigo-400" />
                            <span className="font-medium">{currentModel.name}</span>
                            <ChevronDown size={14} className={`text-slate-500 transition-transform ${showModelPicker ? 'rotate-180' : ''}`} />
                        </button>

                        {showModelPicker && (
                            <div className="absolute right-0 top-full mt-2 w-64 bg-slate-900/95 backdrop-blur-xl border border-white/10 rounded-xl shadow-2xl z-50 overflow-hidden">
                                <div className="p-2 border-b border-white/[0.05]">
                                    <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold px-2 py-1">Select Model</p>
                                </div>
                                <div className="p-1.5">
                                    {AI_MODELS.map((model) => (
                                        <button
                                            key={model.id}
                                            onClick={() => { setSelectedModel(model.id); setShowModelPicker(false); }}
                                            className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm transition-all ${selectedModel === model.id
                                                    ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                                                    : 'text-slate-300 hover:bg-white/[0.06] border border-transparent'
                                                }`}
                                        >
                                            <div className="flex items-center gap-2.5">
                                                <div className={`h-2 w-2 rounded-full ${selectedModel === model.id ? 'bg-indigo-400' : 'bg-slate-600'}`}></div>
                                                <span className="font-medium">{model.name}</span>
                                            </div>
                                            <span className={`text-[10px] uppercase tracking-wider font-bold px-1.5 py-0.5 rounded ${model.tier === 'latest'
                                                    ? 'bg-indigo-500/20 text-indigo-400'
                                                    : 'bg-slate-700/50 text-slate-500'
                                                }`}>
                                                {model.tier}
                                            </span>
                                        </button>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                    <button onClick={() => setActiveTab('settings')} className="p-2 text-slate-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors">
                        <Settings size={18} />
                    </button>
                </div>
            </div>

            {/* Support Mode Banner */}
            {supportMode && (
                <div className="px-6 py-3 bg-amber-500/5 border-b border-amber-500/10 flex items-center gap-3 relative z-10">
                    <div className="relative">
                        <div className="w-2 h-2 rounded-full bg-amber-400 animate-ping absolute"></div>
                        <div className="w-2 h-2 rounded-full bg-amber-500 relative"></div>
                    </div>
                    <span className="text-xs text-amber-400/80 font-medium">
                        Support Mode Active — FlowAI is reading live {contextMode === 'full' ? 'logs & metrics' : contextMode === 'logs' ? 'system logs' : 'system metrics'} to diagnose issues
                    </span>
                </div>
            )}

            {/* Chat Area */}
            <div ref={scrollRef} className="flex-1 overflow-y-auto p-8 space-y-8 relative z-10 no-scrollbar scroll-smooth">
                {messages.map((msg, index) => (
                    <div key={index} className={`flex gap-4 max-w-3xl ${msg.role === 'user' ? 'ml-auto justify-end' : ''}`}>
                        {msg.role === 'assistant' && (
                            <div className={`h-8 w-8 rounded-full border flex items-center justify-center shrink-0 mt-1 ${supportMode ? 'bg-amber-500/20 border-amber-500/30' : 'bg-indigo-500/20 border-indigo-500/30'}`}>
                                {supportMode ? <Wrench size={16} className="text-amber-400" /> : <Bot size={16} className="text-indigo-400" />}
                            </div>
                        )}

                        <div className={`p-5 rounded-2xl shadow-sm text-sm leading-relaxed whitespace-pre-wrap ${msg.role === 'user'
                            ? 'bg-indigo-600 text-white rounded-tr-sm font-medium'
                            : 'bg-white/[0.03] border border-white/[0.05] text-slate-200 rounded-tl-sm'
                            }`}>
                            {msg.text}
                        </div>

                        {msg.role === 'user' && (
                            <div className="h-8 w-8 rounded-full bg-slate-700/50 border border-white/10 flex items-center justify-center shrink-0 mt-1">
                                <User size={16} className="text-slate-300" />
                            </div>
                        )}
                    </div>
                ))}

                {isTyping && (
                    <div className="flex gap-4 max-w-3xl">
                        <div className={`h-8 w-8 rounded-full border flex items-center justify-center shrink-0 mt-1 ${supportMode ? 'bg-amber-500/20 border-amber-500/30' : 'bg-indigo-500/20 border-indigo-500/30'}`}>
                            {supportMode ? <Wrench size={16} className="text-amber-400" /> : <Bot size={16} className="text-indigo-400" />}
                        </div>
                        <div className="bg-white/[0.03] border border-white/[0.05] p-5 rounded-2xl rounded-tl-sm text-slate-200 flex items-center gap-2">
                            <span className={`w-2 h-2 rounded-full animate-bounce cursor-default ${supportMode ? 'bg-amber-500' : 'bg-indigo-500'}`} style={{ animationDelay: '0ms' }}></span>
                            <span className={`w-2 h-2 rounded-full animate-bounce cursor-default ${supportMode ? 'bg-amber-500' : 'bg-indigo-500'}`} style={{ animationDelay: '150ms' }}></span>
                            <span className={`w-2 h-2 rounded-full animate-bounce cursor-default ${supportMode ? 'bg-amber-500' : 'bg-indigo-500'}`} style={{ animationDelay: '300ms' }}></span>
                        </div>
                    </div>
                )}
            </div>

            {/* Input Area */}
            <div className="p-6 bg-slate-950/80 backdrop-blur-xl border-t border-white/[0.05] relative z-10 w-full">
                <form onSubmit={handleSendMessage} className={`relative max-w-4xl mx-auto flex items-end overflow-hidden rounded-2xl bg-white/[0.02] border focus-within:bg-white/[0.04] transition-all shadow-inner ${supportMode ? 'border-amber-500/20 focus-within:border-amber-500/50' : 'border-white/10 focus-within:border-indigo-500/50'}`}>
                    <textarea
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        placeholder={supportMode ? "Describe the issue you're troubleshooting..." : "Ask FlowAI about your system..."}
                        className="w-full bg-transparent py-4 pl-6 pr-16 text-slate-200 placeholder:text-slate-500 focus:outline-none resize-none overflow-hidden min-h-[56px] max-h-32 text-sm"
                        rows={1}
                        disabled={isTyping}
                    />
                    <div className="absolute right-2 bottom-2 flex gap-2">
                        <button type="button" className="p-2 text-slate-400 hover:text-white hover:bg-white/10 rounded-xl transition-colors">
                            <Lock size={18} />
                        </button>
                        <button
                            type="submit"
                            disabled={!input.trim() || isTyping}
                            className={`p-2 rounded-xl text-white shadow-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${supportMode ? 'bg-amber-500 hover:bg-amber-400' : 'bg-indigo-500 hover:bg-indigo-400'}`}
                        >
                            <ChevronRight size={18} />
                        </button>
                    </div>
                </form>
                <div className="text-center mt-3">
                    <p className="text-[10px] text-slate-500 font-medium">FlowAI can make mistakes. Verify critical configuration changes before applying.</p>
                </div>
            </div>
        </div>
    );
}
