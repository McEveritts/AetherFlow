import { Sparkles, Settings, Bot, User, ChevronRight, Lock, ChevronDown } from 'lucide-react';
import { TabId } from '@/types/dashboard';
import { useState, useRef, useEffect, FormEvent } from 'react';

interface AiChatTabProps {
    setActiveTab: (tab: TabId) => void;
}

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

export default function AiChatTab({ setActiveTab }: AiChatTabProps) {
    const [messages, setMessages] = useState<ChatMessage[]>([
        { role: 'assistant', text: "Hello! I am FlowAI, your localized infrastructure management assistant. I'm connected to your system metrics, docker containers, and media pipelines.\n\nHow can I help you today?" }
    ]);
    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);
    const [selectedModel, setSelectedModel] = useState('gemini-2.5-pro');
    const [showModelPicker, setShowModelPicker] = useState(false);
    const scrollRef = useRef<HTMLDivElement>(null);
    const modelPickerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [messages, isTyping]);

    // Close model picker when clicking outside
    useEffect(() => {
        const handleClickOutside = (e: MouseEvent) => {
            if (modelPickerRef.current && !modelPickerRef.current.contains(e.target as Node)) {
                setShowModelPicker(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const currentModel = AI_MODELS.find(m => m.id === selectedModel) || AI_MODELS[0];

    const handleSendMessage = async (e?: FormEvent) => {
        if (e) e.preventDefault();

        const text = input.trim();
        if (!text || isTyping) return;

        setInput('');
        setMessages(prev => [...prev, { role: 'user', text }]);
        setIsTyping(true);

        try {
            const res = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text, history: messages, model: selectedModel })
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
            <div className="absolute top-0 left-0 w-[500px] h-[500px] bg-indigo-500/10 rounded-full blur-[100px] pointer-events-none -translate-x-1/2 -translate-y-1/2"></div>
            <div className="absolute bottom-0 right-0 w-[600px] h-[600px] bg-blue-500/5 rounded-full blur-[120px] pointer-events-none translate-x-1/3 translate-y-1/3"></div>

            <div className="flex items-center justify-between p-6 border-b border-white/[0.05] bg-slate-900/50 relative z-10 backdrop-blur-md">
                <div className="flex items-center gap-4">
                    <div className="h-10 w-10 bg-indigo-500/20 rounded-xl flex items-center justify-center border border-indigo-500/30">
                        <Sparkles size={20} className="text-indigo-400" />
                    </div>
                    <div>
                        <h2 className="text-lg font-bold text-slate-200 tracking-tight">FlowAI Assistant</h2>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5"><span className="absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span><span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-indigo-500"></span></span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide">Ready · {currentModel.name}</span>
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-2">
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

            {/* Chat Area */}
            <div ref={scrollRef} className="flex-1 overflow-y-auto p-8 space-y-8 relative z-10 no-scrollbar scroll-smooth">
                {messages.map((msg, index) => (
                    <div key={index} className={`flex gap-4 max-w-3xl ${msg.role === 'user' ? 'ml-auto justify-end' : ''}`}>
                        {msg.role === 'assistant' && (
                            <div className="h-8 w-8 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0 mt-1">
                                <Bot size={16} className="text-indigo-400" />
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
                        <div className="h-8 w-8 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0 mt-1">
                            <Bot size={16} className="text-indigo-400" />
                        </div>
                        <div className="bg-white/[0.03] border border-white/[0.05] p-5 rounded-2xl rounded-tl-sm text-slate-200 flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-indigo-500 animate-bounce cursor-default" style={{ animationDelay: '0ms' }}></span>
                            <span className="w-2 h-2 rounded-full bg-indigo-500 animate-bounce cursor-default" style={{ animationDelay: '150ms' }}></span>
                            <span className="w-2 h-2 rounded-full bg-indigo-500 animate-bounce cursor-default" style={{ animationDelay: '300ms' }}></span>
                        </div>
                    </div>
                )}
            </div>

            {/* Input Area */}
            <div className="p-6 bg-slate-950/80 backdrop-blur-xl border-t border-white/[0.05] relative z-10 w-full">
                <form onSubmit={handleSendMessage} className="relative max-w-4xl mx-auto flex items-end overflow-hidden rounded-2xl bg-white/[0.02] border border-white/10 focus-within:border-indigo-500/50 focus-within:bg-white/[0.04] transition-all shadow-inner">
                    <textarea
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        placeholder="Ask FlowAI about your system..."
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
                            className="p-2 bg-indigo-500 rounded-xl text-white hover:bg-indigo-400 shadow-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
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
