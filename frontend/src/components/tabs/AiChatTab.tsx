import { Sparkles, Settings, Bot, User, ChevronRight, Lock } from 'lucide-react';
import { TabId } from '@/types/dashboard';

interface AiChatTabProps {
    setActiveTab: (tab: TabId) => void;
}

export default function AiChatTab({ setActiveTab }: AiChatTabProps) {
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
                            <span className="text-xs text-slate-400 font-medium tracking-wide">Ready via Selected Google AI Model</span>
                        </div>
                    </div>
                </div>
                <button onClick={() => setActiveTab('settings')} className="p-2 text-slate-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors">
                    <Settings size={18} />
                </button>
            </div>

            {/* Chat Area Mockup */}
            <div className="flex-1 overflow-y-auto p-8 space-y-8 relative z-10 no-scrollbar">
                {/* Assistant Intro */}
                <div className="flex gap-4 max-w-3xl">
                    <div className="h-8 w-8 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0 mt-1">
                        <Bot size={16} className="text-indigo-400" />
                    </div>
                    <div className="space-y-2">
                        <div className="bg-white/[0.03] border border-white/[0.05] p-5 rounded-2xl rounded-tl-sm text-slate-200 text-sm leading-relaxed shadow-sm">
                            Hello! I am FlowAI, your localized infrastructure management assistant. I'm connected to your system metrics, docker containers, and media pipelines.
                            <br /><br />
                            I noticed **WireGuard VPN** is currently returning an <span className="text-red-400 font-mono bg-red-500/10 px-1 py-0.5 rounded">error</span> state. Would you like me to pull the trace logs for you, or restart the container?
                        </div>
                        <div className="flex gap-2">
                            <button className="px-3 py-1.5 bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 rounded-md text-[11px] font-medium text-slate-300 transition-colors">Pull Trace Logs</button>
                            <button className="px-3 py-1.5 bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 rounded-md text-[11px] font-medium text-slate-300 transition-colors">Force Restart</button>
                        </div>
                    </div>
                </div>

                {/* User Message */}
                <div className="flex gap-4 max-w-3xl ml-auto justify-end">
                    <div className="bg-indigo-600 p-5 rounded-2xl rounded-tr-sm text-white text-sm leading-relaxed shadow-md font-medium">
                        Actually, let's look at the storage. How is the cache drive holding up?
                    </div>
                    <div className="h-8 w-8 rounded-full bg-slate-700/50 border border-white/10 flex items-center justify-center shrink-0 mt-1">
                        <User size={16} className="text-slate-300" />
                    </div>
                </div>

                {/* Assistant Reply */}
                <div className="flex gap-4 max-w-3xl">
                    <div className="h-8 w-8 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0 mt-1">
                        <Bot size={16} className="text-indigo-400" />
                    </div>
                    <div className="bg-white/[0.03] border border-white/[0.05] p-5 rounded-2xl rounded-tl-sm text-slate-200 text-sm leading-relaxed shadow-sm space-y-4">
                        <p>Your NVMe cache drive (`/` Root) is currently in excellent condition. It is at **18.4% capacity** (94.2 GB used out of 512 GB).</p>

                        <div className="p-4 bg-slate-900/50 rounded-xl border border-white/5 font-mono text-xs text-slate-400">
                            $ df -h /<br />
                            Filesystem      Size  Used Avail Use% Mounted on<br />
                            /dev/nvme0n1p2  512G   94G  418G  19% /
                        </div>
                        <p className="text-slate-400 italic text-xs">I can configure an automated alert if capacity exceeds 80%. Should I set that up?</p>
                    </div>
                </div>
            </div>

            {/* Input Area */}
            <div className="p-6 bg-slate-950/80 backdrop-blur-xl border-t border-white/[0.05] relative z-10 w-full">
                <div className="relative max-w-4xl mx-auto flex items-end overflow-hidden rounded-2xl bg-white/[0.02] border border-white/10 focus-within:border-indigo-500/50 focus-within:bg-white/[0.04] transition-all shadow-inner">
                    <textarea
                        placeholder="Ask FlowAI about your system..."
                        className="w-full bg-transparent py-4 pl-6 pr-16 text-slate-200 placeholder:text-slate-500 focus:outline-none resize-none overflow-hidden min-h-[56px] text-sm"
                        rows={1}
                    />
                    <div className="absolute right-2 bottom-2 flex gap-2">
                        <button className="p-2 text-slate-400 hover:text-white hover:bg-white/10 rounded-xl transition-colors">
                            <Lock size={18} />
                        </button>
                        <button className="p-2 bg-indigo-500 rounded-xl text-white hover:bg-indigo-400 shadow-md transition-colors">
                            <ChevronRight size={18} />
                        </button>
                    </div>
                </div>
                <div className="text-center mt-3">
                    <p className="text-[10px] text-slate-500 font-medium">FlowAI can make mistakes. Verify critical configuration changes before applying.</p>
                </div>
            </div>
        </div>
    );
}
