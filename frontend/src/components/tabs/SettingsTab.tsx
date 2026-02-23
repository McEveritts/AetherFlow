import { Settings, Sparkles, Shield, ChevronRight } from 'lucide-react';

export default function SettingsTab() {
    return (
        <div className="space-y-6 animate-fade-in relative z-10">
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-10 backdrop-blur-xl relative overflow-hidden">
                {/* Background glow for settings */}
                <div className="absolute top-0 right-0 w-[400px] h-[400px] bg-slate-500/10 rounded-full blur-[100px] pointer-events-none -translate-y-1/2 translate-x-1/3"></div>

                <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3 mb-8 pb-4 border-b border-white/5 relative z-10">
                    <Settings size={24} className="text-slate-400" />
                    System Settings & AI Configuration
                </h2>

                <div className="max-w-2xl space-y-8 relative z-10">
                    {/* FlowAI Config block */}
                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6">
                        <h3 className="text-lg font-bold text-slate-200 mb-6 flex items-center gap-2">
                            <Sparkles size={18} className="text-indigo-400" /> FlowAI Engine
                        </h3>
                        <div className="space-y-6">
                            <div>
                                <label className="block text-sm font-semibold text-slate-300 mb-2">Active Language Model (Google OAuth)</label>
                                <div className="relative">
                                    <select className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3.5 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer">
                                        <option value="gemini-1.5-ultra">Gemini 1.5 Ultra (Google OAuth Connected)</option>
                                        <option value="gemini-1.5-pro">Gemini 1.5 Pro (Google OAuth Connected)</option>
                                        <option value="gemini-1.0-pro">Gemini 1.0 Pro</option>
                                    </select>
                                    <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                                </div>
                                <p className="text-xs text-slate-500 mt-2">Select the underlying model for FlowAI computations. Ultra provides best performance for complex log analysis.</p>
                            </div>

                            <div>
                                <label className="block text-sm font-semibold text-slate-300 mb-2">Default System Prompt</label>
                                <textarea
                                    className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors min-h-[100px] resize-none"
                                    defaultValue="You are FlowAI, a highly intelligent infrastructure assistant connected to a local Next.js + Go Nexus environment. Always prioritize safe and performant configurations."
                                />
                                <p className="text-xs text-slate-500 mt-2">Tune the prompt to modify the assistant's behavior and strictness.</p>
                            </div>
                        </div>
                    </div>

                    {/* Other settings mock */}
                    <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6 opacity-50 pointer-events-none">
                        <h3 className="text-lg font-bold text-slate-200 mb-6 flex items-center gap-2">
                            <Shield size={18} className="text-emerald-400" /> Security Policies
                            <span className="text-[10px] font-bold bg-white/10 px-2 py-0.5 rounded ml-2">Coming Soon</span>
                        </h3>
                        <div className="space-y-4 text-sm text-slate-400">
                            Configuration restricted in demo mode.
                        </div>
                    </div>

                    <button className="px-8 py-3 bg-indigo-500 hover:bg-indigo-400 rounded-xl text-sm font-bold text-white transition-all shadow-lg shadow-indigo-500/20">
                        Save Configuration
                    </button>
                </div>
            </div>
        </div>
    );
}
