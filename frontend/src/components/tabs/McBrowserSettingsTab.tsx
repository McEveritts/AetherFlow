'use client';

import React, { useState } from 'react';
import { Folder, Shield, Activity, ArrowUpRight, Sparkles } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useSystemStore } from '@/store/useSystemStore';
import McBrowserPolicyAdmin from '@/components/mcbrowser/McBrowserPolicyAdmin';
import McBrowserEventsAdmin from '@/components/mcbrowser/McBrowserEventsAdmin';

export default function McBrowserSettingsTab() {
    const { user, isAuthenticated } = useAuth();
    const setActiveTab = useSystemStore((s) => s.setActiveTab);
    const [eventsAdminOpen, setEventsAdminOpen] = useState(false);

    const isAdmin = Boolean(isAuthenticated && user?.role === 'admin');

    return (
        <div className="space-y-6 animate-fade-in w-full">
            <div className="glass-panel p-6 rounded-2xl border border-white/[0.06] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-start gap-3.5">
                    <div className="h-11 w-11 rounded-2xl flex items-center justify-center border bg-indigo-500/15 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.2)] text-indigo-400 shrink-0">
                        <Folder size={22} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5 flex-wrap">
                            <h3 className="text-base font-bold text-slate-100">
                                McBrowser Administration &amp; File Policies
                            </h3>
                            <span className="text-[11px] font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                FlowAI Paired Search
                            </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">
                            Manage per-user workspace confinement, 8-flag operation permissions, prefix/regex access rules, and audit event queues for McBrowser.
                        </p>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0">
                    {isAdmin && (
                        <button
                            type="button"
                            aria-expanded={eventsAdminOpen}
                            onClick={() => setEventsAdminOpen((open) => !open)}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3.5 py-2 rounded-xl border border-indigo-500/30 text-xs font-semibold text-indigo-200 bg-indigo-500/10 hover:bg-indigo-500/20 transition-all"
                        >
                            <Activity size={14} className="text-indigo-400" />
                            <span>Audit Events &amp; Internal Queue</span>
                        </button>
                    )}
                    <button
                        type="button"
                        onClick={() => setActiveTab('fileshare')}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-white/10 bg-white/[0.04] hover:bg-white/[0.08] text-xs font-semibold text-slate-200 transition-all"
                    >
                        <span>Open McBrowser</span>
                        <ArrowUpRight size={14} className="text-indigo-400" />
                    </button>
                </div>
            </div>

            {isAdmin ? (
                <>
                    {eventsAdminOpen && (
                        <section aria-label="McBrowser audit administration" className="space-y-3">
                            <McBrowserEventsAdmin
                                onClose={() => setEventsAdminOpen(false)}
                            />
                        </section>
                    )}

                    <McBrowserPolicyAdmin
                        initialTargetUserId={user?.id}
                    />
                </>
            ) : (
                <div className="glass-panel p-6 rounded-2xl border border-white/[0.06] flex items-center gap-3 text-xs text-slate-300">
                    <Shield size={18} className="text-amber-400 shrink-0" />
                    <span>
                        Administrator privileges are required to edit per-user McBrowser file policies and inspect the system-wide audit event queue. Your personal view preferences (List/Grid/Gallery, sort order, hidden files, and FlowAI natural language search) can be toggled directly inside the McBrowser workspace toolbar.
                    </span>
                </div>
            )}
        </div>
    );
}
