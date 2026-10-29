'use client';

import React, { useState } from 'react';
import useSWR from 'swr';
import {
    Bell,
    AlertTriangle,
    ShieldAlert,
    CheckCircle2,
    Plus,
    Trash2,
    Send,
    Radio,
    ToggleLeft,
    ToggleRight,
    RefreshCw,
    Sliders,
    MessageSquare,
    Webhook,
    Cpu,
    HardDrive,
    Activity,
    Layers,
    X,
    ExternalLink
} from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import { useToast } from '@/contexts/ToastContext';

export interface NotificationRule {
    id: number;
    name: string;
    condition_type: 'disk_usage' | 'cpu_usage' | 'memory_usage' | 'service_down';
    condition_value: string;
    level: 'info' | 'warning' | 'critical';
    enabled: boolean;
    created_at?: string;
}

export interface NotificationChannel {
    id: number;
    name: string;
    type: 'discord' | 'telegram' | 'slack' | 'custom';
    config: string | Record<string, unknown>;
    enabled: boolean;
    created_at?: string;
}

const fetcher = (url: string) => apiFetch(url).then(res => res.json());

export default function NotificationsSettingsTab() {
    const { addToast } = useToast();
    const [activeSection, setActiveSection] = useState<'rules' | 'channels'>('rules');

    // SWR Data Fetching
    const {
        data: rulesData,
        error: rulesError,
        isLoading: rulesLoading,
        mutate: mutateRules
    } = useSWR<{ rules: NotificationRule[] }>('/api/v1/admin/notifications/rules', fetcher, {
        refreshInterval: 15000,
    });

    const {
        data: channelsData,
        error: channelsError,
        isLoading: channelsLoading,
        mutate: mutateChannels
    } = useSWR<{ channels: NotificationChannel[] }>('/api/v1/admin/notifications/channels', fetcher, {
        refreshInterval: 15000,
    });

    const rules = rulesData?.rules || [];
    const channels = channelsData?.channels || [];

    // Modals
    const [showAddRuleModal, setShowAddRuleModal] = useState(false);
    const [showAddChannelModal, setShowAddChannelModal] = useState(false);
    const [testingChannelId, setTestingChannelId] = useState<number | null>(null);
    const [togglingRuleId, setTogglingRuleId] = useState<number | null>(null);

    // Add Rule Form
    const [ruleName, setRuleName] = useState('');
    const [conditionType, setConditionType] = useState<'cpu_usage' | 'memory_usage' | 'disk_usage' | 'service_down'>('cpu_usage');
    const [conditionValue, setConditionValue] = useState('85');
    const [ruleLevel, setRuleLevel] = useState<'info' | 'warning' | 'critical'>('warning');
    const [isSubmittingRule, setIsSubmittingRule] = useState(false);

    // Add Channel Form
    const [channelName, setChannelName] = useState('');
    const [channelType, setChannelType] = useState<'discord' | 'telegram' | 'slack' | 'custom'>('discord');
    const [webhookUrl, setWebhookUrl] = useState('');
    const [botToken, setBotToken] = useState('');
    const [chatId, setChatId] = useState('');
    const [isSubmittingChannel, setIsSubmittingChannel] = useState(false);

    // Handlers
    const handleToggleRule = async (rule: NotificationRule) => {
        setTogglingRuleId(rule.id);
        const newEnabled = !rule.enabled;
        try {
            const res = await apiFetch(`/api/v1/admin/notifications/rules/${rule.id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: newEnabled }),
            });
            if (!res.ok) throw new Error('Failed to update rule');
            addToast(`Alert rule "${rule.name}" ${newEnabled ? 'enabled' : 'disabled'}.`, 'success');
            mutateRules();
        } catch {
            addToast('Failed to update alert rule.', 'error');
        } finally {
            setTogglingRuleId(null);
        }
    };

    const handleDeleteRule = async (id: number, name: string) => {
        if (!confirm(`Are you sure you want to delete alert rule "${name}"?`)) return;
        try {
            const res = await apiFetch(`/api/v1/admin/notifications/rules/${id}`, { method: 'DELETE' });
            if (!res.ok) throw new Error('Failed to delete rule');
            addToast(`Rule "${name}" deleted.`, 'success');
            mutateRules();
        } catch {
            addToast('Failed to delete rule.', 'error');
        }
    };

    const handleCreateRule = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!ruleName.trim()) {
            addToast('Rule name is required.', 'error');
            return;
        }
        setIsSubmittingRule(true);
        try {
            const res = await apiFetch('/api/v1/admin/notifications/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: ruleName.trim(),
                    condition_type: conditionType,
                    condition_value: conditionValue.trim(),
                    level: ruleLevel,
                }),
            });
            if (!res.ok) throw new Error('Failed to create rule');
            addToast(`Alert rule "${ruleName}" created.`, 'success');
            setShowAddRuleModal(false);
            setRuleName('');
            setConditionValue('85');
            mutateRules();
        } catch {
            addToast('Failed to create alert rule.', 'error');
        } finally {
            setIsSubmittingRule(false);
        }
    };

    const handleTestChannel = async (channel: NotificationChannel) => {
        setTestingChannelId(channel.id);
        try {
            const res = await apiFetch(`/api/v1/admin/notifications/channels/${channel.id}/test`, {
                method: 'POST',
            });
            if (!res.ok) throw new Error('Test failed');
            const data = await res.json().catch(() => ({}));
            addToast(data.message || `Test dispatch sent to ${channel.name}!`, 'success');
        } catch {
            addToast(`Failed to dispatch test notification to ${channel.name}.`, 'error');
        } finally {
            setTestingChannelId(null);
        }
    };

    const handleDeleteChannel = async (id: number, name: string) => {
        if (!confirm(`Are you sure you want to delete delivery channel "${name}"?`)) return;
        try {
            const res = await apiFetch(`/api/v1/admin/notifications/channels/${id}`, { method: 'DELETE' });
            if (!res.ok) throw new Error('Failed to delete channel');
            addToast(`Channel "${name}" removed.`, 'success');
            mutateChannels();
        } catch {
            addToast('Failed to delete channel.', 'error');
        }
    };

    const handleCreateChannel = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!channelName.trim()) {
            addToast('Channel name is required.', 'error');
            return;
        }

        let configObj: Record<string, string> = {};
        if (channelType === 'telegram') {
            if (!botToken.trim() || !chatId.trim()) {
                addToast('Bot Token and Chat ID are required for Telegram.', 'error');
                return;
            }
            configObj = { bot_token: botToken.trim(), chat_id: chatId.trim() };
        } else {
            if (!webhookUrl.trim()) {
                addToast('Webhook URL is required.', 'error');
                return;
            }
            configObj = { webhook_url: webhookUrl.trim() };
        }

        setIsSubmittingChannel(false);
        try {
            const res = await apiFetch('/api/v1/admin/notifications/channels', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: channelName.trim(),
                    type: channelType,
                    config: configObj,
                    enabled: true,
                }),
            });
            if (!res.ok) throw new Error('Failed to create channel');
            addToast(`Notification channel "${channelName}" added.`, 'success');
            setShowAddChannelModal(false);
            setChannelName('');
            setWebhookUrl('');
            setBotToken('');
            setChatId('');
            mutateChannels();
        } catch {
            addToast('Failed to create notification channel.', 'error');
        } finally {
            setIsSubmittingChannel(false);
        }
    };

    const renderSeverityBadge = (level: string) => {
        switch (level) {
            case 'critical':
                return (
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider bg-rose-500/20 text-rose-400 border border-rose-500/40">
                        Critical
                    </span>
                );
            case 'warning':
                return (
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider bg-amber-500/20 text-amber-400 border border-amber-500/40">
                        Warning
                    </span>
                );
            default:
                return (
                    <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider bg-sky-500/20 text-sky-400 border border-sky-500/40">
                        Info
                    </span>
                );
        }
    };

    const renderConditionIcon = (type: string) => {
        switch (type) {
            case 'cpu_usage':
                return <Cpu size={15} className="text-indigo-400" />;
            case 'memory_usage':
                return <Activity size={15} className="text-cyan-400" />;
            case 'disk_usage':
                return <HardDrive size={15} className="text-amber-400" />;
            case 'service_down':
                return <AlertTriangle size={15} className="text-rose-400" />;
            default:
                return <Sliders size={15} className="text-slate-400" />;
        }
    };

    const parseChannelTarget = (channel: NotificationChannel) => {
        try {
            const cfg = typeof channel.config === 'string' ? JSON.parse(channel.config) : channel.config;
            if (cfg?.webhook_url) {
                const url = cfg.webhook_url as string;
                if (url.length > 36) return `${url.substring(0, 36)}...`;
                return url;
            }
            if (cfg?.chat_id) return `Chat ID: ${cfg.chat_id}`;
            return 'Configured';
        } catch {
            return 'Configured';
        }
    };

    return (
        <div className="space-y-6 w-full animate-fade-in text-slate-100">
            {/* Sub-toolbar with Segmented Switcher */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-white/[0.06]">
                <div className="flex items-center gap-3">
                    <div className="h-9 w-9 rounded-xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 text-indigo-400">
                        <Bell size={18} />
                    </div>
                    <div>
                        <h3 className="text-base font-semibold text-slate-100">Alert Dispatcher & Rules</h3>
                        <p className="text-xs text-slate-400 mt-0.5">
                            Real-time monitoring rules, threshold alerts, and outbound webhook dispatchers.
                        </p>
                    </div>
                </div>

                {/* Segmented Switcher */}
                <div className="flex items-center bg-slate-900/60 border border-white/[0.06] p-1 rounded-xl">
                    <button
                        type="button"
                        onClick={() => setActiveSection('rules')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-2 ${
                            activeSection === 'rules'
                                ? 'bg-indigo-600 text-white shadow-sm'
                                : 'text-slate-400 hover:text-slate-200'
                        }`}
                    >
                        <Sliders size={13} /> Alert Rules ({rules.length})
                    </button>
                    <button
                        type="button"
                        onClick={() => setActiveSection('channels')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-2 ${
                            activeSection === 'channels'
                                ? 'bg-indigo-600 text-white shadow-sm'
                                : 'text-slate-400 hover:text-slate-200'
                        }`}
                    >
                        <Radio size={13} /> Delivery Channels ({channels.length})
                    </button>
                </div>
            </div>

            {/* SECTION 1: ALERT RULES */}
            {activeSection === 'rules' && (
                <div className="space-y-4">
                    <div className="flex items-center justify-between px-1">
                        <div>
                            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400">
                                Configured Trigger Conditions
                            </h3>
                            <p className="text-xs text-slate-500">
                                Background engine continuously evaluates host telemetry against these threshold rules.
                            </p>
                        </div>
                        <button
                            type="button"
                            onClick={() => setShowAddRuleModal(true)}
                            className="px-4 py-2 bg-gradient-to-r from-indigo-500 to-fuchsia-600 hover:from-indigo-400 hover:to-fuchsia-500 rounded-xl text-xs font-bold text-white transition-all shadow-lg shadow-indigo-500/20 flex items-center gap-2"
                        >
                            <Plus size={15} /> Add Rule
                        </button>
                    </div>

                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl overflow-hidden divide-y divide-white/[0.06]">
                        {rulesLoading ? (
                            <div className="p-8 text-center text-slate-400 text-sm flex items-center justify-center gap-3">
                                <RefreshCw size={18} className="animate-spin text-indigo-400" />
                                Loading configured rules...
                            </div>
                        ) : rules.length === 0 ? (
                            <div className="p-12 text-center space-y-3">
                                <Sliders size={32} className="mx-auto text-slate-600" />
                                <h4 className="text-sm font-semibold text-slate-300">No Alert Rules Configured</h4>
                                <p className="text-xs text-slate-500 max-w-sm mx-auto">
                                    Define rules to automatically trigger notifications when CPU, memory, disk usage or services degrade.
                                </p>
                            </div>
                        ) : (
                            rules.map((rule) => (
                                <div
                                    key={rule.id}
                                    className={`p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors ${
                                        rule.enabled ? 'hover:bg-white/[0.02]' : 'bg-black/20 opacity-60'
                                    }`}
                                >
                                    <div className="flex items-start sm:items-center gap-3.5">
                                        <div className="p-2.5 rounded-xl bg-white/[0.04] border border-white/10 shrink-0 mt-0.5 sm:mt-0">
                                            {renderConditionIcon(rule.condition_type)}
                                        </div>
                                        <div>
                                            <div className="flex items-center gap-2.5 flex-wrap">
                                                <span className="font-semibold text-white text-sm">
                                                    {rule.name}
                                                </span>
                                                {renderSeverityBadge(rule.level)}
                                            </div>
                                            <div className="flex items-center gap-3 text-xs text-slate-400 mt-1 font-mono">
                                                <span className="capitalize">{rule.condition_type.replace('_', ' ')}:</span>
                                                <span className="text-indigo-300 font-bold">
                                                    {rule.condition_type === 'service_down'
                                                        ? `down (${rule.condition_value})`
                                                        : `≥ ${rule.condition_value}%`}
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-2 self-end sm:self-center">
                                        <button
                                            type="button"
                                            disabled={togglingRuleId === rule.id}
                                            onClick={() => handleToggleRule(rule)}
                                            className="px-3 py-1.5 rounded-lg text-xs font-semibold border border-white/10 hover:border-white/20 text-slate-300 hover:text-white flex items-center gap-1.5 transition-colors"
                                        >
                                            {rule.enabled ? (
                                                <>
                                                    <ToggleRight size={16} className="text-emerald-400" /> Active
                                                </>
                                            ) : (
                                                <>
                                                    <ToggleLeft size={16} className="text-slate-500" /> Disabled
                                                </>
                                            )}
                                        </button>
                                        <button
                                            type="button"
                                            onClick={() => handleDeleteRule(rule.id, rule.name)}
                                            className="p-2 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                                            title="Delete Rule"
                                        >
                                            <Trash2 size={16} />
                                        </button>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            )}

            {/* SECTION 2: DELIVERY CHANNELS */}
            {activeSection === 'channels' && (
                <div className="space-y-4">
                    <div className="flex items-center justify-between px-1">
                        <div>
                            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-400">
                                Outbound Webhook Integrations
                            </h3>
                            <p className="text-xs text-slate-500">
                                Forward alerts to team chat platforms, incident webhooks, and mobile bots.
                            </p>
                        </div>
                        <button
                            type="button"
                            onClick={() => setShowAddChannelModal(true)}
                            className="px-4 py-2 bg-gradient-to-r from-indigo-500 to-fuchsia-600 hover:from-indigo-400 hover:to-fuchsia-500 rounded-xl text-xs font-bold text-white transition-all shadow-lg shadow-indigo-500/20 flex items-center gap-2"
                        >
                            <Plus size={15} /> Add Channel
                        </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {channelsLoading ? (
                            <div className="col-span-full p-8 text-center text-slate-400 text-sm flex items-center justify-center gap-3">
                                <RefreshCw size={18} className="animate-spin text-indigo-400" />
                                Loading delivery channels...
                            </div>
                        ) : channels.length === 0 ? (
                            <div className="col-span-full p-12 text-center rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl space-y-3">
                                <MessageSquare size={32} className="mx-auto text-slate-600" />
                                <h4 className="text-sm font-semibold text-slate-300">No Delivery Channels Connected</h4>
                                <p className="text-xs text-slate-500 max-w-sm mx-auto">
                                    Configure Discord, Telegram, Slack, or generic webhook endpoints to receive instant alerts.
                                </p>
                            </div>
                        ) : (
                            channels.map((channel) => (
                                <div
                                    key={channel.id}
                                    className="p-5 rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl flex flex-col justify-between gap-4 relative overflow-hidden group hover:border-white/10 transition-all"
                                >
                                    <div className="flex items-start justify-between gap-3">
                                        <div className="flex items-center gap-3">
                                            <div className="w-10 h-10 rounded-xl bg-white/[0.04] border border-white/10 flex items-center justify-center text-indigo-400">
                                                {channel.type === 'discord' && <MessageSquare size={18} className="text-indigo-400" />}
                                                {channel.type === 'slack' && <MessageSquare size={18} className="text-amber-400" />}
                                                {channel.type === 'telegram' && <Send size={18} className="text-sky-400" />}
                                                {channel.type === 'custom' && <Webhook size={18} className="text-fuchsia-400" />}
                                            </div>
                                            <div>
                                                <h4 className="font-semibold text-sm text-white group-hover:text-indigo-200 transition-colors">
                                                    {channel.name}
                                                </h4>
                                                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 bg-white/[0.04] px-2 py-0.5 rounded border border-white/5">
                                                    {channel.type}
                                                </span>
                                            </div>
                                        </div>

                                        <button
                                            type="button"
                                            onClick={() => handleDeleteChannel(channel.id, channel.name)}
                                            className="p-1.5 text-slate-500 hover:text-rose-400 rounded-lg hover:bg-rose-500/10 transition-colors"
                                            title="Delete Channel"
                                        >
                                            <Trash2 size={15} />
                                        </button>
                                    </div>

                                    <div className="text-xs text-slate-400 font-mono bg-black/40 px-3 py-2 rounded-xl border border-white/5 truncate">
                                        {parseChannelTarget(channel)}
                                    </div>

                                    <div className="flex items-center justify-between pt-2 border-t border-white/5">
                                        <span className="text-[11px] text-emerald-400 flex items-center gap-1.5">
                                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Ready
                                        </span>
                                        <button
                                            type="button"
                                            disabled={testingChannelId === channel.id}
                                            onClick={() => handleTestChannel(channel)}
                                            className="px-3 py-1.5 bg-white/[0.05] hover:bg-white/[0.1] disabled:opacity-50 rounded-xl text-xs font-semibold text-slate-200 hover:text-white flex items-center gap-1.5 transition-all"
                                        >
                                            {testingChannelId === channel.id ? (
                                                <>
                                                    <RefreshCw size={13} className="animate-spin text-indigo-400" /> Dispatching...
                                                </>
                                            ) : (
                                                <>
                                                    <Send size={13} className="text-indigo-400" /> Send Test
                                                </>
                                            )}
                                        </button>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            )}

            {/* MODAL: ADD ALERT RULE */}
            {showAddRuleModal && (
                <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
                    <div className="w-full max-w-md p-6 rounded-2xl border border-white/[0.08] bg-slate-900/95 backdrop-blur-2xl shadow-2xl relative animate-fade-in">
                        <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-5">
                            <h3 className="text-base font-bold text-white flex items-center gap-2">
                                <Plus size={18} className="text-indigo-400" /> Add Alert Threshold Rule
                            </h3>
                            <button
                                onClick={() => setShowAddRuleModal(false)}
                                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
                            >
                                <X size={18} />
                            </button>
                        </div>

                        <form onSubmit={handleCreateRule} className="space-y-4">
                            <div>
                                <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                                    Rule Name
                                </label>
                                <input
                                    type="text"
                                    required
                                    placeholder="e.g. High CPU Usage Warning"
                                    value={ruleName}
                                    onChange={(e) => setRuleName(e.target.value)}
                                    className="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/60"
                                />
                            </div>

                            <div>
                                <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                                    Condition Metric
                                </label>
                                <select
                                    value={conditionType}
                                    onChange={(e) => setConditionType(e.target.value as typeof conditionType)}
                                    className="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-indigo-500/60"
                                >
                                    <option value="cpu_usage">CPU Usage (%)</option>
                                    <option value="memory_usage">Memory Usage (%)</option>
                                    <option value="disk_usage">Disk Space Usage (%)</option>
                                    <option value="service_down">Service Stopped / Down</option>
                                </select>
                            </div>

                            <div>
                                <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                                    {conditionType === 'service_down' ? 'Service Name' : 'Threshold Value (%)'}
                                </label>
                                <input
                                    type="text"
                                    required
                                    placeholder={conditionType === 'service_down' ? 'e.g. rtorrent, plex, nginx' : 'e.g. 90'}
                                    value={conditionValue}
                                    onChange={(e) => setConditionValue(e.target.value)}
                                    className="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/60"
                                />
                            </div>

                            <div>
                                <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                                    Severity Level
                                </label>
                                <select
                                    value={ruleLevel}
                                    onChange={(e) => setRuleLevel(e.target.value as typeof ruleLevel)}
                                    className="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-indigo-500/60"
                                >
                                    <option value="info">Info</option>
                                    <option value="warning">Warning</option>
                                    <option value="critical">Critical</option>
                                </select>
                            </div>

                            <div className="flex items-center justify-end gap-3 pt-4 border-t border-white/10">
                                <button
                                    type="button"
                                    onClick={() => setShowAddRuleModal(false)}
                                    className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={isSubmittingRule}
                                    className="px-5 py-2 bg-gradient-to-r from-indigo-500 to-fuchsia-600 hover:from-indigo-400 hover:to-fuchsia-500 rounded-xl text-xs font-bold text-white transition-all shadow-lg shadow-indigo-500/20 disabled:opacity-50"
                                >
                                    {isSubmittingRule ? 'Saving...' : 'Create Rule'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* MODAL: ADD DELIVERY CHANNEL */}
            {showAddChannelModal && (
                <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
                    <div className="w-full max-w-md p-6 rounded-2xl border border-white/[0.08] bg-slate-900/95 backdrop-blur-2xl shadow-2xl relative animate-fade-in">
                        <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-5">
                            <h3 className="text-base font-bold text-white flex items-center gap-2">
                                <Plus size={18} className="text-indigo-400" /> Connect Notification Channel
                            </h3>
                            <button
                                onClick={() => setShowAddChannelModal(false)}
                                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
                            >
                                <X size={18} />
                            </button>
                        </div>

                        <form onSubmit={handleCreateChannel} className="space-y-4">
                            <div>
                                <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                                    Channel Name
                                </label>
                                <input
                                    type="text"
                                    required
                                    placeholder="e.g. DevOps Discord, Alert Slack"
                                    value={channelName}
                                    onChange={(e) => setChannelName(e.target.value)}
                                    className="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/60"
                                />
                            </div>

                            <div>
                                <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                                    Platform Type
                                </label>
                                <select
                                    value={channelType}
                                    onChange={(e) => setChannelType(e.target.value as typeof channelType)}
                                    className="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-indigo-500/60"
                                >
                                    <option value="discord">Discord Webhook</option>
                                    <option value="slack">Slack Incoming Webhook</option>
                                    <option value="telegram">Telegram Bot</option>
                                    <option value="custom">Generic JSON Webhook</option>
                                </select>
                            </div>

                            {channelType !== 'telegram' ? (
                                <div>
                                    <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                                        Webhook Target URL
                                    </label>
                                    <input
                                        type="url"
                                        required
                                        placeholder="https://discord.com/api/webhooks/..."
                                        value={webhookUrl}
                                        onChange={(e) => setWebhookUrl(e.target.value)}
                                        className="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/60 font-mono"
                                    />
                                </div>
                            ) : (
                                <>
                                    <div>
                                        <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                                            Telegram Bot Token (Secret)
                                        </label>
                                        <input
                                            type="password"
                                            required
                                            placeholder="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ"
                                            value={botToken}
                                            onChange={(e) => setBotToken(e.target.value)}
                                            className="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/60 font-mono"
                                        />
                                    </div>
                                    <div>
                                        <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-1.5">
                                            Target Chat ID
                                        </label>
                                        <input
                                            type="text"
                                            required
                                            placeholder="-100123456789"
                                            value={chatId}
                                            onChange={(e) => setChatId(e.target.value)}
                                            className="w-full bg-black/50 border border-white/10 rounded-xl px-3.5 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-indigo-500/60 font-mono"
                                        />
                                    </div>
                                </>
                            )}

                            <div className="flex items-center justify-end gap-3 pt-4 border-t border-white/10">
                                <button
                                    type="button"
                                    onClick={() => setShowAddChannelModal(false)}
                                    className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={isSubmittingChannel}
                                    className="px-5 py-2 bg-gradient-to-r from-indigo-500 to-fuchsia-600 hover:from-indigo-400 hover:to-fuchsia-500 rounded-xl text-xs font-bold text-white transition-all shadow-lg shadow-indigo-500/20 disabled:opacity-50"
                                >
                                    {isSubmittingChannel ? 'Saving...' : 'Connect Channel'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
