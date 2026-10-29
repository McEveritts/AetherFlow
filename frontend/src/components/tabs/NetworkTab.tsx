'use client';

import React, { useState } from 'react';
import useSWR from 'swr';
import { Network, Shield, KeyRound, Plus, Trash2, RefreshCw, Send, CheckCircle2, AlertCircle, Laptop, Radio, Server, Globe, Activity, ArrowDownUp } from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import { useToast } from '@/contexts/ToastContext';

interface WireGuardPeer {
    public_key: string;
    endpoint?: string;
    allowed_ips: string;
    latest_handshake?: string;
    transfer_rx?: string;
    transfer_tx?: string;
}

interface WireGuardStatus {
    interface: string;
    public_key: string;
    listen_port: string;
    peers: WireGuardPeer[];
}

interface TailscalePeer {
    id: string;
    hostname: string;
    dns_name: string;
    tailscale_ip: string;
    os: string;
    online: boolean;
    exit_node: boolean;
    tags?: string[];
}

interface TailscaleStatus {
    backend_state: string;
    self?: TailscalePeer;
    peers: TailscalePeer[];
    magic_dns: boolean;
}

interface NetworkStatusResponse {
    wireguard?: WireGuardStatus;
    tailscale?: TailscaleStatus;
    wireguard_available: boolean;
    tailscale_available: boolean;
    platform: string;
}

const fetcher = (url: string) => apiFetch(url).then(res => res.json());

export default function NetworkTab() {
    const { addToast } = useToast();
    const [activeSection, setActiveSection] = useState<'wireguard' | 'tailscale'>('wireguard');

    // Network status query
    const { data: networkStatus, isValidating: isValidatingStatus, mutate: mutateStatus } = useSWR<NetworkStatusResponse>(
        '/api/v1/admin/network/status',
        fetcher,
        { refreshInterval: 15000 }
    );

    // WireGuard peers query
    const { data: wgPeersData, mutate: mutateWgPeers } = useSWR<{ peers: WireGuardPeer[] }>(
        '/api/v1/admin/network/wireguard/peers',
        fetcher,
        { refreshInterval: 10000 }
    );

    // Tailscale peers query
    const { data: tsPeersData, mutate: mutateTsPeers } = useSWR<{ peers: TailscalePeer[] }>(
        '/api/v1/admin/network/tailscale/peers',
        fetcher,
        { refreshInterval: 10000 }
    );

    // Add WireGuard Peer Modal State
    const [showAddWgModal, setShowAddWgModal] = useState(false);
    const [newPeerPubKey, setNewPeerPubKey] = useState('');
    const [newPeerAllowedIPs, setNewPeerAllowedIPs] = useState('10.0.0.2/32');
    const [newPeerEndpoint, setNewPeerEndpoint] = useState('');
    const [generatedPrivKey, setGeneratedPrivKey] = useState('');
    const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
    const [isSubmittingPeer, setIsSubmittingPeer] = useState(false);

    // Tailscale Routes State
    const [subnetRouteInput, setSubnetRouteInput] = useState('192.168.1.0/24');
    const [isAdvertisingRoutes, setIsAdvertisingRoutes] = useState(false);

    const handleKeygen = async () => {
        setIsGeneratingKeys(true);
        try {
            const res = await apiFetch('/api/v1/admin/network/wireguard/keygen', { method: 'POST' });
            if (!res.ok) throw new Error('Keygen failed');
            const data = await res.json();
            setNewPeerPubKey(data.public_key || '');
            setGeneratedPrivKey(data.private_key || '');
            addToast('WireGuard keypair generated.', 'success');
        } catch {
            addToast('Failed to generate keypair.', 'error');
        } finally {
            setIsGeneratingKeys(false);
        }
    };

    const handleAddWgPeer = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsSubmittingPeer(true);
        try {
            const res = await apiFetch('/api/v1/admin/network/wireguard/peers', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    public_key: newPeerPubKey,
                    allowed_ips: newPeerAllowedIPs,
                    endpoint: newPeerEndpoint || undefined
                })
            });
            const data = await res.json();
            if (res.ok) {
                addToast('WireGuard peer added successfully.', 'success');
                setShowAddWgModal(false);
                setNewPeerPubKey('');
                setNewPeerAllowedIPs('10.0.0.2/32');
                setNewPeerEndpoint('');
                setGeneratedPrivKey('');
                mutateWgPeers();
                mutateStatus();
            } else {
                addToast(data.error || 'Failed to add WireGuard peer.', 'error');
            }
        } catch {
            addToast('Network error adding peer.', 'error');
        } finally {
            setIsSubmittingPeer(false);
        }
    };

    const handleRemoveWgPeer = async (key: string) => {
        if (!confirm('Remove WireGuard peer?')) return;
        try {
            const res = await apiFetch(`/api/v1/admin/network/wireguard/peers/${encodeURIComponent(key)}`, {
                method: 'DELETE'
            });
            if (res.ok) {
                addToast('Peer removed.', 'success');
                mutateWgPeers();
                mutateStatus();
            } else {
                const data = await res.json().catch(() => ({}));
                addToast(data.error || 'Failed to remove peer.', 'error');
            }
        } catch {
            addToast('Network error removing peer.', 'error');
        }
    };

    const handleAdvertiseRoutes = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!subnetRouteInput.trim()) return;
        setIsAdvertisingRoutes(true);
        try {
            const routes = subnetRouteInput.split(',').map(r => r.trim()).filter(Boolean);
            const res = await apiFetch('/api/v1/admin/network/tailscale/routes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ routes })
            });
            const data = await res.json();
            if (res.ok) {
                addToast('Subnet routes advertised successfully.', 'success');
                mutateStatus();
                mutateTsPeers();
            } else {
                addToast(data.error || 'Failed to advertise routes.', 'error');
            }
        } catch {
            addToast('Network error advertising routes.', 'error');
        } finally {
            setIsAdvertisingRoutes(false);
        }
    };

    const wgPeers = wgPeersData?.peers || networkStatus?.wireguard?.peers || [];
    const tsPeers = tsPeersData?.peers || networkStatus?.tailscale?.peers || [];
    const tsStatus = networkStatus?.tailscale;
    const activeWgPeers = wgPeers.filter(p => p.latest_handshake && p.latest_handshake !== 'Never').length;
    const onlineTsPeers = tsPeers.filter(p => p.online).length;

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-w-0">
            {/* Open Top Toolbar with Integrated View Switcher */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-2 border-b border-white/[0.06] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400">
                        {activeSection === 'wireguard' ? <Shield size={20} /> : <Radio size={20} />}
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">Network &amp; VPN Mesh</h2>
                            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                {activeSection === 'wireguard' ? 'WireGuard Kernel' : 'Tailscale Mesh'}
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5">
                                <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${networkStatus?.wireguard_available ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
                                <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${networkStatus?.wireguard_available ? 'bg-emerald-500' : 'bg-amber-500'}`}></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide">
                                Mesh Health · {wgPeers.length} WireGuard Peers / {tsPeers.length} Tailnet Devices
                            </span>
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    {/* View Switcher */}
                    <div className="flex items-center gap-1 p-1 bg-white/[0.04] border border-white/10 rounded-xl">
                        <button
                            type="button"
                            onClick={() => setActiveSection('wireguard')}
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                                activeSection === 'wireguard'
                                    ? 'bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 shadow-md shadow-indigo-500/10'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <Shield size={13} />
                            WireGuard VPN
                        </button>
                        <button
                            type="button"
                            onClick={() => setActiveSection('tailscale')}
                            className={`obs-touch-target-standard obs-gpu-120hz-interactive px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center gap-1.5 ${
                                activeSection === 'tailscale'
                                    ? 'bg-violet-500/20 border border-violet-500/30 text-violet-300 shadow-md shadow-violet-500/10'
                                    : 'text-slate-400 hover:text-white'
                            }`}
                        >
                            <Radio size={13} />
                            Tailscale Mesh
                        </button>
                    </div>

                    {activeSection === 'wireguard' && (
                        <button
                            onClick={() => setShowAddWgModal(true)}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-all shadow-lg shadow-indigo-500/20"
                        >
                            <Plus size={13} />
                            <span>Add Peer</span>
                        </button>
                    )}

                    <button
                        onClick={() => { mutateStatus(); mutateWgPeers(); mutateTsPeers(); }}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                        title="Refresh Network"
                    >
                        <RefreshCw size={13} className={isValidatingStatus ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                        <span>Refresh</span>
                    </button>
                </div>
            </div>

            {/* Open 4-Card Telemetry Strip */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Tunnel Health</p>
                        <p className="text-base font-bold text-slate-100 mt-1">
                            {networkStatus?.wireguard_available ? 'wg0 Active' : 'Standby'}
                        </p>
                        <p className="text-[11px] text-slate-500 mt-0.5">
                            Port {networkStatus?.wireguard?.listen_port || '51820'} · Kernel Active
                        </p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                        <CheckCircle2 size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Active Peers</p>
                        <p className="text-2xl font-bold text-slate-100 mt-1">{wgPeers.length}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">
                            {activeWgPeers} connected handshakes
                        </p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                        <Shield size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Transfer Metrics</p>
                        <p className="text-base font-bold text-slate-100 mt-1">
                            {wgPeers.length > 0 ? `${wgPeers.length} Active` : '0 bps'}
                        </p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Encrypted WireGuard Pipeline</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                        <ArrowDownUp size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Tailnet Mesh Status</p>
                        <p className="text-base font-bold text-slate-100 mt-1">
                            {tsStatus?.backend_state || 'Standalone'}
                        </p>
                        <p className="text-[11px] text-slate-500 mt-0.5">
                            {onlineTsPeers} Online / {tsPeers.length} Mesh Devices
                        </p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center text-violet-400">
                        <Radio size={20} />
                    </div>
                </div>
            </div>

            {/* WireGuard View */}
            {activeSection === 'wireguard' && (
                <div className="space-y-6">
                    {/* Interface Status Card */}
                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5">
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
                            <div className="flex items-center gap-3">
                                <div className="h-9 w-9 bg-indigo-500/20 rounded-xl flex items-center justify-center border border-indigo-500/30 text-indigo-400">
                                    <Shield size={18} />
                                </div>
                                <div>
                                    <h3 className="text-sm font-bold text-slate-200">
                                        Interface: {networkStatus?.wireguard?.interface || 'wg0'}
                                    </h3>
                                    <p className="text-xs text-slate-400 font-mono mt-0.5">
                                        Port: {networkStatus?.wireguard?.listen_port || '51820'} &middot; {networkStatus?.wireguard_available ? 'Kernel Module Active' : 'Fallback / Userland'}
                                    </p>
                                </div>
                            </div>
                            <span className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase border flex items-center gap-1.5 self-start md:self-auto ${
                                networkStatus?.wireguard_available 
                                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                                    : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                            }`}>
                                <div className={`w-1.5 h-1.5 rounded-full ${networkStatus?.wireguard_available ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
                                {networkStatus?.wireguard_available ? 'Interface Running' : 'Standby / Offline'}
                            </span>
                        </div>

                        {networkStatus?.wireguard?.public_key && (
                            <div className="bg-black/40 rounded-xl p-3 border border-white/[0.06] font-mono text-xs flex items-center justify-between gap-4">
                                <span className="text-slate-500 shrink-0">Server Public Key:</span>
                                <span className="text-slate-300 truncate select-all">{networkStatus.wireguard.public_key}</span>
                            </div>
                        )}
                    </div>

                    {/* WireGuard Peers Table */}
                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5">
                        <div className="flex items-center justify-between mb-4 pb-3 border-b border-white/[0.06]">
                            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                                Registered Peers ({wgPeers.length})
                            </h4>
                            <button
                                onClick={() => { mutateWgPeers(); mutateStatus(); }}
                                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-white/5 transition-colors"
                                title="Refresh peers"
                            >
                                <RefreshCw size={14} />
                            </button>
                        </div>

                        <div className="overflow-x-auto">
                            <table className="w-full text-left border-collapse text-xs">
                                <thead>
                                    <tr className="border-b border-white/[0.06] text-slate-400 text-[11px] uppercase tracking-wider">
                                        <th className="py-2.5 px-3">Public Key</th>
                                        <th className="py-2.5 px-3">Allowed IPs</th>
                                        <th className="py-2.5 px-3">Endpoint</th>
                                        <th className="py-2.5 px-3">Latest Handshake</th>
                                        <th className="py-2.5 px-3">Transfer</th>
                                        <th className="py-2.5 px-3 text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/[0.04]">
                                    {wgPeers.length === 0 ? (
                                        <tr>
                                            <td colSpan={6} className="py-12 text-center text-slate-500">
                                                No WireGuard peers configured. Click &quot;Add Peer&quot; to register a client.
                                            </td>
                                        </tr>
                                    ) : (
                                        wgPeers.map((peer, idx) => (
                                            <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                                                <td className="py-3 px-3 font-mono text-indigo-300 truncate max-w-[180px]" title={peer.public_key}>
                                                    {peer.public_key.substring(0, 16)}...
                                                </td>
                                                <td className="py-3 px-3 font-mono text-slate-300">
                                                    {peer.allowed_ips || '-'}
                                                </td>
                                                <td className="py-3 px-3 font-mono text-slate-400">
                                                    {peer.endpoint || 'Roaming'}
                                                </td>
                                                <td className="py-3 px-3 text-slate-400">
                                                    {peer.latest_handshake || 'Never'}
                                                </td>
                                                <td className="py-3 px-3 text-slate-400 font-mono text-[11px]">
                                                    {peer.transfer_rx ? `↓ ${peer.transfer_rx} · ↑ ${peer.transfer_tx}` : '-'}
                                                </td>
                                                <td className="py-3 px-3 text-right">
                                                    <button
                                                        onClick={() => handleRemoveWgPeer(peer.public_key)}
                                                        className="p-1.5 text-slate-400 hover:text-red-400 rounded-lg hover:bg-red-500/10 transition-colors"
                                                        title="Remove peer"
                                                    >
                                                        <Trash2 size={14} />
                                                    </button>
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}

            {/* Tailscale View */}
            {activeSection === 'tailscale' && (
                <div className="space-y-6">
                    {/* Tailscale Status Card */}
                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5">
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
                            <div className="flex items-center gap-3">
                                <div className="h-9 w-9 bg-violet-500/20 rounded-xl flex items-center justify-center border border-violet-500/30 text-violet-400">
                                    <Radio size={18} />
                                </div>
                                <div>
                                    <h3 className="text-sm font-bold text-slate-200">
                                        Tailscale Node: {tsStatus?.self?.hostname || 'aetherflow-node'}
                                    </h3>
                                    <p className="text-xs text-slate-400 font-mono mt-0.5">
                                        IP: {tsStatus?.self?.tailscale_ip || 'Offline'} &middot; Backend: {tsStatus?.backend_state || 'Unknown'}
                                    </p>
                                </div>
                            </div>
                            <span className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase border flex items-center gap-1.5 self-start md:self-auto ${
                                tsStatus?.backend_state === 'Running'
                                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                                    : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                            }`}>
                                <div className={`w-1.5 h-1.5 rounded-full ${tsStatus?.backend_state === 'Running' ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
                                {tsStatus?.backend_state || 'Disconnected'}
                            </span>
                        </div>

                        {/* Subnet Route Form */}
                        <form onSubmit={handleAdvertiseRoutes} className="pt-4 border-t border-white/[0.06] flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                            <div className="flex-1">
                                <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1">
                                    Advertise Subnet Routes (comma-separated CIDRs)
                                </label>
                                <input
                                    type="text"
                                    value={subnetRouteInput}
                                    onChange={(e) => setSubnetRouteInput(e.target.value)}
                                    placeholder="10.0.0.0/24, 192.168.1.0/24"
                                    className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-violet-500/50"
                                />
                            </div>
                            <button
                                type="submit"
                                disabled={isAdvertisingRoutes || !subnetRouteInput.trim()}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive px-5 py-2 bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white text-xs font-bold rounded-xl transition-all self-end flex items-center gap-1.5 shrink-0"
                            >
                                <Send size={13} />
                                <span>{isAdvertisingRoutes ? 'Advertising...' : 'Advertise Routes'}</span>
                            </button>
                        </form>
                    </div>

                    {/* Tailscale Peers Table */}
                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5">
                        <div className="flex items-center justify-between mb-4 pb-3 border-b border-white/[0.06]">
                            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                                Tailnet Mesh Devices ({tsPeers.length})
                            </h4>
                            <button
                                onClick={() => { mutateTsPeers(); mutateStatus(); }}
                                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-white/5 transition-colors"
                                title="Refresh Tailscale peers"
                            >
                                <RefreshCw size={14} />
                            </button>
                        </div>

                        <div className="overflow-x-auto">
                            <table className="w-full text-left border-collapse text-xs">
                                <thead>
                                    <tr className="border-b border-white/[0.06] text-slate-400 text-[11px] uppercase tracking-wider">
                                        <th className="py-2.5 px-3">Device Hostname</th>
                                        <th className="py-2.5 px-3">Tailscale IP</th>
                                        <th className="py-2.5 px-3">OS</th>
                                        <th className="py-2.5 px-3">Status</th>
                                        <th className="py-2.5 px-3">Exit Node</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/[0.04]">
                                    {tsPeers.length === 0 ? (
                                        <tr>
                                            <td colSpan={5} className="py-12 text-center text-slate-500">
                                                No Tailscale mesh peers discovered or Tailscale daemon offline.
                                            </td>
                                        </tr>
                                    ) : (
                                        tsPeers.map((peer, idx) => (
                                            <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                                                <td className="py-3 px-3 font-semibold text-slate-200 flex items-center gap-2">
                                                    <Laptop size={14} className="text-slate-500" />
                                                    {peer.hostname}
                                                    {peer.dns_name && <span className="text-[10px] text-slate-500">({peer.dns_name})</span>}
                                                </td>
                                                <td className="py-3 px-3 font-mono text-violet-300">
                                                    {peer.tailscale_ip}
                                                </td>
                                                <td className="py-3 px-3 text-slate-400 capitalize">
                                                    {peer.os || 'Linux'}
                                                </td>
                                                <td className="py-3 px-3">
                                                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                                                        peer.online ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-800 text-slate-500'
                                                    }`}>
                                                        {peer.online ? 'Online' : 'Idle'}
                                                    </span>
                                                </td>
                                                <td className="py-3 px-3 text-slate-400">
                                                    {peer.exit_node ? <span className="text-emerald-400 font-bold">Yes</span> : 'No'}
                                                </td>
                                            </tr>
                                        ))
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}

            {/* Add WireGuard Peer Modal */}
            {showAddWgModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
                    <div className="rounded-2xl border border-white/[0.08] bg-slate-900/95 backdrop-blur-2xl w-full max-w-lg p-6 shadow-2xl relative">
                        <div className="flex items-center justify-between pb-4 border-b border-white/[0.06] mb-5">
                            <div className="flex items-center gap-2">
                                <KeyRound className="text-indigo-400" size={18} />
                                <h3 className="text-base font-bold text-white">Enroll WireGuard Peer</h3>
                            </div>
                            <button
                                onClick={() => setShowAddWgModal(false)}
                                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-white/5 transition-colors"
                            >
                                &times;
                            </button>
                        </div>

                        <form onSubmit={handleAddWgPeer} className="space-y-4">
                            <div className="flex items-center justify-between">
                                <label className="text-xs font-semibold text-slate-300">Client Public Key</label>
                                <button
                                    type="button"
                                    onClick={handleKeygen}
                                    disabled={isGeneratingKeys}
                                    className="text-[11px] text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-bold"
                                >
                                    <KeyRound size={12} />
                                    {isGeneratingKeys ? 'Generating...' : 'Generate Keypair'}
                                </button>
                            </div>

                            <input
                                type="text"
                                value={newPeerPubKey}
                                onChange={(e) => setNewPeerPubKey(e.target.value)}
                                placeholder="Base64 public key (44 characters)"
                                required
                                className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs font-mono focus:outline-none focus:border-indigo-500/50"
                            />

                            {generatedPrivKey && (
                                <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl space-y-1">
                                    <div className="text-[10px] font-bold text-amber-400 uppercase tracking-wider">
                                        Client Private Key (Save Now — Never Stored on Server)
                                    </div>
                                    <div className="text-xs font-mono text-slate-200 select-all break-all">
                                        {generatedPrivKey}
                                    </div>
                                </div>
                            )}

                            <div>
                                <label className="block text-xs font-semibold text-slate-300 mb-1">Allowed IPs</label>
                                <input
                                    type="text"
                                    value={newPeerAllowedIPs}
                                    onChange={(e) => setNewPeerAllowedIPs(e.target.value)}
                                    placeholder="10.0.0.2/32"
                                    required
                                    className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs font-mono focus:outline-none focus:border-indigo-500/50"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-semibold text-slate-300 mb-1">Optional Endpoint</label>
                                <input
                                    type="text"
                                    value={newPeerEndpoint}
                                    onChange={(e) => setNewPeerEndpoint(e.target.value)}
                                    placeholder="client.example.com:51820"
                                    className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs font-mono focus:outline-none focus:border-indigo-500/50"
                                />
                            </div>

                            <div className="flex justify-end gap-2.5 pt-4 border-t border-white/[0.06]">
                                <button
                                    type="button"
                                    onClick={() => setShowAddWgModal(false)}
                                    className="px-4 py-2 text-xs font-bold text-slate-400 hover:text-white rounded-xl transition-colors"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    disabled={isSubmittingPeer || !newPeerPubKey.trim()}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive px-5 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-xs font-bold text-white rounded-xl transition-all shadow-lg shadow-indigo-500/20"
                                >
                                    {isSubmittingPeer ? 'Adding Peer...' : 'Enroll Peer'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
