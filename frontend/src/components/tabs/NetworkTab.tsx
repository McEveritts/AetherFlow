'use client';

import React, { useState } from 'react';
import useSWR from 'swr';
import { Network, Shield, KeyRound, Plus, Trash2, RefreshCw, Send, CheckCircle2, AlertCircle, Laptop, Radio, Server, Globe } from 'lucide-react';
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
    const { data: networkStatus, mutate: mutateStatus } = useSWR<NetworkStatusResponse>(
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

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full max-w-7xl mx-auto pb-12">
            {/* Header & Segmented Switcher */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-white/5 pb-4">
                <div>
                    <h2 className="text-2xl font-black text-slate-100 flex items-center gap-3">
                        <Network size={28} className="text-indigo-400" />
                        Network & VPN Infrastructure
                    </h2>
                    <p className="text-xs text-slate-400 mt-1">
                        High-performance WireGuard tunnels and zero-config Tailscale mesh networking
                    </p>
                </div>

                <div className="flex items-center gap-1.5 p-1 bg-white/[0.04] border border-white/10 rounded-2xl backdrop-blur-xl">
                    <button
                        onClick={() => setActiveSection('wireguard')}
                        className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
                            activeSection === 'wireguard'
                                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/25'
                                : 'text-slate-400 hover:text-slate-200'
                        }`}
                    >
                        <Shield size={14} />
                        WireGuard VPN
                    </button>
                    <button
                        onClick={() => setActiveSection('tailscale')}
                        className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
                            activeSection === 'tailscale'
                                ? 'bg-violet-600 text-white shadow-lg shadow-violet-500/25'
                                : 'text-slate-400 hover:text-slate-200'
                        }`}
                    >
                        <Radio size={14} />
                        Tailscale Mesh
                    </button>
                </div>
            </div>

            {/* WireGuard Section */}
            {activeSection === 'wireguard' && (
                <div className="space-y-6">
                    {/* Interface Status Card */}
                    <div className="glass-card rounded-2xl p-6 relative overflow-hidden">
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                            <div className="flex items-center gap-3">
                                <div className="h-10 w-10 bg-indigo-500/20 rounded-xl flex items-center justify-center border border-indigo-500/30">
                                    <Shield size={20} className="text-indigo-400" />
                                </div>
                                <div>
                                    <h3 className="text-sm font-bold text-slate-200">
                                        Interface: {networkStatus?.wireguard?.interface || 'wg0'}
                                    </h3>
                                    <p className="text-xs text-slate-500 font-mono">
                                        Port: {networkStatus?.wireguard?.listen_port || '51820'} · {networkStatus?.wireguard_available ? 'Kernel Module Active' : 'Fallback / Userland'}
                                    </p>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                <span className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase border flex items-center gap-1.5 ${
                                    networkStatus?.wireguard_available 
                                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                                        : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                                }`}>
                                    <div className={`w-1.5 h-1.5 rounded-full ${networkStatus?.wireguard_available ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
                                    {networkStatus?.wireguard_available ? 'Interface Running' : 'Standby / Offline'}
                                </span>
                                <button
                                    onClick={() => setShowAddWgModal(true)}
                                    className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-xl transition-all shadow-lg shadow-indigo-500/20 flex items-center gap-1.5"
                                >
                                    <Plus size={14} /> Add Peer
                                </button>
                            </div>
                        </div>

                        {networkStatus?.wireguard?.public_key && (
                            <div className="bg-black/40 rounded-xl p-3 border border-white/5 font-mono text-xs flex items-center justify-between gap-4">
                                <span className="text-slate-500 shrink-0">Server Public Key:</span>
                                <span className="text-slate-300 truncate">{networkStatus.wireguard.public_key}</span>
                            </div>
                        )}
                    </div>

                    {/* Peers Table */}
                    <div className="glass-card rounded-2xl overflow-hidden">
                        <div className="p-4 border-b border-white/5 flex items-center justify-between">
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
                            <table className="w-full text-left border-collapse">
                                <thead>
                                    <tr className="bg-black/40 text-slate-400 text-[10px] uppercase tracking-wider border-b border-white/5">
                                        <th className="p-4">Public Key</th>
                                        <th className="p-4">Allowed IPs</th>
                                        <th className="p-4">Endpoint</th>
                                        <th className="p-4">Latest Handshake</th>
                                        <th className="p-4">Transfer</th>
                                        <th className="p-4 text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/5 text-xs">
                                    {wgPeers.length === 0 ? (
                                        <tr>
                                            <td colSpan={6} className="p-8 text-center text-slate-500">
                                                No WireGuard peers configured. Click &quot;Add Peer&quot; to register a client.
                                            </td>
                                        </tr>
                                    ) : (
                                        wgPeers.map((peer, idx) => (
                                            <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                                                <td className="p-4 font-mono text-indigo-300 truncate max-w-[180px]" title={peer.public_key}>
                                                    {peer.public_key.substring(0, 16)}...
                                                </td>
                                                <td className="p-4 font-mono text-slate-300">
                                                    {peer.allowed_ips || '-'}
                                                </td>
                                                <td className="p-4 font-mono text-slate-400">
                                                    {peer.endpoint || 'Roaming'}
                                                </td>
                                                <td className="p-4 text-slate-400">
                                                    {peer.latest_handshake || 'Never'}
                                                </td>
                                                <td className="p-4 text-slate-400 font-mono text-[11px]">
                                                    {peer.transfer_rx ? `↓ ${peer.transfer_rx} · ↑ ${peer.transfer_tx}` : '-'}
                                                </td>
                                                <td className="p-4 text-right">
                                                    <button
                                                        onClick={() => handleRemoveWgPeer(peer.public_key)}
                                                        className="p-1.5 text-slate-400 hover:text-red-400 rounded-lg hover:bg-white/5 transition-colors"
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

            {/* Tailscale Section */}
            {activeSection === 'tailscale' && (
                <div className="space-y-6">
                    {/* Tailscale Status Card */}
                    <div className="glass-card rounded-2xl p-6 relative overflow-hidden">
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
                            <div className="flex items-center gap-3">
                                <div className="h-10 w-10 bg-violet-500/20 rounded-xl flex items-center justify-center border border-violet-500/30">
                                    <Radio size={20} className="text-violet-400" />
                                </div>
                                <div>
                                    <h3 className="text-sm font-bold text-slate-200">
                                        Tailscale Node: {tsStatus?.self?.hostname || 'aetherflow-node'}
                                    </h3>
                                    <p className="text-xs text-slate-500 font-mono">
                                        IP: {tsStatus?.self?.tailscale_ip || 'Offline'} · Backend: {tsStatus?.backend_state || 'Unknown'}
                                    </p>
                                </div>
                            </div>
                            <span className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase border flex items-center gap-1.5 ${
                                tsStatus?.backend_state === 'Running'
                                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                                    : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                            }`}>
                                <div className={`w-1.5 h-1.5 rounded-full ${tsStatus?.backend_state === 'Running' ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
                                {tsStatus?.backend_state || 'Disconnected'}
                            </span>
                        </div>

                        {/* Subnet Route Form */}
                        <form onSubmit={handleAdvertiseRoutes} className="pt-4 border-t border-white/5 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
                            <div className="flex-1">
                                <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1">
                                    Advertise Subnet Routes (comma-separated CIDRs)
                                </label>
                                <input
                                    type="text"
                                    value={subnetRouteInput}
                                    onChange={(e) => setSubnetRouteInput(e.target.value)}
                                    placeholder="10.0.0.0/24, 192.168.1.0/24"
                                    className="w-full bg-black/60 border border-white/10 rounded-xl px-4 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-violet-500/50"
                                />
                            </div>
                            <button
                                type="submit"
                                disabled={isAdvertisingRoutes || !subnetRouteInput.trim()}
                                className="px-5 py-2 bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white text-xs font-bold rounded-xl transition-all self-end flex items-center gap-1.5 shrink-0"
                            >
                                <Send size={14} />
                                {isAdvertisingRoutes ? 'Advertising...' : 'Advertise Routes'}
                            </button>
                        </form>
                    </div>

                    {/* Tailscale Peers Table */}
                    <div className="glass-card rounded-2xl overflow-hidden">
                        <div className="p-4 border-b border-white/5 flex items-center justify-between">
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
                            <table className="w-full text-left border-collapse">
                                <thead>
                                    <tr className="bg-black/40 text-slate-400 text-[10px] uppercase tracking-wider border-b border-white/5">
                                        <th className="p-4">Device Hostname</th>
                                        <th className="p-4">Tailscale IP</th>
                                        <th className="p-4">OS</th>
                                        <th className="p-4">Status</th>
                                        <th className="p-4">Exit Node</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/5 text-xs">
                                    {tsPeers.length === 0 ? (
                                        <tr>
                                            <td colSpan={5} className="p-8 text-center text-slate-500">
                                                No Tailscale mesh peers discovered or Tailscale daemon offline.
                                            </td>
                                        </tr>
                                    ) : (
                                        tsPeers.map((peer, idx) => (
                                            <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                                                <td className="p-4 font-semibold text-slate-200 flex items-center gap-2">
                                                    <Laptop size={14} className="text-slate-500" />
                                                    {peer.hostname}
                                                    {peer.dns_name && <span className="text-[10px] text-slate-500">({peer.dns_name})</span>}
                                                </td>
                                                <td className="p-4 font-mono text-violet-300">
                                                    {peer.tailscale_ip}
                                                </td>
                                                <td className="p-4 text-slate-400 capitalize">
                                                    {peer.os || 'Linux'}
                                                </td>
                                                <td className="p-4">
                                                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                                                        peer.online ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-800 text-slate-500'
                                                    }`}>
                                                        {peer.online ? 'Online' : 'Idle'}
                                                    </span>
                                                </td>
                                                <td className="p-4 text-slate-400">
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
                    <div className="glass-panel w-full max-w-lg rounded-3xl p-6 border border-white/10 shadow-2xl relative">
                        <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-6">
                            <div className="flex items-center gap-2">
                                <KeyRound className="text-indigo-400" size={20} />
                                <h3 className="text-lg font-bold text-white">Enroll WireGuard Peer</h3>
                            </div>
                            <button
                                onClick={() => setShowAddWgModal(false)}
                                className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-white/5 transition-colors"
                            >
                                ✕
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
                                className="w-full bg-black/60 border border-white/10 rounded-xl px-4 py-2.5 text-slate-100 text-xs font-mono focus:outline-none focus:border-indigo-500/50"
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
                                <label className="block text-xs font-semibold text-slate-300 mb-1.5">Allowed IPs</label>
                                <input
                                    type="text"
                                    value={newPeerAllowedIPs}
                                    onChange={(e) => setNewPeerAllowedIPs(e.target.value)}
                                    placeholder="10.0.0.2/32"
                                    required
                                    className="w-full bg-black/60 border border-white/10 rounded-xl px-4 py-2.5 text-slate-100 text-xs font-mono focus:outline-none focus:border-indigo-500/50"
                                />
                            </div>

                            <div>
                                <label className="block text-xs font-semibold text-slate-300 mb-1.5">Optional Endpoint</label>
                                <input
                                    type="text"
                                    value={newPeerEndpoint}
                                    onChange={(e) => setNewPeerEndpoint(e.target.value)}
                                    placeholder="client.example.com:51820"
                                    className="w-full bg-black/60 border border-white/10 rounded-xl px-4 py-2.5 text-slate-100 text-xs font-mono focus:outline-none focus:border-indigo-500/50"
                                />
                            </div>

                            <div className="flex justify-end gap-3 pt-4 border-t border-white/10">
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
                                    className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-xs font-bold text-white rounded-xl transition-all shadow-lg shadow-indigo-500/20"
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
