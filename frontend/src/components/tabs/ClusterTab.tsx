'use client';

import React, { useState } from 'react';
import useSWR from 'swr';
import {
    Boxes,
    Server,
    Cpu,
    Activity,
    Plus,
    Trash2,
    RefreshCw,
    CheckCircle2,
    AlertCircle,
    XCircle,
    Copy,
    Check,
    X,
    Zap,
    Network
} from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';
import { useToast } from '@/contexts/ToastContext';

export interface WorkerService {
    name: string;
    status: string;
    uptime: string;
    managed_by: string;
}

export interface WorkerMetrics {
    cpu_usage: number;
    mem_used_gb: number;
    mem_total_gb: number;
    disk_used_gb: number;
    disk_total_gb: number;
    net_rx_speed: string;
    net_tx_speed: string;
    uptime: string;
    load_average: number[];
}

export interface WorkerSystemInfo {
    os: string;
    arch: string;
    cpu_cores: number;
    total_memory_bytes: number;
    total_disk_bytes: number;
}

export interface WorkerNode {
    id: string;
    hostname: string;
    address: string;
    role: string;
    status: 'online' | 'offline' | 'degraded';
    version: string;
    last_heartbeat: string;
    enrolled_at: string;
    metrics?: WorkerMetrics;
    services?: WorkerService[];
    system_info?: WorkerSystemInfo;
}

export interface ClusterStatus {
    total_nodes?: number;
    online_nodes?: number;
    degraded_nodes?: number;
    offline_nodes?: number;
    healthy?: boolean;
}

interface ClusterApiResponse {
    nodes: WorkerNode[];
    summary: ClusterStatus | Record<string, unknown>;
}

const fetcher = (url: string) => apiFetch(url).then(res => res.json());

export default function ClusterTab() {
    const { addToast } = useToast();

    // SWR Cluster Nodes Fetching
    const {
        data: clusterData,
        isLoading: clusterLoading,
        isValidating: clusterValidating,
        mutate: mutateCluster
    } = useSWR<ClusterApiResponse>('/api/v1/admin/cluster/nodes', fetcher, {
        refreshInterval: 10000,
    });

    const nodes = clusterData?.nodes || [];

    // Enrollment Modal State
    const [showEnrollModal, setShowEnrollModal] = useState(false);
    const [enrollmentToken, setEnrollmentToken] = useState('');
    const [enrollInstructions, setEnrollInstructions] = useState('');
    const [isEnrolling, setIsEnrolling] = useState(false);
    const [copiedToken, setCopiedToken] = useState(false);
    const [copiedCmd, setCopiedCmd] = useState(false);

    // Node Telemetry Modal State
    const [selectedNode, setSelectedNode] = useState<WorkerNode | null>(null);

    // Decommissioning node state
    const [decommissioningNodeId, setDecommissioningNodeId] = useState<string | null>(null);

    const handleGenerateEnrollment = async () => {
        setIsEnrolling(true);
        try {
            const res = await apiFetch('/api/v1/admin/cluster/enroll', { method: 'POST' });
            if (!res.ok) throw new Error('Enrollment request failed');
            const data = await res.json();
            setEnrollmentToken(data.enrollment_token || '');
            setEnrollInstructions(data.instructions || '');
            setShowEnrollModal(true);
        } catch {
            addToast('Failed to generate cluster enrollment credentials.', 'error');
        } finally {
            setIsEnrolling(false);
        }
    };

    const handleCopy = (text: string, type: 'token' | 'cmd') => {
        navigator.clipboard.writeText(text);
        if (type === 'token') {
            setCopiedToken(true);
            setTimeout(() => setCopiedToken(false), 2000);
        } else {
            setCopiedCmd(true);
            setTimeout(() => setCopiedCmd(false), 2000);
        }
        addToast('Copied to clipboard!', 'success');
    };

    const handleInspectNode = async (node: WorkerNode) => {
        setSelectedNode(node);
        try {
            const res = await apiFetch(`/api/v1/admin/cluster/nodes/${node.id}/metrics`);
            if (res.ok) {
                const detailed = await res.json();
                setSelectedNode(prev => (prev ? { ...prev, ...detailed } : detailed));
            }
        } catch {
            // Keep existing node state if detailed fetch fails
        }
    };

    const handleRemoveNode = async (nodeId: string, hostname: string) => {
        if (!confirm(`Are you sure you want to decommission worker node "${hostname}" (${nodeId})?`)) return;

        setDecommissioningNodeId(nodeId);
        try {
            const res = await apiFetch(`/api/v1/admin/cluster/nodes/${nodeId}`, { method: 'DELETE' });
            if (!res.ok) throw new Error('Decommission failed');
            addToast(`Worker node ${hostname} decommissioned successfully.`, 'success');
            mutateCluster();
            if (selectedNode?.id === nodeId) {
                setSelectedNode(null);
            }
        } catch {
            addToast(`Failed to remove worker node ${hostname}.`, 'error');
        } finally {
            setDecommissioningNodeId(null);
        }
    };

    const onlineNodesCount = nodes.filter(n => n.status === 'online').length;
    const degradedNodesCount = nodes.filter(n => n.status === 'degraded').length;
    const offlineNodesCount = nodes.filter(n => n.status === 'offline').length;

    const renderNodeStatusBadge = (status: string) => {
        switch (status) {
            case 'online':
                return (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Online
                    </span>
                );
            case 'degraded':
                return (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-400" /> Degraded
                    </span>
                );
            default:
                return (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-400" /> Offline
                    </span>
                );
        }
    };

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-w-0">
            {/* Open Top Toolbar */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-2 border-b border-white/[0.06] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400">
                        <Boxes size={20} />
                    </div>
                    <div>
                        <div className="flex items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">Cluster Fleet &amp; Topology</h2>
                            <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                {nodes.length > 1 ? 'Distributed Mesh' : 'Single-Node Master'}
                            </span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                            <span className="relative flex h-1.5 w-1.5">
                                <span className="absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400"></span>
                                <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
                            </span>
                            <span className="text-xs text-slate-400 font-medium tracking-wide">
                                gRPC Coordinator &middot; {onlineNodesCount} online / {nodes.length} registered nodes
                            </span>
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    <button
                        type="button"
                        disabled={isEnrolling}
                        onClick={handleGenerateEnrollment}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-all shadow-lg shadow-indigo-500/20 disabled:opacity-50"
                    >
                        {isEnrolling ? (
                            <>
                                <RefreshCw size={13} className="animate-spin" />
                                <span>Generating...</span>
                            </>
                        ) : (
                            <>
                                <Plus size={13} />
                                <span>Enroll Worker Node</span>
                            </>
                        )}
                    </button>
                    <button
                        type="button"
                        onClick={() => mutateCluster()}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                        title="Refresh Topology"
                    >
                        <RefreshCw size={13} className={clusterValidating ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                        <span>Refresh</span>
                    </button>
                </div>
            </div>

            {/* Open 4-Card Telemetry Summary Strip */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Total Fleet Nodes</p>
                        <p className="text-2xl font-bold text-slate-100 mt-1">{nodes.length}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Enrolled instances</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
                        <Boxes size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Active Workers</p>
                        <p className="text-2xl font-bold text-emerald-400 mt-1">{onlineNodesCount}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Healthy gRPC heartbeats</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                        <CheckCircle2 size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Degraded / Stale</p>
                        <p className="text-2xl font-bold text-amber-400 mt-1">{degradedNodesCount}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Late heartbeat sync</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                        <AlertCircle size={20} />
                    </div>
                </div>

                <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-4 flex items-center justify-between">
                    <div>
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Offline Nodes</p>
                        <p className="text-2xl font-bold text-rose-400 mt-1">{offlineNodesCount}</p>
                        <p className="text-[11px] text-slate-500 mt-0.5">Decommissioned / Down</p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
                        <XCircle size={20} />
                    </div>
                </div>
            </div>

            {/* Topology Overview & Nodes Grid */}
            <div className="space-y-4">
                <div className="flex items-center justify-between px-1">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                        Registered Cluster Nodes ({nodes.length})
                    </h3>
                </div>

                {clusterLoading && nodes.length === 0 ? (
                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-12 text-center text-slate-400 text-xs flex items-center justify-center gap-2.5">
                        <RefreshCw size={16} className="animate-spin text-indigo-400" />
                        <span>Querying cluster daemon topology...</span>
                    </div>
                ) : nodes.length === 0 ? (
                    <div className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-10 text-center space-y-3">
                        <div className="w-12 h-12 rounded-2xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 mx-auto">
                            <Boxes size={24} />
                        </div>
                        <h4 className="text-sm font-bold text-slate-200">Single-Node Master Topology</h4>
                        <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
                            No remote worker nodes currently registered in this cluster topology. Click &quot;Enroll Worker Node&quot; to join secondary seedboxes to this master instance.
                        </p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {nodes.map((node) => {
                            const cpu = node.metrics?.cpu_usage ?? 0;
                            const memUsed = node.metrics?.mem_used_gb ?? 0;
                            const memTotal = node.metrics?.mem_total_gb ?? 1;
                            const memPct = memTotal > 0 ? (memUsed / memTotal) * 100 : 0;

                            return (
                                <div
                                    key={node.id}
                                    className="rounded-2xl border border-white/[0.06] bg-slate-900/40 backdrop-blur-xl p-5 hover:border-white/10 transition-all flex flex-col justify-between gap-4 group"
                                >
                                    <div className="space-y-3">
                                        <div className="flex items-start justify-between gap-2">
                                            <div className="flex items-center gap-3">
                                                <div className="w-9 h-9 rounded-xl bg-white/[0.04] border border-white/[0.06] flex items-center justify-center text-indigo-400 shrink-0">
                                                    <Server size={17} />
                                                </div>
                                                <div>
                                                    <h4 className="font-bold text-xs text-slate-100 group-hover:text-indigo-200 transition-colors">
                                                        {node.hostname || node.id}
                                                    </h4>
                                                    <span className="text-[11px] text-slate-500 font-mono">
                                                        {node.address || '127.0.0.1:50051'}
                                                    </span>
                                                </div>
                                            </div>

                                            {renderNodeStatusBadge(node.status)}
                                        </div>

                                        {/* Telemetry Spark Bars */}
                                        <div className="space-y-2 pt-2 border-t border-white/[0.06] font-mono text-xs">
                                            <div>
                                                <div className="flex items-center justify-between text-[11px] mb-1">
                                                    <span className="text-slate-400 flex items-center gap-1">
                                                        <Cpu size={12} className="text-indigo-400" /> CPU Load
                                                    </span>
                                                    <span className="text-slate-200 font-bold">{cpu.toFixed(1)}%</span>
                                                </div>
                                                <div className="w-full h-1.5 rounded-full bg-white/5 overflow-hidden">
                                                    <div
                                                        className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-cyan-400"
                                                        style={{ width: `${Math.min(100, Math.max(0, cpu))}%` }}
                                                    />
                                                </div>
                                            </div>

                                            <div>
                                                <div className="flex items-center justify-between text-[11px] mb-1">
                                                    <span className="text-slate-400 flex items-center gap-1">
                                                        <Activity size={12} className="text-cyan-400" /> Memory
                                                    </span>
                                                    <span className="text-slate-200 font-bold">
                                                        {memUsed.toFixed(1)} / {memTotal.toFixed(1)} GB
                                                    </span>
                                                </div>
                                                <div className="w-full h-1.5 rounded-full bg-white/5 overflow-hidden">
                                                    <div
                                                        className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-emerald-400"
                                                        style={{ width: `${Math.min(100, Math.max(0, memPct))}%` }}
                                                    />
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Card Footer Actions */}
                                    <div className="flex items-center justify-between pt-3 border-t border-white/[0.06]">
                                        <button
                                            type="button"
                                            onClick={() => handleInspectNode(node)}
                                            className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] hover:bg-white/[0.08] text-slate-200 hover:text-white border border-white/10 flex items-center gap-1.5 transition-all"
                                        >
                                            <Zap size={12} className="text-indigo-400" /> Telemetry &amp; Services
                                        </button>

                                        <button
                                            type="button"
                                            disabled={decommissioningNodeId === node.id}
                                            onClick={() => handleRemoveNode(node.id, node.hostname)}
                                            className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                                            title="Decommission Node"
                                        >
                                            <Trash2 size={14} />
                                        </button>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            {/* MODAL: ENROLL WORKER NODE */}
            {showEnrollModal && (
                <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
                    <div className="rounded-2xl border border-white/[0.08] bg-slate-900/95 backdrop-blur-2xl w-full max-w-lg p-6 shadow-2xl relative animate-fade-in space-y-4">
                        <div className="flex items-center justify-between pb-3.5 border-b border-white/[0.06]">
                            <h3 className="text-sm font-bold text-white flex items-center gap-2">
                                <Plus size={16} className="text-indigo-400" /> Enroll Worker Node
                            </h3>
                            <button
                                onClick={() => setShowEnrollModal(false)}
                                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
                            >
                                <X size={16} />
                            </button>
                        </div>

                        <div className="space-y-3.5">
                            <div>
                                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                                    Pre-Shared Enrollment Key (PSK)
                                </label>
                                <div className="flex items-center gap-2">
                                    <input
                                        type="text"
                                        readOnly
                                        value={enrollmentToken}
                                        className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-3 py-2 text-xs text-indigo-300 font-mono focus:outline-none"
                                    />
                                    <button
                                        type="button"
                                        onClick={() => handleCopy(enrollmentToken, 'token')}
                                        className="p-2 bg-white/[0.05] hover:bg-white/[0.1] rounded-xl text-slate-300 hover:text-white transition-all shrink-0"
                                        title="Copy PSK"
                                    >
                                        {copiedToken ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                                    </button>
                                </div>
                            </div>

                            <div>
                                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block mb-1">
                                    Join Command (Run on Worker Seedbox)
                                </label>
                                <div className="relative bg-black/80 border border-white/[0.08] rounded-xl p-3 font-mono text-xs text-slate-200">
                                    <pre className="whitespace-pre-wrap break-all text-emerald-400 text-xs">
                                        {enrollInstructions || `aetherflow-api --cluster-mode=worker --master-addr=${typeof window !== 'undefined' ? window.location.hostname : '127.0.0.1'}:50051 --psk=${enrollmentToken}`}
                                    </pre>
                                    <button
                                        type="button"
                                        onClick={() =>
                                            handleCopy(
                                                enrollInstructions || `aetherflow-api --cluster-mode=worker --master-addr=${typeof window !== 'undefined' ? window.location.hostname : '127.0.0.1'}:50051 --psk=${enrollmentToken}`,
                                                'cmd'
                                            )
                                        }
                                        className="absolute top-2 right-2 p-1.5 bg-white/10 hover:bg-white/20 rounded-lg text-slate-300 hover:text-white transition-all"
                                        title="Copy Command"
                                    >
                                        {copiedCmd ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                                    </button>
                                </div>
                            </div>

                            <p className="text-[11px] text-slate-400 leading-relaxed">
                                Once started, the worker connects via mTLS gRPC on port 50051, registers its CPU, memory, and services, and begins heartbeating automatically.
                            </p>
                        </div>

                        <div className="flex items-center justify-end pt-3.5 border-t border-white/[0.06]">
                            <button
                                type="button"
                                onClick={() => {
                                    setShowEnrollModal(false);
                                    mutateCluster();
                                }}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive px-5 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-xl text-xs font-bold text-white transition-all shadow-lg shadow-indigo-500/20"
                            >
                                Done
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* MODAL / DRAWER: NODE TELEMETRY INSPECTOR */}
            {selectedNode && (
                <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
                    <div className="rounded-2xl border border-white/[0.08] bg-slate-900/95 backdrop-blur-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto p-6 shadow-2xl relative animate-fade-in space-y-5">
                        <div className="flex items-center justify-between pb-3.5 border-b border-white/[0.06]">
                            <div className="flex items-center gap-3">
                                <div className="w-9 h-9 rounded-xl bg-white/[0.04] border border-white/[0.06] flex items-center justify-center text-indigo-400">
                                    <Server size={18} />
                                </div>
                                <div>
                                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                                        {selectedNode.hostname || selectedNode.id}
                                    </h3>
                                    <span className="text-[11px] font-mono text-slate-400">
                                        ID: {selectedNode.id} &middot; {selectedNode.address}
                                    </span>
                                </div>
                            </div>

                            <button
                                onClick={() => setSelectedNode(null)}
                                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/10 transition-colors"
                            >
                                <X size={16} />
                            </button>
                        </div>

                        {/* System Specs */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                            <div className="bg-black/40 border border-white/[0.06] rounded-xl p-3">
                                <span className="text-[10px] text-slate-400 uppercase font-mono block">OS / Arch</span>
                                <span className="text-xs font-bold text-white mt-0.5 block truncate">
                                    {selectedNode.system_info?.os || 'Linux'} ({selectedNode.system_info?.arch || 'amd64'})
                                </span>
                            </div>
                            <div className="bg-black/40 border border-white/[0.06] rounded-xl p-3">
                                <span className="text-[10px] text-slate-400 uppercase font-mono block">CPU Cores</span>
                                <span className="text-xs font-bold text-indigo-300 mt-0.5 block">
                                    {selectedNode.system_info?.cpu_cores || 'Multi-core'}
                                </span>
                            </div>
                            <div className="bg-black/40 border border-white/[0.06] rounded-xl p-3">
                                <span className="text-[10px] text-slate-400 uppercase font-mono block">Network RX/TX</span>
                                <span className="text-xs font-bold text-cyan-300 mt-0.5 block truncate">
                                    &darr; {selectedNode.metrics?.net_rx_speed || '0 B/s'} / &uarr; {selectedNode.metrics?.net_tx_speed || '0 B/s'}
                                </span>
                            </div>
                            <div className="bg-black/40 border border-white/[0.06] rounded-xl p-3">
                                <span className="text-[10px] text-slate-400 uppercase font-mono block">Uptime</span>
                                <span className="text-xs font-bold text-emerald-400 mt-0.5 block truncate">
                                    {selectedNode.metrics?.uptime || 'Online'}
                                </span>
                            </div>
                        </div>

                        {/* Running Services on Worker */}
                        <div className="space-y-2.5">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                                Supervised Services on Worker
                            </h4>
                            <div className="rounded-xl border border-white/[0.06] bg-black/40 divide-y divide-white/[0.04] overflow-hidden">
                                {(!selectedNode.services || selectedNode.services.length === 0) ? (
                                    <div className="p-4 text-center text-xs text-slate-500">
                                        No isolated daemon services reported on this worker.
                                    </div>
                                ) : (
                                    selectedNode.services.map((svc, idx) => (
                                        <div key={idx} className="p-2.5 flex items-center justify-between text-xs font-mono">
                                            <div className="flex items-center gap-2">
                                                <div className={`w-1.5 h-1.5 rounded-full ${svc.status === 'running' ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
                                                <span className="font-bold text-white">{svc.name}</span>
                                                <span className="text-slate-500 text-[10px]">({svc.managed_by})</span>
                                            </div>
                                            <span className="text-slate-400">{svc.uptime || 'Active'}</span>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>

                        {/* Decommission Action */}
                        <div className="pt-3.5 border-t border-white/[0.06] flex items-center justify-between">
                            <span className="text-xs text-slate-500 font-mono">
                                Last Heartbeat: {selectedNode.last_heartbeat ? new Date(selectedNode.last_heartbeat).toLocaleTimeString() : 'Recent'}
                            </span>
                            <button
                                type="button"
                                disabled={decommissioningNodeId === selectedNode.id}
                                onClick={() => handleRemoveNode(selectedNode.id, selectedNode.hostname)}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive px-4 py-2 rounded-xl text-xs font-bold text-rose-400 hover:text-white bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 flex items-center gap-1.5 transition-all"
                            >
                                <Trash2 size={13} /> Decommission Node
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
