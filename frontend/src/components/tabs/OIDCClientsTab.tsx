'use client';

import { useState } from 'react';
import useSWR from 'swr';
import { apiFetch } from '@/lib/fetcher';
import { useToast } from '@/contexts/ToastContext';
import { Modal } from '@/components/ui/Modal';
import { Key, Plus, Trash2, Copy, Check, AlertTriangle, Shield } from 'lucide-react';

interface OIDCClient {
    id: string;
    name: string;
    redirect_uris: string;
    created_at: string;
}

interface NewClientResponse {
    client_id: string;
    client_secret: string;
    name: string;
    redirect_uris: string[];
}

export default function OIDCClientsTab() {
    const { data, isLoading, error, mutate } = useSWR<OIDCClient[]>('/api/v1/admin/oidc/clients');
    const { addToast } = useToast();

    const [showCreate, setShowCreate] = useState(false);
    const [showSecret, setShowSecret] = useState<NewClientResponse | null>(null);
    const [deleteTarget, setDeleteTarget] = useState<OIDCClient | null>(null);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [copiedField, setCopiedField] = useState<string | null>(null);

    // Create form state
    const [newName, setNewName] = useState('');
    const [newRedirectURIs, setNewRedirectURIs] = useState('');

    const handleCopy = async (text: string, field: string) => {
        await navigator.clipboard.writeText(text);
        setCopiedField(field);
        setTimeout(() => setCopiedField(null), 2000);
    };

    const handleCreate = async () => {
        if (!newName.trim()) return;
        setIsSubmitting(true);
        try {
            const uris = newRedirectURIs.split('\n').map(u => u.trim()).filter(Boolean);
            const res = await apiFetch('/api/v1/admin/oidc/clients', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: newName.trim(), redirect_uris: uris }),
            });
            if (!res.ok) {
                const err = await res.json();
                addToast(err.message || 'Failed to create client', 'error');
                return;
            }
            const result: NewClientResponse = await res.json();
            setShowCreate(false);
            setNewName('');
            setNewRedirectURIs('');
            setShowSecret(result);
            mutate();
            addToast(`OIDC client "${result.name}" created`, 'success');
        } catch (e) {
            addToast('Failed to create OIDC client', 'error');
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleDelete = async () => {
        if (!deleteTarget) return;
        setIsSubmitting(true);
        try {
            const res = await apiFetch(`/api/v1/admin/oidc/clients/${deleteTarget.id}`, {
                method: 'DELETE',
            });
            if (!res.ok) {
                addToast('Failed to delete OIDC client', 'error');
                return;
            }
            mutate();
            addToast(`Client "${deleteTarget.name}" deleted`, 'success');
            setDeleteTarget(null);
        } catch {
            addToast('Failed to delete OIDC client', 'error');
        } finally {
            setIsSubmitting(false);
        }
    };

    function parseRedirectURIs(json: string): string[] {
        try { return JSON.parse(json); } catch { return []; }
    }

    const clients = Array.isArray(data) ? data : [];

    // Loading
    if (isLoading && !data) {
        return (
            <div className="space-y-4">
                <h2 className="text-2xl font-bold text-slate-100 tracking-tight">OIDC Clients</h2>
                <div className="glass-card p-8 rounded-2xl border border-white/[0.08]">
                    <div className="flex items-center justify-center gap-3 text-slate-400">
                        <div className="w-5 h-5 border-2 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin"></div>
                        <span>Loading clients...</span>
                    </div>
                </div>
            </div>
        );
    }

    // Error
    if (error) {
        return (
            <div className="space-y-4">
                <h2 className="text-2xl font-bold text-slate-100 tracking-tight">OIDC Clients</h2>
                <div className="glass-card p-8 rounded-2xl border border-red-500/20 bg-red-500/5 text-center">
                    <Shield className="w-10 h-10 text-red-400 mx-auto mb-3" />
                    <p className="text-red-400 font-medium">Failed to load OIDC clients</p>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-slate-100 tracking-tight">OIDC Clients</h2>
                    <p className="text-sm text-slate-400 mt-1">
                        Manage OAuth2/OIDC client applications registered with AetherFlow as an identity provider.
                    </p>
                </div>
                <button
                    onClick={() => setShowCreate(true)}
                    className="flex items-center gap-2 px-4 py-2.5 bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 rounded-xl text-sm font-medium border border-indigo-500/20 transition-all hover:shadow-[0_0_12px_rgba(99,102,241,0.15)]"
                >
                    <Plus size={16} />
                    New Client
                </button>
            </div>

            {/* Client List */}
            {clients.length === 0 ? (
                <div className="glass-card p-12 rounded-2xl border border-white/[0.08] text-center">
                    <Key className="w-10 h-10 text-slate-600 mx-auto mb-3" />
                    <p className="text-sm text-slate-400">No OIDC clients registered.</p>
                    <p className="text-xs text-slate-500 mt-1">Create one to enable third-party auth integration.</p>
                </div>
            ) : (
                <div className="grid gap-4">
                    {clients.map((client) => {
                        const uris = parseRedirectURIs(client.redirect_uris);
                        return (
                            <div key={client.id} className="glass-card rounded-2xl border border-white/[0.08] p-5 hover:border-white/[0.12] transition-all group">
                                <div className="flex items-start justify-between">
                                    <div className="flex items-center gap-3">
                                        <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center">
                                            <Key size={18} className="text-indigo-400" />
                                        </div>
                                        <div>
                                            <h3 className="text-base font-semibold text-slate-100">{client.name}</h3>
                                            <div className="flex items-center gap-2 mt-0.5">
                                                <code className="text-xs text-slate-400 font-mono bg-white/[0.03] px-1.5 py-0.5 rounded">{client.id}</code>
                                                <button
                                                    onClick={() => handleCopy(client.id, `id-${client.id}`)}
                                                    className="text-slate-500 hover:text-slate-300 transition-colors"
                                                >
                                                    {copiedField === `id-${client.id}` ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                    <button
                                        onClick={() => setDeleteTarget(client)}
                                        className="opacity-0 group-hover:opacity-100 p-2 rounded-lg hover:bg-red-500/10 text-slate-500 hover:text-red-400 transition-all"
                                    >
                                        <Trash2 size={16} />
                                    </button>
                                </div>

                                {/* Redirect URIs */}
                                {uris.length > 0 && (
                                    <div className="mt-3 pt-3 border-t border-white/[0.04]">
                                        <p className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-1.5">Redirect URIs</p>
                                        <div className="flex flex-wrap gap-1.5">
                                            {uris.map((uri, i) => (
                                                <span key={i} className="text-xs font-mono text-slate-400 bg-white/[0.03] px-2 py-1 rounded-lg border border-white/[0.06]">
                                                    {uri}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                <div className="mt-2 text-xs text-slate-500">
                                    Created: {new Date(client.created_at).toLocaleDateString()}
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}

            {/* Create Modal */}
            {showCreate && (
                <Modal isOpen={true} title="Create OIDC Client" onClose={() => setShowCreate(false)}>
                    <div className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-slate-300 mb-1.5">Client Name</label>
                            <input
                                type="text"
                                value={newName}
                                onChange={(e) => setNewName(e.target.value)}
                                placeholder="My Application"
                                className="w-full px-4 py-2.5 bg-white/[0.03] border border-white/[0.08] rounded-xl text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/20 transition-all"
                                autoFocus
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-300 mb-1.5">Redirect URIs</label>
                            <textarea
                                value={newRedirectURIs}
                                onChange={(e) => setNewRedirectURIs(e.target.value)}
                                placeholder="http://localhost:3000/callback&#10;https://app.example.com/auth/callback"
                                rows={3}
                                className="w-full px-4 py-2.5 bg-white/[0.03] border border-white/[0.08] rounded-xl text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/20 transition-all resize-none font-mono"
                            />
                            <p className="text-xs text-slate-500 mt-1">One URI per line.</p>
                        </div>
                        <div className="flex justify-end gap-3 pt-2">
                            <button
                                onClick={() => setShowCreate(false)}
                                className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleCreate}
                                disabled={!newName.trim() || isSubmitting}
                                className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                            >
                                {isSubmitting ? 'Creating...' : 'Create Client'}
                            </button>
                        </div>
                    </div>
                </Modal>
            )}

            {/* Secret Reveal Modal */}
            {showSecret && (
                <Modal isOpen={true} title="Client Created Successfully" onClose={() => setShowSecret(null)}>
                    <div className="space-y-5">
                        <div className="flex items-start gap-3 p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl">
                            <AlertTriangle className="w-5 h-5 text-amber-400 mt-0.5 shrink-0" />
                            <p className="text-sm text-amber-300">
                                Copy the client secret now. It will <strong>not be shown again</strong>.
                            </p>
                        </div>

                        <div>
                            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">Client ID</label>
                            <div className="flex items-center gap-2">
                                <code className="flex-1 text-sm font-mono text-slate-200 bg-white/[0.03] px-3 py-2 rounded-lg border border-white/[0.08] break-all">
                                    {showSecret.client_id}
                                </code>
                                <button onClick={() => handleCopy(showSecret.client_id, 'new-id')} className="p-2 rounded-lg hover:bg-white/[0.05] transition-colors">
                                    {copiedField === 'new-id' ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} className="text-slate-400" />}
                                </button>
                            </div>
                        </div>

                        <div>
                            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">Client Secret</label>
                            <div className="flex items-center gap-2">
                                <code className="flex-1 text-sm font-mono text-emerald-300 bg-emerald-500/5 px-3 py-2 rounded-lg border border-emerald-500/20 break-all">
                                    {showSecret.client_secret}
                                </code>
                                <button onClick={() => handleCopy(showSecret.client_secret, 'new-secret')} className="p-2 rounded-lg hover:bg-white/[0.05] transition-colors">
                                    {copiedField === 'new-secret' ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} className="text-slate-400" />}
                                </button>
                            </div>
                        </div>

                        <button
                            onClick={() => setShowSecret(null)}
                            className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-sm font-medium transition-all"
                        >
                            Done
                        </button>
                    </div>
                </Modal>
            )}

            {/* Delete Confirmation Modal */}
            {deleteTarget && (
                <Modal isOpen={true} title="Delete OIDC Client" onClose={() => setDeleteTarget(null)}>
                    <div className="space-y-4">
                        <p className="text-sm text-slate-300">
                            Are you sure you want to delete <strong className="text-slate-100">{deleteTarget.name}</strong>?
                            All applications using this client will lose access immediately.
                        </p>
                        <div className="flex justify-end gap-3">
                            <button
                                onClick={() => setDeleteTarget(null)}
                                className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleDelete}
                                disabled={isSubmitting}
                                className="px-5 py-2.5 bg-red-600 hover:bg-red-500 text-white rounded-xl text-sm font-medium disabled:opacity-40 transition-all"
                            >
                                {isSubmitting ? 'Deleting...' : 'Delete Client'}
                            </button>
                        </div>
                    </div>
                </Modal>
            )}
        </div>
    );
}
