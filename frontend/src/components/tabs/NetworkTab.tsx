'use client';

import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import useSWR from 'swr';
import {
    Shield,
    KeyRound,
    Plus,
    Trash2,
    RefreshCw,
    Send,
    CheckCircle2,
    AlertCircle,
    Laptop,
    Radio,
    ArrowDownUp,
    Play,
    Square,
    RotateCw,
    FileCode2,
    Download,
    QrCode,
    Copy,
    Check,
    Edit3,
    ExternalLink,
    LogOut,
    Unplug,
    Store,
    ServerCog,
    Terminal,
    XCircle,
    Info
} from 'lucide-react';
import { QRCodeSVG } from 'qrcode.react';
import { useToast } from '@/contexts/ToastContext';
import { useSystemStore } from '@/store/useSystemStore';
import { Modal } from '@/components/ui/Modal';
import {
    NETWORK_STATUS_ENDPOINT,
    NetworkStatusResponse,
    WireGuardPeer,
    WireGuardKeygenResponse,
    WireGuardPeerMutationResponse,
    WireGuardTunnelMode,
    TailscaleConnectResponse,
    TailscaleRoutesResponse,
    NetworkDiagnosticsResponse,
    NetworkServiceAction,
    NetworkProviderId,
    fetchNetworkStatus,
    networkApiRequest,
    extractErrorMessage,
    resolveWireGuardState,
    resolveTailscaleState,
    isWireGuardPeerActive,
    formatHandshakeRelative,
    parseByteCount,
    formatBytes,
    formatByteRate,
    computeTransferRates,
    TransferSampleSnapshot,
    ComputedTransferRates,
    buildWireGuardClientConfig,
    deriveDefaultSplitSubnet,
    defaultServerEndpointHost,
    sanitizeConfigFilename,
    parseRoutesList,
    isValidSafeHttpsUrl,
} from '@/lib/network';

interface PendingConfirmAction {
    title: string;
    description: string;
    confirmLabel: string;
    danger?: boolean;
    onConfirm: () => Promise<void>;
}

interface ExportHandoffState {
    peer: WireGuardPeer;
    clientPrivateKey: string;
    serverPublicKey: string;
    serverEndpoint: string;
    dns: string;
    tunnelMode: WireGuardTunnelMode;
    splitAllowedIps: string;
    defaultSplitAllowedIps: string;
    persistentKeepalive: number;
}

export default function NetworkTab() {
    const { addToast } = useToast();
    const setActiveTab = useSystemStore((state) => state.setActiveTab);

    const [activeSection, setActiveSection] = useState<NetworkProviderId>('wireguard');

    // Single unified polling source for all Network state to avoid duplicate CLI executions
    const {
        data: networkStatus,
        error: statusError,
        isLoading: isStatusLoading,
        isValidating: isValidatingStatus,
        mutate: mutateStatus,
    } = useSWR<NetworkStatusResponse>(NETWORK_STATUS_ENDPOINT, fetchNetworkStatus, {
        refreshInterval: 15000,
    });

    // True measured byte-delta transfer rate tracking per provider
    const wgSampleRef = useRef<TransferSampleSnapshot | null>(null);
    const tsSampleRef = useRef<TransferSampleSnapshot | null>(null);
    const [wgRates, setWgRates] = useState<ComputedTransferRates>({
        rxRateBytesPerSec: null,
        txRateBytesPerSec: null,
        counterReset: false,
    });
    const [tsRates, setTsRates] = useState<ComputedTransferRates>({
        rxRateBytesPerSec: null,
        txRateBytesPerSec: null,
        counterReset: false,
    });

    const wgPeers = useMemo(() => networkStatus?.wireguard?.peers ?? [], [networkStatus?.wireguard?.peers]);
    const tsPeers = useMemo(() => networkStatus?.tailscale?.peers ?? [], [networkStatus?.tailscale?.peers]);

    const wgTotalBytes = useMemo(() => {
        return wgPeers.reduce(
            (acc, peer) => ({
                rx: acc.rx + parseByteCount(peer.transfer_rx),
                tx: acc.tx + parseByteCount(peer.transfer_tx),
            }),
            { rx: 0, tx: 0 }
        );
    }, [wgPeers]);

    const tsTotalBytes = useMemo(() => {
        return tsPeers.reduce(
            (acc, peer) => ({
                rx: acc.rx + parseByteCount(peer.rx_bytes),
                tx: acc.tx + parseByteCount(peer.tx_bytes),
            }),
            { rx: 0, tx: 0 }
        );
    }, [tsPeers]);

    const hasNetworkStatus = Boolean(networkStatus);
    const checkedAtIso = networkStatus?.checked_at || '';

    useEffect(() => {
        if (!hasNetworkStatus) return;
        const parsedTime = checkedAtIso ? Date.parse(checkedAtIso) : NaN;
        const prevWg = wgSampleRef.current;

        const wgChanged =
            !prevWg ||
            (Number.isFinite(parsedTime) && parsedTime > 0 && prevWg.timestampMs !== parsedTime) ||
            prevWg.rxBytes !== wgTotalBytes.rx ||
            prevWg.txBytes !== wgTotalBytes.tx;

        if (wgChanged) {
            const sampleTimeMs =
                Number.isFinite(parsedTime) && parsedTime > 0 ? parsedTime : Date.now();
            const currentWgSample: TransferSampleSnapshot = {
                timestampMs: sampleTimeMs,
                rxBytes: wgTotalBytes.rx,
                txBytes: wgTotalBytes.tx,
            };
            if (prevWg) {
                const nextWgRates = computeTransferRates(prevWg, currentWgSample);
                setWgRates((prev) =>
                    prev.rxRateBytesPerSec === nextWgRates.rxRateBytesPerSec &&
                    prev.txRateBytesPerSec === nextWgRates.txRateBytesPerSec &&
                    prev.counterReset === nextWgRates.counterReset
                        ? prev
                        : nextWgRates
                );
            }
            wgSampleRef.current = currentWgSample;
        }

        const prevTs = tsSampleRef.current;
        const tsChanged =
            !prevTs ||
            (Number.isFinite(parsedTime) && parsedTime > 0 && prevTs.timestampMs !== parsedTime) ||
            prevTs.rxBytes !== tsTotalBytes.rx ||
            prevTs.txBytes !== tsTotalBytes.tx;

        if (tsChanged) {
            const sampleTimeMs =
                Number.isFinite(parsedTime) && parsedTime > 0 ? parsedTime : Date.now();
            const currentTsSample: TransferSampleSnapshot = {
                timestampMs: sampleTimeMs,
                rxBytes: tsTotalBytes.rx,
                txBytes: tsTotalBytes.tx,
            };
            if (prevTs) {
                const nextTsRates = computeTransferRates(prevTs, currentTsSample);
                setTsRates((prev) =>
                    prev.rxRateBytesPerSec === nextTsRates.rxRateBytesPerSec &&
                    prev.txRateBytesPerSec === nextTsRates.txRateBytesPerSec &&
                    prev.counterReset === nextTsRates.counterReset
                        ? prev
                        : nextTsRates
                );
            }
            tsSampleRef.current = currentTsSample;
        }
    }, [hasNetworkStatus, checkedAtIso, wgTotalBytes.rx, wgTotalBytes.tx, tsTotalBytes.rx, tsTotalBytes.tx]);

    // ── Add / Enroll WireGuard Peer & One-Time Config Handoff State ──
    const [showAddWgModal, setShowAddWgModal] = useState(false);
    const [newPeerName, setNewPeerName] = useState('');
    const [newPeerPubKey, setNewPeerPubKey] = useState('');
    const [newPeerAllowedIPs, setNewPeerAllowedIPs] = useState('');
    const [newPeerEndpoint, setNewPeerEndpoint] = useState('');
    const [newPeerKeepalive, setNewPeerKeepalive] = useState('25');
    const [generatedPrivKey, setGeneratedPrivKey] = useState('');
    const [generatedPubKeyPair, setGeneratedPubKeyPair] = useState('');
    const [clientServerEndpoint, setClientServerEndpoint] = useState('');
    const [clientDns, setClientDns] = useState('1.1.1.1, 9.9.9.9');
    const [clientTunnelMode, setClientTunnelMode] = useState<WireGuardTunnelMode>('full_ipv4');
    const [clientSplitCidrs, setClientSplitCidrs] = useState('10.66.66.0/24');
    const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
    const [isSubmittingPeer, setIsSubmittingPeer] = useState(false);
    const [exportHandoff, setExportHandoff] = useState<ExportHandoffState | null>(null);
    const [copiedConfig, setCopiedConfig] = useState(false);
    const enrollSessionRef = useRef(0);
    const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    // ── Edit Existing WireGuard Peer Modal State ──
    const [editingPeer, setEditingPeer] = useState<WireGuardPeer | null>(null);
    const [editPeerName, setEditPeerName] = useState('');
    const [editPeerAllowedIPs, setEditPeerAllowedIPs] = useState('');
    const [editPeerEndpoint, setEditPeerEndpoint] = useState('');
    const [editPeerKeepalive, setEditPeerKeepalive] = useState('25');
    const [isUpdatingPeer, setIsUpdatingPeer] = useState(false);

    // ── Tailscale Lifecycle, Routes & Settings State ──
    const [subnetRouteDraft, setSubnetRouteInput] = useState<string | null>(null);
    const subnetRouteInput = subnetRouteDraft ??
        (networkStatus?.tailscale?.advertised_routes ?? []).join(', ');
    const [isAdvertisingRoutes, setIsAdvertisingRoutes] = useState(false);
    const [isConnectingTs, setIsConnectingTs] = useState(false);
    const [pendingAuthUrl, setPendingAuthUrl] = useState<string | null>(null);
    const [authStatusVersion, setAuthStatusVersion] = useState<string | null>(null);
    const [isSavingTsSettings, setIsSavingTsSettings] = useState(false);

    // ── Service Control & Diagnostics State ──
    const [isRunningServiceAction, setIsRunningServiceAction] = useState(false);
    const [pendingConfirm, setPendingConfirm] = useState<PendingConfirmAction | null>(null);
    const [showDiagnosticsModal, setShowDiagnosticsModal] = useState(false);
    const [diagnosticsProvider, setDiagnosticsProvider] = useState<NetworkProviderId>('wireguard');
    const [diagnosticsData, setDiagnosticsData] = useState<NetworkDiagnosticsResponse | null>(null);
    const [diagnosticsError, setDiagnosticsError] = useState<string | null>(null);
    const [isLoadingDiagnostics, setIsLoadingDiagnostics] = useState(false);



    // Clear any ephemeral secrets on component unmount
    useEffect(() => {
        return () => {
            enrollSessionRef.current += 1;
            if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
        };
    }, []);

    const clearEnrollSecretsAndReset = useCallback(() => {
        enrollSessionRef.current += 1;
        if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
        setIsGeneratingKeys(false);
        setIsSubmittingPeer(false);
        setGeneratedPrivKey('');
        setGeneratedPubKeyPair('');
        setExportHandoff(null);
        setCopiedConfig(false);
        setNewPeerName('');
        setNewPeerPubKey('');
        setNewPeerAllowedIPs(networkStatus?.wireguard?.next_ip || '');
        setNewPeerEndpoint('');
        setNewPeerKeepalive('25');
    }, [networkStatus?.wireguard?.next_ip]);

    const openAddWgModal = useCallback(() => {
        enrollSessionRef.current += 1;
        const defaultPort = networkStatus?.wireguard?.listen_port || '51820';
        const defaultSplit = deriveDefaultSplitSubnet(
            networkStatus?.wireguard?.address,
            networkStatus?.wireguard?.next_ip
        );
        setGeneratedPrivKey('');
        setGeneratedPubKeyPair('');
        setExportHandoff(null);
        setCopiedConfig(false);
        setNewPeerName('');
        setNewPeerPubKey('');
        setNewPeerAllowedIPs(networkStatus?.wireguard?.next_ip || '');
        setNewPeerEndpoint('');
        setNewPeerKeepalive('25');
        setClientServerEndpoint(defaultServerEndpointHost(defaultPort));
        setClientDns('1.1.1.1, 9.9.9.9');
        setClientTunnelMode('full_ipv4');
        setClientSplitCidrs(defaultSplit);
        setShowAddWgModal(true);
    }, [networkStatus?.wireguard?.address, networkStatus?.wireguard?.listen_port, networkStatus?.wireguard?.next_ip]);

    const closeAddWgModal = useCallback(() => {
        if (isSubmittingPeer) return;
        clearEnrollSecretsAndReset();
        setShowAddWgModal(false);
    }, [clearEnrollSecretsAndReset, isSubmittingPeer]);

    // Keyboard Escape handler for modals
    useEffect(() => {
        const onKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                if (pendingConfirm) {
                    setPendingConfirm(null);
                } else if (showAddWgModal) {
                    closeAddWgModal();
                } else if (editingPeer) {
                    setEditingPeer(null);
                } else if (showDiagnosticsModal) {
                    setShowDiagnosticsModal(false);
                }
            }
        };
        window.addEventListener('keydown', onKeyDown);
        return () => window.removeEventListener('keydown', onKeyDown);
    }, [pendingConfirm, showAddWgModal, editingPeer, showDiagnosticsModal, closeAddWgModal]);

    // ── WireGuard Handlers ──
    const handleKeygen = async () => {
        const session = enrollSessionRef.current;
        setIsGeneratingKeys(true);
        try {
            const data = await networkApiRequest<WireGuardKeygenResponse>(
                '/api/v1/admin/network/wireguard/keygen',
                { method: 'POST' }
            );
            if (session !== enrollSessionRef.current) return;
            if (!data.public_key || !data.private_key) throw new Error('Key generation returned incomplete credentials.');
            setNewPeerPubKey(data.public_key || '');
            setGeneratedPubKeyPair(data.public_key || '');
            setGeneratedPrivKey(data.private_key || '');
            addToast('Client keypair ready. Save its configuration after enrollment.', 'success');
        } catch (err) {
            if (session === enrollSessionRef.current) addToast(extractErrorMessage(err, 'Failed to generate keypair.'), 'error');
        } finally {
            if (session === enrollSessionRef.current) setIsGeneratingKeys(false);
        }
    };

    const handlePublicKeyInputChange = (val: string) => {
        if (isGeneratingKeys) {
            enrollSessionRef.current += 1;
            setIsGeneratingKeys(false);
        }
        setNewPeerPubKey(val);
        // If user edits public key away from generated keypair, purge ephemeral private key immediately
        if (generatedPubKeyPair && val.trim() !== generatedPubKeyPair.trim()) {
            setGeneratedPrivKey('');
            setGeneratedPubKeyPair('');
        }
    };

    const handleAddWgPeer = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!newPeerPubKey.trim() || isGeneratingKeys || isSubmittingPeer) return;
        const session = enrollSessionRef.current;
        setIsSubmittingPeer(true);
        const parsedKeepalive = newPeerKeepalive.trim() === '' ? NaN : Number(newPeerKeepalive);
        const keepaliveVal =
            Number.isFinite(parsedKeepalive) && parsedKeepalive >= 0
                ? Math.floor(parsedKeepalive)
                : 25;

        try {
            const payload: Record<string, unknown> = {
                public_key: newPeerPubKey.trim(),
                name: newPeerName.trim() || 'WireGuard Client',
                persistent_keepalive: keepaliveVal,
            };
            if (newPeerAllowedIPs.trim()) {
                payload.allowed_ips = newPeerAllowedIPs.trim();
            }
            if (newPeerEndpoint.trim()) {
                payload.endpoint = newPeerEndpoint.trim();
            }

            const data = await networkApiRequest<WireGuardPeerMutationResponse>(
                '/api/v1/admin/network/wireguard/peers',
                {
                    method: 'POST',
                    body: JSON.stringify(payload),
                }
            );
            if (session !== enrollSessionRef.current) return;

            addToast(data.message || 'WireGuard peer enrolled.', 'success');
            await Promise.resolve(mutateStatus()).catch(() => undefined);

            const enrolledPeer = data.peer;
            if (!enrolledPeer?.allowed_ips || enrolledPeer.public_key !== newPeerPubKey.trim()) {
                throw new Error('Peer was saved, but its assigned address was not returned. Keep the private key and refresh before exporting.');
            }

            // If we have an ephemeral generated private key matching the enrolled public key,
            // transition into the one-time browser client config export/QR handoff view.
            if (generatedPrivKey && generatedPubKeyPair === newPeerPubKey.trim()) {
                setExportHandoff({
                    peer: enrolledPeer,
                    clientPrivateKey: generatedPrivKey,
                    serverPublicKey: networkStatus?.wireguard?.public_key || '',
                    serverEndpoint:
                        clientServerEndpoint.trim() ||
                        defaultServerEndpointHost(networkStatus?.wireguard?.listen_port || '51820'),
                    dns: clientDns.trim(),
                    tunnelMode: clientTunnelMode,
                    splitAllowedIps:
                        clientSplitCidrs.trim() ||
                        deriveDefaultSplitSubnet(networkStatus?.wireguard?.address, enrolledPeer.allowed_ips),
                    defaultSplitAllowedIps:
                        deriveDefaultSplitSubnet(networkStatus?.wireguard?.address, enrolledPeer.allowed_ips),
                    persistentKeepalive: keepaliveVal,
                });
                // Clear raw form private key state so only exportHandoff holds it until modal close
                setGeneratedPrivKey('');
                setGeneratedPubKeyPair('');
            } else {
                closeAddWgModal();
            }
        } catch (err) {
            addToast(extractErrorMessage(err, 'Failed to add WireGuard peer.'), 'error');
        } finally {
            if (session === enrollSessionRef.current) setIsSubmittingPeer(false);
        }
    };

    const openEditPeerModal = (peer: WireGuardPeer) => {
        setEditingPeer(peer);
        setEditPeerName(peer.name || '');
        setEditPeerAllowedIPs(peer.allowed_ips || '');
        setEditPeerEndpoint(peer.endpoint || '');
        setEditPeerKeepalive(String(peer.persistent_keepalive ?? 25));
    };

    const handleUpdateWgPeer = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!editingPeer) return;
        setIsUpdatingPeer(true);
        const parsedKeepalive = editPeerKeepalive.trim() === '' ? NaN : Number(editPeerKeepalive);
        const keepaliveVal =
            Number.isFinite(parsedKeepalive) && parsedKeepalive >= 0
                ? Math.floor(parsedKeepalive)
                : 25;

        try {
            const data = await networkApiRequest<WireGuardPeerMutationResponse>(
                `/api/v1/admin/network/wireguard/peers/${encodeURIComponent(editingPeer.public_key)}`,
                {
                    method: 'PUT',
                    body: JSON.stringify({
                        name: editPeerName.trim(),
                        allowed_ips: editPeerAllowedIPs.trim(),
                        endpoint: editPeerEndpoint.trim() || undefined,
                        persistent_keepalive: keepaliveVal,
                    }),
                }
            );
            addToast(data.message || 'WireGuard peer updated.', 'success');
            setEditingPeer(null);
            await Promise.resolve(mutateStatus()).catch(() => undefined);
        } catch (err) {
            addToast(extractErrorMessage(err, 'Failed to update WireGuard peer.'), 'error');
        } finally {
            setIsUpdatingPeer(false);
        }
    };

    const requestRemoveWgPeer = (peer: WireGuardPeer) => {
        setPendingConfirm({
            title: 'Remove WireGuard Peer',
            description: `Remove peer "${peer.name || peer.public_key.slice(0, 16)}" (${peer.allowed_ips || 'no IP'}) from both live tunnel and persistent configuration?`,
            confirmLabel: 'Remove Peer',
            danger: true,
            onConfirm: async () => {
                try {
                    const data = await networkApiRequest<{ message?: string }>(
                        `/api/v1/admin/network/wireguard/peers/${encodeURIComponent(peer.public_key)}`,
                        { method: 'DELETE' }
                    );
                    addToast(data.message || 'WireGuard peer removed.', 'success');
                    await Promise.resolve(mutateStatus()).catch(() => undefined);
                } catch (err) {
                    addToast(extractErrorMessage(err, 'Failed to remove WireGuard peer.'), 'error');
                }
            },
        });
    };

    const exportedClientConfigText = useMemo(() => {
        if (!exportHandoff) return '';
        return buildWireGuardClientConfig({
            clientPrivateKey: exportHandoff.clientPrivateKey,
            clientAddress: exportHandoff.peer.allowed_ips,
            serverPublicKey: exportHandoff.serverPublicKey,
            serverEndpoint: exportHandoff.serverEndpoint,
            dns: exportHandoff.dns,
            tunnelMode: exportHandoff.tunnelMode,
            splitAllowedIps:
                exportHandoff.splitAllowedIps.trim() ||
                exportHandoff.defaultSplitAllowedIps,
            persistentKeepalive: exportHandoff.persistentKeepalive,
        });
    }, [exportHandoff]);

    const handleDownloadConfig = () => {
        if (!exportHandoff || !exportedClientConfigText) return;
        const blob = new Blob([exportedClientConfigText], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = sanitizeConfigFilename(exportHandoff.peer.name);
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        addToast('Client .conf downloaded.', 'info');
    };

    const handleCopyConfig = async () => {
        if (!exportedClientConfigText) return;
        try {
            await navigator.clipboard.writeText(exportedClientConfigText);
            setCopiedConfig(true);
            addToast('Client configuration copied to clipboard.', 'info');
            if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
            copyTimerRef.current = setTimeout(() => setCopiedConfig(false), 2000);
        } catch {
            addToast('Failed to copy configuration.', 'error');
        }
    };

    // ── Service Lifecycle & Diagnostics Handlers ──
    const executeServiceAction = async (provider: NetworkProviderId, action: NetworkServiceAction) => {
        setIsRunningServiceAction(true);
        try {
            const data = await networkApiRequest<{ message?: string }>(
                `/api/v1/admin/network/${provider}/service`,
                {
                    method: 'POST',
                    body: JSON.stringify({ action }),
                }
            );
            addToast(data.message || `${provider} service ${action} completed.`, 'success');
            await Promise.resolve(mutateStatus()).catch(() => undefined);
        } catch (err) {
            addToast(extractErrorMessage(err, `Failed to ${action} ${provider} service.`), 'error');
        } finally {
            setIsRunningServiceAction(false);
        }
    };

    const handleServiceControl = (provider: NetworkProviderId, action: NetworkServiceAction) => {
        if (action === 'start') {
            void executeServiceAction(provider, action);
            return;
        }
        const label = provider === 'wireguard' ? 'WireGuard (wg0)' : 'Tailscale (tailscaled)';
        setPendingConfirm({
            title: `${action === 'stop' ? 'Stop' : 'Restart'} ${label}`,
            description:
                action === 'stop'
                    ? `Stopping ${label} will immediately disconnect active VPN sessions using this tunnel.`
                    : `Restarting ${label} will briefly interrupt active tunnel sessions and reload configuration.`,
            confirmLabel: `${action === 'stop' ? 'Stop' : 'Restart'} Service`,
            danger: action === 'stop',
            onConfirm: () => executeServiceAction(provider, action),
        });
    };

    const openDiagnostics = async (provider: NetworkProviderId) => {
        setDiagnosticsProvider(provider);
        setShowDiagnosticsModal(true);
        setIsLoadingDiagnostics(true);
        setDiagnosticsError(null);
        try {
            const data = await networkApiRequest<NetworkDiagnosticsResponse>(
                `/api/v1/admin/network/diagnostics?provider=${encodeURIComponent(provider)}`
            );
            setDiagnosticsData(data);
        } catch (err) {
            setDiagnosticsError(extractErrorMessage(err, 'Failed to load diagnostics.'));
            setDiagnosticsData(null);
        } finally {
            setIsLoadingDiagnostics(false);
        }
    };

    // ── Tailscale Handlers ──
    const handleTailscaleConnect = async (reauth = false) => {
        setIsConnectingTs(true);
        try {
            const data = await networkApiRequest<TailscaleConnectResponse>(
                '/api/v1/admin/network/tailscale/connect',
                {
                    method: 'POST',
                    body: JSON.stringify({ reauth }),
                }
            );
            if (data.auth_url && isValidSafeHttpsUrl(data.auth_url)) {
                setAuthStatusVersion(checkedAtIso);
                setPendingAuthUrl(data.auth_url);
            } else {
                setPendingAuthUrl(null);
            }
            addToast(
                data.message ||
                    (data.auth_url
                        ? 'Complete authentication via the Tailscale login URL.'
                        : 'Tailscale connection updated.'),
                'info'
            );
            await Promise.resolve(mutateStatus()).catch(() => undefined);
        } catch (err) {
            addToast(extractErrorMessage(err, 'Failed to initiate Tailscale connection.'), 'error');
        } finally {
            setIsConnectingTs(false);
        }
    };

    const handleTailscaleDisconnect = () => {
        setPendingConfirm({
            title: 'Disconnect Tailscale Mesh',
            description: 'Bring down the Tailscale tunnel while keeping this node enrolled in your tailnet?',
            confirmLabel: 'Disconnect',
            danger: false,
            onConfirm: async () => {
                try {
                    const data = await networkApiRequest<{ message?: string }>(
                        '/api/v1/admin/network/tailscale/disconnect',
                        { method: 'POST' }
                    );
                    addToast(data.message || 'Tailscale disconnected.', 'success');
                    await Promise.resolve(mutateStatus()).catch(() => undefined);
                } catch (err) {
                    addToast(extractErrorMessage(err, 'Failed to disconnect Tailscale.'), 'error');
                }
            },
        });
    };

    const handleTailscaleLogout = () => {
        setPendingConfirm({
            title: 'Log Out Tailscale Node',
            description:
                'Logging out expires this node key and removes active tailnet connectivity until you re-authenticate.',
            confirmLabel: 'Log Out Node',
            danger: true,
            onConfirm: async () => {
                try {
                    const data = await networkApiRequest<{ message?: string }>(
                        '/api/v1/admin/network/tailscale/logout',
                        { method: 'POST' }
                    );
                    setPendingAuthUrl(null);
                    addToast(data.message || 'Logged out from Tailscale.', 'success');
                    await Promise.resolve(mutateStatus()).catch(() => undefined);
                } catch (err) {
                    addToast(extractErrorMessage(err, 'Failed to log out Tailscale.'), 'error');
                }
            },
        });
    };

    const submitTailscaleRoutes = async (
        routes: string[],
        options?: { clearDraftIfMatches?: string | null; removeCidrFromDraft?: string }
    ) => {
        setIsAdvertisingRoutes(true);
        try {
            const data = await networkApiRequest<TailscaleRoutesResponse>(
                '/api/v1/admin/network/tailscale/routes',
                {
                    method: 'POST',
                    body: JSON.stringify({ routes }),
                }
            );
            const updatedRoutes = data.routes ?? routes;
            setSubnetRouteInput((currentDraft) => {
                if (options && 'clearDraftIfMatches' in options) {
                    return currentDraft === options.clearDraftIfMatches ? null : currentDraft;
                }
                if (options?.removeCidrFromDraft && currentDraft !== null) {
                    const remaining = parseRoutesList(currentDraft).filter(
                        (r) => r !== options.removeCidrFromDraft
                    );
                    return remaining.join(', ');
                }
                return currentDraft;
            });
            await mutateStatus(current => current?.tailscale ? {
                ...current,
                tailscale: { ...current.tailscale, advertised_routes: updatedRoutes },
            } : current, { revalidate: false });
            addToast(
                data.message ||
                    (updatedRoutes.length === 0
                        ? 'Cleared all advertised subnet routes.'
                        : 'Advertised subnet routes updated.'),
                'success'
            );
            await Promise.resolve(mutateStatus()).catch(() => undefined);
        } catch (err) {
            addToast(extractErrorMessage(err, 'Failed to update advertised routes.'), 'error');
        } finally {
            setIsAdvertisingRoutes(false);
        }
    };

    const handleAdvertiseRoutesSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        const draftSnapshot = subnetRouteDraft;
        const routes = parseRoutesList(subnetRouteInput);
        await submitTailscaleRoutes(routes, { clearDraftIfMatches: draftSnapshot });
    };

    const handleRemoveSingleRoute = async (cidrToRemove: string) => {
        const current = tsStatus?.advertised_routes ?? [];
        const nextRoutes = current.filter((r) => r !== cidrToRemove);
        await submitTailscaleRoutes(nextRoutes, { removeCidrFromDraft: cidrToRemove });
    };

    const handleClearAllRoutes = async () => {
        const draftSnapshot = subnetRouteDraft;
        await submitTailscaleRoutes([], { clearDraftIfMatches: draftSnapshot });
    };

    const handleUpdateTailscaleSettings = async (patch: {
        accept_routes?: boolean;
        advertise_exit_node?: boolean;
        exit_node?: string;
        exit_node_allow_lan_access?: boolean;
    }) => {
        setIsSavingTsSettings(true);
        try {
            const data = await networkApiRequest<{ message?: string }>(
                '/api/v1/admin/network/tailscale/settings',
                {
                    method: 'POST',
                    body: JSON.stringify(patch),
                }
            );
            addToast(data.message || 'Tailscale settings updated.', 'success');
            await Promise.resolve(mutateStatus()).catch(() => undefined);
        } catch (err) {
            addToast(extractErrorMessage(err, 'Failed to update Tailscale settings.'), 'error');
        } finally {
            setIsSavingTsSettings(false);
        }
    };

    // ── Derived Truthful States ──
    const wgState = resolveWireGuardState(networkStatus);
    const tsState = resolveTailscaleState(networkStatus);
    const wgStatus = networkStatus?.wireguard;
    const tsStatus = networkStatus?.tailscale;
    const runnerUnavailable = networkStatus?.runner_available === false;

    const activeWgPeersCount = useMemo(
        () => wgPeers.filter((p) => isWireGuardPeerActive(p)).length,
        [wgPeers]
    );
    const onlineTsPeersCount = useMemo(
        () => tsPeers.filter((p) => p.online).length,
        [tsPeers]
    );
    const exitNodeCandidates = useMemo(
        () => tsPeers.filter((p) => p.exit_node_option || p.exit_node),
        [tsPeers]
    );

    // A newer running snapshot completes this login. Keep a fresh link while
    // the pre-login snapshot is still cached during the connection request.
    if (pendingAuthUrl && !isConnectingTs && tsState === 'running' &&
        authStatusVersion !== checkedAtIso) {
        setPendingAuthUrl(null);
    }

    const activeAuthUrl = useMemo(() => {
        const candidate = pendingAuthUrl || (tsState !== 'running' ? tsStatus?.auth_url : null);
        return isValidSafeHttpsUrl(candidate) ? candidate! : null;
    }, [pendingAuthUrl, tsStatus?.auth_url, tsState]);

    const wgStateBadge = useMemo(() => {
        switch (wgState) {
            case 'running':
                return { label: 'Running', cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20', dot: 'bg-emerald-400 animate-pulse' };
            case 'stopped':
                return { label: 'Stopped', cls: 'bg-slate-500/15 text-slate-300 border-slate-500/30', dot: 'bg-slate-400' };
            case 'unconfigured':
                return { label: 'Unconfigured', cls: 'bg-amber-500/10 text-amber-300 border-amber-500/25', dot: 'bg-amber-400' };
            case 'not_installed':
                return { label: 'Not Installed', cls: 'bg-slate-800 text-slate-400 border-white/10', dot: 'bg-slate-500' };
            case 'error':
                return { label: 'Error', cls: 'bg-red-500/10 text-red-400 border-red-500/25', dot: 'bg-red-400' };
        }
    }, [wgState]);

    const tsStateBadge = useMemo(() => {
        switch (tsState) {
            case 'running':
                return { label: 'Running', cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20', dot: 'bg-emerald-400 animate-pulse' };
            case 'needs_login':
                return { label: 'Needs Login', cls: 'bg-amber-500/10 text-amber-300 border-amber-500/25', dot: 'bg-amber-400' };
            case 'needs_approval':
                return { label: 'Needs Approval', cls: 'bg-amber-500/10 text-amber-300 border-amber-500/25', dot: 'bg-amber-400' };
            case 'stopped':
                return { label: 'Stopped', cls: 'bg-slate-500/15 text-slate-300 border-slate-500/30', dot: 'bg-slate-400' };
            case 'not_installed':
                return { label: 'Not Installed', cls: 'bg-slate-800 text-slate-400 border-white/10', dot: 'bg-slate-500' };
            case 'error':
                return { label: 'Error', cls: 'bg-red-500/10 text-red-400 border-red-500/25', dot: 'bg-red-400' };
        }
    }, [tsState]);

    const activeProviderRates = activeSection === 'wireguard' ? wgRates : tsRates;
    const activeProviderTotalBytes = activeSection === 'wireguard' ? wgTotalBytes : tsTotalBytes;

    return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-w-0 max-w-full">
            {/* Top Toolbar & Provider Switcher */}
            <div className="flex flex-wrap items-center justify-between gap-4 pb-4 mb-2 border-b border-white/[0.06] relative z-30 shrink-0">
                <div className="flex items-center gap-3.5 min-w-0">
                    <div className="h-10 w-10 rounded-xl flex items-center justify-center border bg-indigo-500/20 border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.15)] text-indigo-400 shrink-0">
                        {activeSection === 'wireguard' ? <Shield size={20} /> : <Radio size={20} />}
                    </div>
                    <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2.5">
                            <h2 className="text-lg font-bold text-slate-100 tracking-tight">Network &amp; VPN Mesh</h2>
                            <span className="text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border bg-indigo-500/15 text-indigo-300 border-indigo-500/30">
                                {activeSection === 'wireguard' ? 'WireGuard Kernel' : 'Tailscale Mesh'}
                            </span>
                        </div>
                        <div className="flex flex-wrap items-center gap-2 mt-0.5 text-xs text-slate-400 font-medium">
                            <span className="relative flex h-2 w-2 shrink-0">
                                <span
                                    className={`relative inline-flex rounded-full h-2 w-2 ${
                                        (activeSection === 'wireguard' ? wgState === 'running' : tsState === 'running')
                                            ? 'bg-emerald-500'
                                            : (activeSection === 'wireguard' ? wgState === 'error' : tsState === 'error')
                                            ? 'bg-red-500'
                                            : 'bg-amber-500'
                                    }`}
                                />
                            </span>
                            <span>
                                Mesh Health &middot; {wgPeers.length} WireGuard Peers ({activeWgPeersCount} active) / {tsPeers.length} Tailnet Devices
                            </span>
                            {networkStatus?.checked_at && (
                                <span className="text-slate-500">
                                    &middot; Checked {new Date(networkStatus.checked_at).toLocaleTimeString()}
                                </span>
                            )}
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
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
                            <Shield size={14} />
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
                            <Radio size={14} />
                            Tailscale Mesh
                        </button>
                    </div>

                    {activeSection === 'wireguard' && wgState !== 'not_installed' && (
                        <button
                            type="button"
                            onClick={openAddWgModal}
                            className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-all shadow-lg shadow-indigo-500/20"
                        >
                            <Plus size={14} />
                            <span>Add Peer</span>
                        </button>
                    )}

                    <button
                        type="button"
                        onClick={() => openDiagnostics(activeSection)}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                    >
                        <Terminal size={14} />
                        <span>Diagnostics</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => setActiveTab('services')}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                    >
                        <ServerCog size={14} />
                        <span>Services</span>
                    </button>

                    <button
                        type="button"
                        onClick={() => mutateStatus()}
                        className="obs-touch-target-standard obs-gpu-120hz-interactive flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-white/[0.04] border border-white/10 text-slate-300 hover:bg-white/[0.08] hover:text-white transition-all"
                        title="Refresh Network"
                    >
                        <RefreshCw size={14} className={isValidatingStatus ? 'animate-spin text-indigo-400' : 'text-slate-400'} />
                        <span>Refresh</span>
                    </button>
                </div>
            </div>

            {/* Global Status / Privilege / Runner Alerts */}
            {statusError && (
                <div
                    role="alert"
                    className="rounded-2xl border border-red-500/30 bg-red-500/10 p-4 flex flex-wrap items-center justify-between gap-3 text-xs text-red-200"
                >
                    <div className="flex items-center gap-2.5">
                        <AlertCircle size={18} className="text-red-400 shrink-0" />
                        <div>
                            <p className="font-bold text-red-300">Failed to load Network status</p>
                            <p className="text-red-200/90 mt-0.5">
                                {extractErrorMessage(statusError, 'Unable to reach /api/v1/admin/network/status')}
                            </p>
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={() => mutateStatus()}
                        className="px-3 py-1.5 rounded-xl bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 text-xs font-bold text-red-100 transition-colors"
                    >
                        Retry Status
                    </button>
                </div>
            )}

            {runnerUnavailable && (
                <div
                    role="alert"
                    className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4 flex flex-wrap items-center justify-between gap-3 text-xs text-amber-200"
                >
                    <div className="flex items-center gap-2.5">
                        <AlertCircle size={18} className="text-amber-400 shrink-0" />
                        <div>
                            <p className="font-bold text-amber-300">Privileged Runner Unavailable (af-runner)</p>
                            <p className="text-amber-200/90 mt-0.5">
                                Privileged network inspection and mutations require the local af-runner daemon. Verify the runner service is active.
                            </p>
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={() => setActiveTab('services')}
                        className="px-3 py-1.5 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/30 text-xs font-bold text-amber-100 transition-colors"
                    >
                        Open Services
                    </button>
                </div>
            )}

            {isStatusLoading && !networkStatus && !statusError && (
                <div className="obs-canvas-section py-5 text-xs text-slate-300 flex items-center gap-3">
                    <RefreshCw size={16} className="animate-spin text-indigo-400" />
                    <span>Loading live WireGuard and Tailscale telemetry...</span>
                </div>
            )}

            {/* 4-Card Truthful Telemetry Strip */}
            <div className="obs-canvas-section grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y divide-white/[0.07] sm:divide-y-0 sm:[&>*:nth-child(n+3)]:border-t sm:[&>*:nth-child(n+3)]:border-white/[0.07] sm:max-lg:[&>*:nth-child(even)]:border-l sm:max-lg:[&>*:nth-child(even)]:border-white/[0.07] lg:[&>*]:border-t-0 lg:divide-x lg:divide-white/[0.07]">
                <div className="p-4 flex items-center justify-between min-w-0">
                    <div className="min-w-0">
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Tunnel Health</p>
                        <p className="text-base font-bold text-slate-100 mt-1">
                            {wgState === 'running'
                                ? `${wgStatus?.interface || 'wg0'} Running`
                                : wgState === 'stopped'
                                ? 'WireGuard Stopped'
                                : wgState === 'unconfigured'
                                ? 'WireGuard Unconfigured'
                                : wgState === 'not_installed'
                                ? 'Not Installed'
                                : 'WireGuard Error'}
                        </p>
                        <p className="text-xs text-slate-400 mt-0.5 truncate">
                            {wgStatus?.listen_port ? `UDP ${wgStatus.listen_port}` : 'No active listen port'} &middot;{' '}
                            {wgStatus?.service_state || wgStateBadge.label}
                        </p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
                        <CheckCircle2 size={20} />
                    </div>
                </div>

                <div className="p-4 flex items-center justify-between min-w-0">
                    <div className="min-w-0">
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Active Peers</p>
                        <p className="text-2xl font-bold text-slate-100 mt-1" data-testid="active-wg-peers-count">
                            {activeWgPeersCount}
                        </p>
                        <p className="text-xs text-slate-400 mt-0.5">
                            {wgPeers.length} configured &middot; {activeWgPeersCount} recent handshake
                        </p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shrink-0">
                        <Shield size={20} />
                    </div>
                </div>

                <div className="p-4 flex items-center justify-between min-w-0">
                    <div className="min-w-0">
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Transfer Metrics</p>
                        <p className="text-sm font-bold text-slate-100 mt-1 font-mono" data-testid="transfer-rate-display">
                            {activeProviderRates.rxRateBytesPerSec !== null && activeProviderRates.txRateBytesPerSec !== null
                                ? `↓ ${formatByteRate(activeProviderRates.rxRateBytesPerSec)} · ↑ ${formatByteRate(activeProviderRates.txRateBytesPerSec)}`
                                : `↓ ${formatBytes(activeProviderTotalBytes.rx)} · ↑ ${formatBytes(activeProviderTotalBytes.tx)}`}
                        </p>
                        <p className="text-xs text-slate-400 mt-0.5">
                            {activeProviderRates.counterReset
                                ? 'Counters reset · Total ↓ ' + formatBytes(activeProviderTotalBytes.rx)
                                : `Total ↓ ${formatBytes(activeProviderTotalBytes.rx)} · ↑ ${formatBytes(activeProviderTotalBytes.tx)}`}
                        </p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 shrink-0">
                        <ArrowDownUp size={20} />
                    </div>
                </div>

                <div className="p-4 flex items-center justify-between min-w-0">
                    <div className="min-w-0">
                        <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Tailnet Mesh Status</p>
                        <p className="text-base font-bold text-slate-100 mt-1">
                            {tsStateBadge.label}
                        </p>
                        <p className="text-xs text-slate-400 mt-0.5">
                            {onlineTsPeersCount} Online / {tsPeers.length} Mesh Devices
                        </p>
                    </div>
                    <div className="h-10 w-10 rounded-xl bg-violet-500/10 border border-violet-500/20 flex items-center justify-center text-violet-400 shrink-0">
                        <Radio size={20} />
                    </div>
                </div>
            </div>

            {/* ── WireGuard Section ── */}
            {activeSection === 'wireguard' && (
                <div className="space-y-6">
                    {/* WireGuard Provider Error Banner */}
                    {wgStatus?.error && (
                        <div
                            role="alert"
                            className="rounded-2xl border border-red-500/30 bg-red-500/10 p-4 flex flex-wrap items-center justify-between gap-3 text-xs text-red-200"
                        >
                            <div className="flex items-center gap-2.5">
                                <AlertCircle size={18} className="text-red-400 shrink-0" />
                                <div>
                                    <p className="font-bold text-red-300">WireGuard Runtime Error</p>
                                    <p className="mt-0.5">{wgStatus.error}</p>
                                </div>
                            </div>
                            <button
                                type="button"
                                onClick={() => openDiagnostics('wireguard')}
                                className="obs-touch-target-standard min-h-[44px] px-3.5 py-2 rounded-xl bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 text-xs font-bold text-red-100 inline-flex items-center justify-center transition-colors"
                            >
                                Inspect Diagnostics
                            </button>
                        </div>
                    )}

                    {/* Not Installed / Unconfigured Recovery Card */}
                    {wgState === 'not_installed' && (
                        <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-5 flex flex-wrap items-center justify-between gap-4">
                            <div className="space-y-1">
                                <h3 className="text-sm font-bold text-amber-200">WireGuard Package Not Installed</h3>
                                <p className="text-xs text-amber-100/80">
                                    Install WireGuard from the AetherFlow Marketplace to provision the kernel interface and `/etc/wireguard/wg0.conf`.
                                </p>
                            </div>
                            <button
                                type="button"
                                onClick={() => setActiveTab('marketplace')}
                                className="obs-touch-target-standard min-h-[44px] px-4 py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-xs font-bold text-amber-100 inline-flex items-center justify-center gap-2 transition-colors"
                            >
                                <Store size={14} />
                                <span>Open Marketplace</span>
                            </button>
                        </div>
                    )}

                    {/* Interface Status & Service Controls Card */}
                    <div className="obs-canvas-section py-5 space-y-4">
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                            <div className="flex items-center gap-3">
                                <div className="h-9 w-9 bg-indigo-500/20 rounded-xl flex items-center justify-center border border-indigo-500/30 text-indigo-400 shrink-0">
                                    <Shield size={18} />
                                </div>
                                <div>
                                    <h3 className="text-sm font-bold text-slate-200">
                                        Interface: {wgStatus?.interface || 'wg0'}
                                    </h3>
                                    <p className="text-xs text-slate-400 font-mono mt-0.5">
                                        Port: {wgStatus?.listen_port || '—'} &middot; Subnet:{' '}
                                        {wgStatus?.address?.length ? wgStatus.address.join(', ') : 'Unassigned'}
                                        {wgStatus?.next_ip ? ` · Next Peer IP: ${wgStatus.next_ip}` : ''}
                                    </p>
                                </div>
                            </div>

                            <div className="flex flex-wrap items-center gap-2">
                                <span
                                    data-testid="wg-state-badge"
                                    className={`px-3 py-1 rounded-full text-xs font-bold uppercase border flex items-center gap-1.5 ${wgStateBadge.cls}`}
                                >
                                    <span className={`w-1.5 h-1.5 rounded-full ${wgStateBadge.dot}`} />
                                    {wgStateBadge.label}
                                </span>

                                {wgState !== 'not_installed' && (
                                    <div className="flex flex-wrap items-center gap-1.5">
                                        <button
                                            type="button"
                                            disabled={isRunningServiceAction}
                                            onClick={() => handleServiceControl('wireguard', 'start')}
                                            className="obs-touch-target-standard min-h-[44px] px-3 py-2 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50 transition-colors"
                                            title="Start WireGuard service"
                                        >
                                            <Play size={12} />
                                            <span>Start</span>
                                        </button>
                                        <button
                                            type="button"
                                            disabled={isRunningServiceAction}
                                            onClick={() => handleServiceControl('wireguard', 'restart')}
                                            className="obs-touch-target-standard min-h-[44px] px-3 py-2 rounded-xl bg-indigo-500/15 hover:bg-indigo-500/25 border border-indigo-500/30 text-indigo-300 text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50 transition-colors"
                                            title="Restart WireGuard service"
                                        >
                                            <RotateCw size={12} />
                                            <span>Restart</span>
                                        </button>
                                        <button
                                            type="button"
                                            disabled={isRunningServiceAction}
                                            onClick={() => handleServiceControl('wireguard', 'stop')}
                                            className="obs-touch-target-standard min-h-[44px] px-3 py-2 rounded-xl bg-red-500/15 hover:bg-red-500/25 border border-red-500/30 text-red-300 text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50 transition-colors"
                                            title="Stop WireGuard service"
                                        >
                                            <Square size={12} />
                                            <span>Stop</span>
                                        </button>
                                    </div>
                                )}
                            </div>
                        </div>

                        {wgStatus?.public_key && (
                            <div className="border-y border-white/[0.07] py-2.5 font-mono text-xs flex flex-wrap items-center justify-between gap-4">
                                <span className="text-slate-400 shrink-0">Server Public Key:</span>
                                <span className="text-slate-200 break-all select-all">{wgStatus.public_key}</span>
                            </div>
                        )}

                        <div className="flex items-start gap-2 text-xs text-slate-400 py-1">
                            <Info size={14} className="text-indigo-400 shrink-0 mt-0.5" />
                            <span>
                                Keys generated here are returned once and are not saved by AetherFlow. Full client <code className="text-indigo-300">.conf</code> and QR code export are available once during enrollment when generating a one-time client keypair. Existing or manual-key peers require the original client private key on your device.
                            </span>
                        </div>
                    </div>

                    {/* WireGuard Peers Table */}
                    <div className="obs-canvas-section py-5 min-w-0 max-w-full">
                        <div className="flex items-center justify-between mb-4 pb-3 border-b border-white/[0.06]">
                            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                                Registered Peers ({wgPeers.length})
                            </h4>
                            <button
                                type="button"
                                onClick={() => mutateStatus()}
                                className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center p-2 text-slate-400 hover:text-white rounded-xl hover:bg-white/5 transition-colors"
                                title="Refresh peers"
                                aria-label="Refresh peers"
                            >
                                <RefreshCw size={14} />
                            </button>
                        </div>

                        <div className="overflow-x-auto min-w-0 max-w-full">
                            <table aria-label="WireGuard peers" className="obs-mobile-ledger w-full text-left border-collapse text-xs">
                                <thead>
                                    <tr className="border-b border-white/[0.06] text-slate-400 text-xs uppercase tracking-wider">
                                        <th className="py-2.5 px-3">Peer / Public Key</th>
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
                                            <td colSpan={6} className="py-12 text-center text-slate-400 text-xs">
                                                No WireGuard peers configured. Click &quot;Add Peer&quot; to register a client.
                                            </td>
                                        </tr>
                                    ) : (
                                        wgPeers.map((peer) => {
                                            const active = isWireGuardPeerActive(peer);
                                            return (
                                                <tr key={peer.public_key} className="hover:bg-white/[0.02] transition-colors">
                                                    <td data-primary data-label="Peer / Public Key" className="py-3 px-3">
                                                        <div className="flex items-center gap-2">
                                                            <span
                                                                className={`h-2 w-2 rounded-full shrink-0 ${
                                                                    active ? 'bg-emerald-400' : 'bg-slate-600'
                                                                }`}
                                                                title={active ? 'Active handshake' : 'Idle / No recent handshake'}
                                                            />
                                                            <span className="font-semibold text-slate-200">
                                                                {peer.name || 'Unnamed Peer'}
                                                            </span>
                                                            {peer.persistent === false && (
                                                                <span className="text-xs text-amber-300" title="Edit and save this peer to preserve it after restarting wg0">
                                                                    Runtime only
                                                                </span>
                                                            )}
                                                        </div>
                                                        <div
                                                            className="font-mono text-indigo-300 truncate max-w-[200px] mt-0.5"
                                                            title={peer.public_key}
                                                        >
                                                            {peer.public_key.substring(0, 20)}...
                                                        </div>
                                                    </td>
                                                    <td data-label="Allowed IPs" className="py-3 px-3 font-mono text-slate-200">
                                                        {peer.allowed_ips || '—'}
                                                    </td>
                                                    <td data-label="Endpoint" className="py-3 px-3 font-mono text-slate-400">
                                                        {peer.endpoint || 'Roaming'}
                                                    </td>
                                                    <td data-label="Latest Handshake" className="py-3 px-3 text-slate-300">
                                                        <span>{formatHandshakeRelative(peer.latest_handshake)}</span>
                                                        {peer.persistent_keepalive ? (
                                                            <span className="block text-slate-500 text-xs">
                                                                Keepalive: {peer.persistent_keepalive}s
                                                            </span>
                                                        ) : null}
                                                    </td>
                                                    <td data-label="Transfer" className="py-3 px-3 text-slate-300 font-mono text-xs">
                                                        ↓ {formatBytes(peer.transfer_rx)} &middot; ↑ {formatBytes(peer.transfer_tx)}
                                                    </td>
                                                    <td data-actions data-label="Actions" className="py-3 px-3 text-right">
                                                        <div className="inline-flex items-center gap-1">
                                                            <button
                                                                type="button"
                                                                onClick={() => openEditPeerModal(peer)}
                                                                className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center p-2 text-slate-400 hover:text-indigo-300 rounded-xl hover:bg-indigo-500/10 transition-colors"
                                                                title={`Edit peer ${peer.name || peer.public_key}`}
                                                                aria-label={`Edit peer ${peer.name || peer.public_key}`}
                                                            >
                                                                <Edit3 size={14} />
                                                            </button>
                                                            <button
                                                                type="button"
                                                                onClick={() => requestRemoveWgPeer(peer)}
                                                                className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center p-2 text-slate-400 hover:text-red-400 rounded-xl hover:bg-red-500/10 transition-colors"
                                                                title={`Remove peer ${peer.name || peer.public_key}`}
                                                                aria-label={`Remove peer ${peer.name || peer.public_key}`}
                                                            >
                                                                <Trash2 size={14} />
                                                            </button>
                                                        </div>
                                                    </td>
                                                </tr>
                                            );
                                        })
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Tailscale Section ── */}
            {activeSection === 'tailscale' && (
                <div className="space-y-6">
                    {/* Tailscale Error Banner */}
                    {tsStatus?.error && (
                        <div
                            role="alert"
                            className="rounded-2xl border border-red-500/30 bg-red-500/10 p-4 flex flex-wrap items-center justify-between gap-3 text-xs text-red-200"
                        >
                            <div className="flex items-center gap-2.5">
                                <AlertCircle size={18} className="text-red-400 shrink-0" />
                                <div>
                                    <p className="font-bold text-red-300">Tailscale Runtime Error</p>
                                    <p className="mt-0.5">{tsStatus.error}</p>
                                </div>
                            </div>
                            <button
                                type="button"
                                onClick={() => openDiagnostics('tailscale')}
                                className="obs-touch-target-standard min-h-[44px] px-3.5 py-2 rounded-xl bg-red-500/20 hover:bg-red-500/30 border border-red-500/30 text-xs font-bold text-red-100 inline-flex items-center justify-center transition-colors"
                            >
                                Inspect Diagnostics
                            </button>
                        </div>
                    )}

                    {/* Tailscale Not Installed Card */}
                    {tsState === 'not_installed' && (
                        <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-5 flex flex-wrap items-center justify-between gap-4">
                            <div className="space-y-1">
                                <h3 className="text-sm font-bold text-amber-200">Tailscale Package Not Installed</h3>
                                <p className="text-xs text-amber-100/80">
                                    Install Tailscale from the AetherFlow Marketplace to enroll this server into your tailnet mesh.
                                </p>
                            </div>
                            <button
                                type="button"
                                onClick={() => setActiveTab('marketplace')}
                                className="obs-touch-target-standard min-h-[44px] px-4 py-2 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-xs font-bold text-amber-100 inline-flex items-center justify-center gap-2 transition-colors"
                            >
                                <Store size={14} />
                                <span>Open Marketplace</span>
                            </button>
                        </div>
                    )}

                    {/* Tailscale Control Plane, Auth & Lifecycle Card */}
                    <div className="obs-canvas-section py-5 space-y-5">
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                            <div className="flex items-center gap-3">
                                <div className="h-9 w-9 bg-violet-500/20 rounded-xl flex items-center justify-center border border-violet-500/30 text-violet-400 shrink-0">
                                    <Radio size={18} />
                                </div>
                                <div>
                                    <h3 className="text-sm font-bold text-slate-200">
                                        Tailscale Node: {tsStatus?.self?.hostname || 'aetherflow-node'}
                                    </h3>
                                    {tsStatus?.tailnet_name && (
                                        <p className="text-xs text-slate-400">Tailnet: {tsStatus.tailnet_name}</p>
                                    )}
                                    <p className="text-xs text-slate-400 font-mono mt-0.5">
                                        IP: {tsStatus?.self?.tailscale_ip || 'Offline'} &middot; Backend:{' '}
                                        {tsStatus?.backend_state || tsStateBadge.label}
                                        {tsStatus?.magic_dns ? ' · MagicDNS Enabled' : ''}
                                    </p>
                                </div>
                            </div>

                            <div className="flex flex-wrap items-center gap-2">
                                <span
                                    data-testid="ts-state-badge"
                                    className={`px-3 py-1 rounded-full text-xs font-bold uppercase border flex items-center gap-1.5 ${tsStateBadge.cls}`}
                                >
                                    <span className={`w-1.5 h-1.5 rounded-full ${tsStateBadge.dot}`} />
                                    {tsStateBadge.label}
                                </span>

                                {tsState !== 'not_installed' && (
                                    <>
                                        <button
                                            type="button"
                                            disabled={isConnectingTs}
                                            onClick={() => handleTailscaleConnect(false)}
                                            className="obs-touch-target-standard min-h-[44px] px-3.5 py-2 rounded-xl bg-violet-600 hover:bg-violet-500 text-white text-xs font-bold flex items-center gap-1.5 disabled:opacity-50 transition-colors"
                                        >
                                            <Play size={12} />
                                            <span>{tsState === 'running' ? 'Reconnect' : 'Connect / Login'}</span>
                                        </button>

                                        <button
                                            type="button"
                                            disabled={isConnectingTs}
                                            onClick={() => handleTailscaleConnect(true)}
                                            className="obs-touch-target-standard min-h-[44px] px-3.5 py-2 rounded-xl bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 text-slate-200 text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50 transition-colors"
                                        >
                                            <KeyRound size={12} />
                                            <span>Reauthenticate</span>
                                        </button>

                                        {tsState === 'running' && (
                                            <button
                                                type="button"
                                                onClick={handleTailscaleDisconnect}
                                                className="obs-touch-target-standard min-h-[44px] px-3.5 py-2 rounded-xl bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-300 text-xs font-semibold flex items-center gap-1.5 transition-colors"
                                            >
                                                <Unplug size={12} />
                                                <span>Disconnect</span>
                                            </button>
                                        )}

                                        <button
                                            type="button"
                                            onClick={handleTailscaleLogout}
                                            className="obs-touch-target-standard min-h-[44px] px-3.5 py-2 rounded-xl bg-red-500/15 hover:bg-red-500/25 border border-red-500/30 text-red-300 text-xs font-semibold flex items-center gap-1.5 transition-colors"
                                        >
                                            <LogOut size={12} />
                                            <span>Logout</span>
                                        </button>
                                    </>
                                )}
                            </div>
                        </div>

                        {/* Daemon service controls */}
                        {tsState !== 'not_installed' && (
                            <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-white/[0.06] text-xs">
                                <span className="text-slate-400">
                                    Daemon Service (<code className="text-violet-300">tailscaled</code>):{' '}
                                    <strong className="text-slate-200">{tsStatus?.service_state || tsStateBadge.label}</strong>
                                </span>
                                <div className="flex flex-wrap items-center gap-1.5">
                                    <button
                                        type="button"
                                        disabled={isRunningServiceAction}
                                        onClick={() => handleServiceControl('tailscale', 'start')}
                                        className="obs-touch-target-standard min-h-[44px] px-3 py-2 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-slate-300 text-xs font-semibold inline-flex items-center justify-center transition-colors"
                                    >
                                        Start Daemon
                                    </button>
                                    <button
                                        type="button"
                                        disabled={isRunningServiceAction}
                                        onClick={() => handleServiceControl('tailscale', 'restart')}
                                        className="obs-touch-target-standard min-h-[44px] px-3 py-2 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/10 text-slate-300 text-xs font-semibold inline-flex items-center justify-center transition-colors"
                                    >
                                        Restart Daemon
                                    </button>
                                    <button
                                        type="button"
                                        disabled={isRunningServiceAction}
                                        onClick={() => handleServiceControl('tailscale', 'stop')}
                                        className="obs-touch-target-standard min-h-[44px] px-3 py-2 rounded-xl bg-red-500/10 hover:bg-red-500/20 border border-red-500/25 text-red-300 text-xs font-semibold inline-flex items-center justify-center transition-colors"
                                    >
                                        Stop Daemon
                                    </button>
                                </div>
                            </div>
                        )}

                        {/* Interactive Login / Machine Approval Banner */}
                        {(tsState === 'needs_login' || tsState === 'needs_approval' || activeAuthUrl) && (
                            <div className="rounded-xl border border-violet-500/30 bg-violet-500/10 p-4 flex flex-wrap items-center justify-between gap-3 text-xs">
                                <div className="space-y-1">
                                    <p className="font-bold text-violet-200">
                                        {tsState === 'needs_approval'
                                            ? 'Machine Approval Required in Tailscale Admin Console'
                                            : 'Tailscale Interactive Login Required'}
                                    </p>
                                    <p className="text-violet-200/80">
                                        {activeAuthUrl
                                            ? 'Open the official Tailscale authentication URL below to authorize this node, then status will update automatically.'
                                            : 'Click "Connect / Login" to generate a fresh interactive authentication link.'}
                                    </p>
                                </div>
                                {activeAuthUrl && (
                                    <a
                                        href={activeAuthUrl}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="px-4 py-2 rounded-xl bg-violet-600 hover:bg-violet-500 text-white text-xs font-bold flex items-center gap-1.5 shrink-0"
                                    >
                                        <span>Authenticate in Tailscale</span>
                                        <ExternalLink size={14} />
                                    </a>
                                )}
                            </div>
                        )}

                        {/* Health Warnings from Tailscale Daemon */}
                        {tsStatus?.health && tsStatus.health.length > 0 && (
                            <div className="rounded-xl border border-amber-500/25 bg-amber-500/10 p-3 space-y-1 text-xs text-amber-200">
                                <p className="font-bold text-amber-300">Tailscale Health Notices</p>
                                <ul className="list-disc list-inside space-y-0.5">
                                    {tsStatus.health.map((h, i) => (
                                        <li key={i}>{h}</li>
                                    ))}
                                </ul>
                            </div>
                        )}

                        {/* Advertised Subnet Routes Management */}
                        <div className="pt-4 border-t border-white/[0.06] space-y-3">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                                <label
                                    htmlFor="tailscale-routes-input"
                                    className="block text-xs font-bold text-slate-300 uppercase tracking-wider"
                                >
                                    Advertised Subnet Routes (comma-separated CIDRs)
                                </label>
                                <span className="text-xs text-amber-300/90 flex items-center gap-1">
                                    <Info size={13} />
                                    Subnet route &amp; exit-node approval is managed in the Tailscale Admin Console
                                </span>
                            </div>

                            {/* Currently advertised route pills with per-route remove + Clear All */}
                            <div className="flex flex-wrap items-center gap-2">
                                {(tsStatus?.advertised_routes ?? []).length === 0 ? (
                                    <span className="text-xs text-slate-400 italic">
                                        No subnet routes currently advertised.
                                    </span>
                                ) : (
                                    (tsStatus?.advertised_routes ?? []).map((cidr) => (
                                        <span
                                            key={cidr}
                                            className="inline-flex items-center gap-1.5 pl-3 pr-1 py-1 rounded-xl bg-violet-500/15 border border-violet-500/30 text-xs font-mono text-violet-200"
                                        >
                                            <span>{cidr}</span>
                                            <button
                                                type="button"
                                                disabled={isAdvertisingRoutes}
                                                onClick={() => handleRemoveSingleRoute(cidr)}
                                                aria-label={`Remove route ${cidr}`}
                                                className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center text-violet-300 hover:text-white rounded-lg hover:bg-violet-500/20 disabled:opacity-40 transition-colors text-base"
                                            >
                                                &times;
                                            </button>
                                        </span>
                                    ))
                                )}
                            </div>

                            <form
                                onSubmit={handleAdvertiseRoutesSubmit}
                                className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5"
                            >
                                <input
                                    id="tailscale-routes-input"
                                    type="text"
                                    value={subnetRouteInput}
                                    onChange={(e) => setSubnetRouteInput(e.target.value)}
                                    placeholder="10.0.0.0/24, 192.168.1.0/24 (leave empty to clear all)"
                                    className="obs-touch-target-standard min-h-[44px] h-11 flex-1 bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-violet-500/50"
                                />
                                <button
                                    type="submit"
                                    disabled={isAdvertisingRoutes}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] h-11 px-4 py-2 bg-violet-600 hover:bg-violet-500 disabled:opacity-50 text-white text-xs font-bold rounded-xl transition-all flex items-center justify-center gap-1.5 shrink-0"
                                >
                                    <Send size={13} />
                                    <span>{isAdvertisingRoutes ? 'Saving...' : 'Save Routes'}</span>
                                </button>
                                <button
                                    type="button"
                                    disabled={isAdvertisingRoutes}
                                    onClick={handleClearAllRoutes}
                                    className="obs-touch-target-standard obs-gpu-120hz-interactive min-h-[44px] h-11 px-3.5 py-2 bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 disabled:opacity-50 text-slate-200 text-xs font-semibold rounded-xl transition-all shrink-0 inline-flex items-center justify-center"
                                >
                                    Clear All Routes
                                </button>
                            </form>
                        </div>

                        {/* Routing & Exit Node Controls */}
                        <div className="pt-4 border-t border-white/[0.07] grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-white/[0.07] text-xs">
                            <label className="flex items-center justify-between gap-3 py-3 md:pr-4 cursor-pointer">
                                <div>
                                    <span className="font-semibold text-slate-200 block">Accept Subnet Routes</span>
                                    <span className="text-slate-400">Accept routes advertised by other tailnet nodes</span>
                                </div>
                                <input
                                    type="checkbox"
                                    aria-label="Accept Subnet Routes"
                                    checked={Boolean(tsStatus?.accept_routes)}
                                    disabled={isSavingTsSettings}
                                    onChange={(e) =>
                                        handleUpdateTailscaleSettings({ accept_routes: e.target.checked })
                                    }
                                    className="h-4 w-4 accent-violet-500 rounded"
                                />
                            </label>

                            <label className="flex items-center justify-between gap-3 py-3 md:px-4 cursor-pointer">
                                <div>
                                    <span className="font-semibold text-slate-200 block">Advertise as Exit Node</span>
                                    <span className="text-slate-400">Offer this server as a tailnet exit node</span>
                                </div>
                                <input
                                    type="checkbox"
                                    aria-label="Advertise as Exit Node"
                                    checked={Boolean(tsStatus?.advertise_exit_node)}
                                    disabled={isSavingTsSettings}
                                    onChange={(e) =>
                                        handleUpdateTailscaleSettings({ advertise_exit_node: e.target.checked })
                                    }
                                    className="h-4 w-4 accent-violet-500 rounded"
                                />
                            </label>

                            <div className="py-3 md:pl-4 space-y-2">
                                <label
                                    htmlFor="tailscale-exit-node-select"
                                    className="font-semibold text-slate-200 block"
                                >
                                    Use Peer Exit Node
                                </label>
                                <select
                                    id="tailscale-exit-node-select"
                                    aria-label="Use Peer Exit Node"
                                    value={tsStatus?.exit_node || ''}
                                    disabled={isSavingTsSettings}
                                    onChange={(e) =>
                                        handleUpdateTailscaleSettings({ exit_node: e.target.value })
                                    }
                                    className="obs-touch-target-standard min-h-[44px] h-11 w-full bg-black/60 border border-white/10 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-violet-500/50"
                                >
                                    <option value="">None (Direct Internet)</option>
                                    {exitNodeCandidates.map((peer) => (
                                        <option key={peer.id || peer.tailscale_ip} value={peer.tailscale_ip}>
                                            {peer.hostname} ({peer.tailscale_ip})
                                        </option>
                                    ))}
                                </select>
                                {tsStatus?.exit_node && (
                                    <label className="flex items-center gap-2 text-slate-300 pt-1 cursor-pointer">
                                        <input
                                            type="checkbox"
                                            aria-label="Allow LAN Access When Using Exit Node"
                                            checked={Boolean(tsStatus?.exit_node_allow_lan_access)}
                                            disabled={isSavingTsSettings}
                                            onChange={(e) =>
                                                handleUpdateTailscaleSettings({
                                                    exit_node_allow_lan_access: e.target.checked,
                                                })
                                            }
                                            className="h-3.5 w-3.5 accent-violet-500 rounded"
                                        />
                                        <span>Allow local LAN access</span>
                                    </label>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Tailscale Peers Table */}
                    <div className="obs-canvas-section py-5 min-w-0 max-w-full">
                        <div className="flex items-center justify-between mb-4 pb-3 border-b border-white/[0.06]">
                            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                                Tailnet Mesh Devices ({tsPeers.length})
                            </h4>
                            <button
                                type="button"
                                onClick={() => mutateStatus()}
                                className="obs-touch-target-standard min-h-[44px] min-w-[44px] inline-flex items-center justify-center p-2 text-slate-400 hover:text-white rounded-xl hover:bg-white/5 transition-colors"
                                title="Refresh Tailscale peers"
                                aria-label="Refresh Tailscale peers"
                            >
                                <RefreshCw size={14} />
                            </button>
                        </div>

                        <div className="overflow-x-auto min-w-0 max-w-full">
                            <table className="w-full text-left border-collapse text-xs">
                                <thead>
                                    <tr className="border-b border-white/[0.06] text-slate-400 text-xs uppercase tracking-wider">
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
                                            <td colSpan={5} className="py-12 text-center text-slate-400 text-xs">
                                                No Tailscale mesh peers discovered or Tailscale daemon offline.
                                            </td>
                                        </tr>
                                    ) : (
                                        tsPeers.map((peer) => (
                                            <tr key={peer.id || peer.tailscale_ip} className="hover:bg-white/[0.02] transition-colors">
                                                <td className="py-3 px-3 font-semibold text-slate-200 flex items-center gap-2">
                                                    <Laptop size={14} className="text-slate-500 shrink-0" />
                                                    <span>{peer.hostname}</span>
                                                    {peer.dns_name && (
                                                        <span className="text-xs text-slate-500">({peer.dns_name})</span>
                                                    )}
                                                </td>
                                                <td className="py-3 px-3 font-mono text-violet-300">
                                                    {peer.tailscale_ip}
                                                </td>
                                                <td className="py-3 px-3 text-slate-300 capitalize">
                                                    {peer.os || 'Linux'}
                                                </td>
                                                <td className="py-3 px-3">
                                                    <span
                                                        className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase ${
                                                            peer.online
                                                                ? 'bg-emerald-500/10 text-emerald-400'
                                                                : 'bg-slate-800 text-slate-400'
                                                        }`}
                                                    >
                                                        {peer.online ? 'Online' : 'Idle'}
                                                    </span>
                                                </td>
                                                <td className="py-3 px-3 text-slate-300">
                                                    {peer.exit_node ? (
                                                        <span className="text-emerald-400 font-bold">Active Exit Node</span>
                                                    ) : peer.exit_node_option ? (
                                                        <span className="text-violet-300">Available</span>
                                                    ) : (
                                                        'No'
                                                    )}
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

            {/* ── Add WireGuard Peer & One-Time Config Export Modal ── */}
            <Modal
                isOpen={showAddWgModal}
                onClose={closeAddWgModal}
                title={exportHandoff ? 'One-Time Client Configuration & QR Export' : 'Enroll WireGuard Peer'}
                className="max-w-xl"
            >
                {exportHandoff ? (
                    <div className="space-y-4 text-xs" data-testid="wg-config-handoff">
                        <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/25 text-amber-200 space-y-1">
                            <p className="font-bold text-amber-300">
                                Save Client Config Now — Private Key Is Never Stored on Server
                            </p>
                            <p>
                                Peer <strong>{exportHandoff.peer.name || 'WireGuard Client'}</strong> has been assigned{' '}
                                <code className="text-amber-100">{exportHandoff.peer.allowed_ips}</code>. Download the{' '}
                                <code>.conf</code> file or scan the QR code before closing this window.
                            </p>
                        </div>

                        {/* Live Client Config Builder Controls */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div>
                                <label
                                    htmlFor="handoff-endpoint-input"
                                    className="block text-xs font-semibold text-slate-300 mb-1"
                                >
                                    Server Endpoint (host:port)
                                </label>
                                <input
                                    id="handoff-endpoint-input"
                                    type="text"
                                    value={exportHandoff.serverEndpoint}
                                    onChange={(e) =>
                                        setExportHandoff((prev) =>
                                            prev ? { ...prev, serverEndpoint: e.target.value } : null
                                        )
                                    }
                                    className="w-full bg-black/60 border border-white/10 rounded-xl px-3 py-1.5 text-xs text-slate-100 font-mono"
                                />
                            </div>
                            <div>
                                <label
                                    htmlFor="handoff-dns-input"
                                    className="block text-xs font-semibold text-slate-300 mb-1"
                                >
                                    Client DNS Servers
                                </label>
                                <input
                                    id="handoff-dns-input"
                                    type="text"
                                    value={exportHandoff.dns}
                                    onChange={(e) =>
                                        setExportHandoff((prev) =>
                                            prev ? { ...prev, dns: e.target.value } : null
                                        )
                                    }
                                    className="w-full bg-black/60 border border-white/10 rounded-xl px-3 py-1.5 text-xs text-slate-100 font-mono"
                                />
                            </div>
                            <div>
                                <label
                                    htmlFor="handoff-tunnel-mode"
                                    className="block text-xs font-semibold text-slate-300 mb-1"
                                >
                                    Client Tunnel Routing Mode
                                </label>
                                <select
                                    id="handoff-tunnel-mode"
                                    value={exportHandoff.tunnelMode}
                                    onChange={(e) =>
                                        setExportHandoff((prev) =>
                                            prev
                                                ? { ...prev, tunnelMode: e.target.value as WireGuardTunnelMode }
                                                : null
                                        )
                                    }
                                    className="w-full bg-black/60 border border-white/10 rounded-xl px-3 py-1.5 text-xs text-slate-100"
                                >
                                    <option value="full_ipv4">IPv4 Full Tunnel (0.0.0.0/0)</option>
                                    <option value="split">Split Tunnel (VPN Subnet Only)</option>
                                </select>
                            </div>
                            {exportHandoff.tunnelMode === 'split' && (
                                <div>
                                    <label
                                        htmlFor="handoff-split-cidrs"
                                        className="block text-xs font-semibold text-slate-300 mb-1"
                                    >
                                        Split Tunnel AllowedIPs
                                    </label>
                                    <input
                                        id="handoff-split-cidrs"
                                        type="text"
                                        value={exportHandoff.splitAllowedIps}
                                        onChange={(e) =>
                                            setExportHandoff((prev) =>
                                                prev ? { ...prev, splitAllowedIps: e.target.value } : null
                                            )
                                        }
                                        className="w-full bg-black/60 border border-white/10 rounded-xl px-3 py-1.5 text-xs text-slate-100 font-mono"
                                    />
                                </div>
                            )}
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-center bg-black/40 border border-white/[0.08] rounded-xl p-4">
                            <div className="flex flex-col items-center justify-center bg-white p-3 rounded-xl mx-auto">
                                <QRCodeSVG value={exportedClientConfigText} size={160} level="M" />
                                <span className="text-xs font-semibold text-slate-800 mt-2 flex items-center gap-1">
                                    <QrCode size={13} /> Scan in WireGuard App
                                </span>
                            </div>

                            <pre
                                data-testid="wg-exported-conf"
                                className="text-xs font-mono text-slate-200 bg-black/70 p-3 rounded-xl border border-white/10 overflow-x-auto whitespace-pre-wrap break-all"
                            >
                                {exportedClientConfigText}
                            </pre>
                        </div>

                        <div className="flex flex-wrap items-center justify-end gap-2.5 pt-3 border-t border-white/10">
                            <button
                                type="button"
                                onClick={handleCopyConfig}
                                className="px-3.5 py-2 rounded-xl bg-white/[0.06] hover:bg-white/[0.12] border border-white/10 text-xs font-bold text-slate-200 flex items-center gap-1.5"
                            >
                                {copiedConfig ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                                <span>{copiedConfig ? 'Copied' : 'Copy .conf'}</span>
                            </button>
                            <button
                                type="button"
                                onClick={handleDownloadConfig}
                                className="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-xs font-bold text-white flex items-center gap-1.5"
                            >
                                <Download size={14} />
                                <span>Download .conf</span>
                            </button>
                            <button
                                type="button"
                                onClick={closeAddWgModal}
                                className="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-xs font-bold text-white"
                            >
                                Done &amp; Purge Key
                            </button>
                        </div>
                    </div>
                ) : (
                    <form onSubmit={handleAddWgPeer} className="space-y-4 text-xs">
                        <div>
                            <label htmlFor="wg-peer-name" className="block text-xs font-semibold text-slate-300 mb-1">
                                Peer Friendly Name
                            </label>
                            <input
                                id="wg-peer-name"
                                type="text"
                                value={newPeerName}
                                onChange={(e) => setNewPeerName(e.target.value)}
                                placeholder="e.g. MacBook-Pro, Pixel-9"
                                required
                                className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs focus:outline-none focus:border-indigo-500/50"
                            />
                        </div>

                        <div>
                            <div className="flex items-center justify-between mb-1">
                                <label htmlFor="wg-peer-pubkey" className="text-xs font-semibold text-slate-300">
                                    Client Public Key
                                </label>
                                <button
                                    type="button"
                                    onClick={handleKeygen}
                                    disabled={isGeneratingKeys}
                                    className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-bold"
                                >
                                    <KeyRound size={12} />
                                    {isGeneratingKeys ? 'Generating...' : 'Generate Keypair'}
                                </button>
                            </div>
                            <input
                                id="wg-peer-pubkey"
                                type="text"
                                value={newPeerPubKey}
                                onChange={(e) => handlePublicKeyInputChange(e.target.value)}
                                placeholder="Base64 public key (44 characters)"
                                required
                                className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs font-mono focus:outline-none focus:border-indigo-500/50"
                            />
                        </div>

                        {generatedPrivKey && (
                            <div
                                data-testid="ephemeral-private-key-box"
                                className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl space-y-1"
                            >
                                <div className="text-xs font-bold text-amber-400 uppercase tracking-wider">
                                    Client Private Key (Ephemeral — Never Stored on Server)
                                </div>
                                <div className="text-xs font-mono text-slate-200 select-all break-all">
                                    {generatedPrivKey}
                                </div>
                            </div>
                        )}

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div>
                                <label
                                    htmlFor="wg-peer-allowed-ips"
                                    className="block text-xs font-semibold text-slate-300 mb-1"
                                >
                                    Tunnel Address (blank = auto-allocate)
                                </label>
                                <input
                                    id="wg-peer-allowed-ips"
                                    type="text"
                                    value={newPeerAllowedIPs}
                                    onChange={(e) => setNewPeerAllowedIPs(e.target.value)}
                                    placeholder={networkStatus?.wireguard?.next_ip || 'Auto-allocate /32'}
                                    className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs font-mono focus:outline-none focus:border-indigo-500/50"
                                />
                            </div>

                            <div>
                                <label
                                    htmlFor="wg-peer-keepalive"
                                    className="block text-xs font-semibold text-slate-300 mb-1"
                                >
                                    Persistent Keepalive (seconds)
                                </label>
                                <input
                                    id="wg-peer-keepalive"
                                    type="number"
                                    min={0}
                                    max={65535}
                                    value={newPeerKeepalive}
                                    onChange={(e) => setNewPeerKeepalive(e.target.value)}
                                    className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs font-mono focus:outline-none focus:border-indigo-500/50"
                                />
                            </div>
                        </div>

                        <div>
                            <label htmlFor="wg-peer-endpoint" className="block text-xs font-semibold text-slate-300 mb-1">
                                Optional Peer Endpoint (for static peers)
                            </label>
                            <input
                                id="wg-peer-endpoint"
                                type="text"
                                value={newPeerEndpoint}
                                onChange={(e) => setNewPeerEndpoint(e.target.value)}
                                placeholder="client.example.com:51820"
                                className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs font-mono focus:outline-none focus:border-indigo-500/50"
                            />
                        </div>

                        {/* Client Config Options when using generated keypair */}
                        <div className="pt-3 border-t border-white/10 space-y-3">
                            <p className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                                <FileCode2 size={14} className="text-indigo-400" />
                                Client Config Export Defaults (Used if Keypair Generated Above)
                            </p>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <div>
                                    <label
                                        htmlFor="wg-client-server-endpoint"
                                        className="block text-xs font-semibold text-slate-300 mb-1"
                                    >
                                        Server Public Endpoint
                                    </label>
                                    <input
                                        id="wg-client-server-endpoint"
                                        type="text"
                                        value={clientServerEndpoint}
                                        onChange={(e) => setClientServerEndpoint(e.target.value)}
                                        placeholder="vpn.example.com:51820"
                                        className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-3 py-1.5 text-slate-100 text-xs font-mono"
                                    />
                                </div>
                                <div>
                                    <label
                                        htmlFor="wg-client-dns"
                                        className="block text-xs font-semibold text-slate-300 mb-1"
                                    >
                                        Client DNS
                                    </label>
                                    <input
                                        id="wg-client-dns"
                                        type="text"
                                        value={clientDns}
                                        onChange={(e) => setClientDns(e.target.value)}
                                        placeholder="1.1.1.1, 9.9.9.9"
                                        className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-3 py-1.5 text-slate-100 text-xs font-mono"
                                    />
                                </div>
                                <div>
                                    <label
                                        htmlFor="wg-client-tunnel-mode"
                                        className="block text-xs font-semibold text-slate-300 mb-1"
                                    >
                                        Tunnel Scope
                                    </label>
                                    <select
                                        id="wg-client-tunnel-mode"
                                        value={clientTunnelMode}
                                        onChange={(e) => setClientTunnelMode(e.target.value as WireGuardTunnelMode)}
                                        className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-3 py-1.5 text-slate-100 text-xs"
                                    >
                                        <option value="full_ipv4">IPv4 Full Tunnel (0.0.0.0/0)</option>
                                        <option value="split">Split Tunnel (Subnet Only)</option>
                                    </select>
                                </div>
                                {clientTunnelMode === 'split' && (
                                    <div>
                                        <label
                                            htmlFor="wg-client-split-cidrs"
                                            className="block text-xs font-semibold text-slate-300 mb-1"
                                        >
                                            Split AllowedIPs
                                        </label>
                                        <input
                                            id="wg-client-split-cidrs"
                                            type="text"
                                            value={clientSplitCidrs}
                                            onChange={(e) => setClientSplitCidrs(e.target.value)}
                                            className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-3 py-1.5 text-slate-100 text-xs font-mono"
                                        />
                                    </div>
                                )}
                            </div>
                        </div>

                        <div className="flex justify-end gap-2.5 pt-4 border-t border-white/[0.06]">
                            <button
                                type="button"
                                onClick={closeAddWgModal}
                                className="px-4 py-2 text-xs font-bold text-slate-400 hover:text-white rounded-xl transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                type="submit"
                                disabled={isSubmittingPeer || isGeneratingKeys || !newPeerPubKey.trim()}
                                className="obs-touch-target-standard obs-gpu-120hz-interactive px-5 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-xs font-bold text-white rounded-xl transition-all shadow-lg shadow-indigo-500/20"
                            >
                                {isSubmittingPeer ? 'Adding Peer...' : 'Enroll Peer'}
                            </button>
                        </div>
                    </form>
                )}
            </Modal>

            {/* ── Edit Existing WireGuard Peer Modal ── */}
            <Modal
                isOpen={Boolean(editingPeer)}
                onClose={() => setEditingPeer(null)}
                title="Edit WireGuard Peer"
            >
                {editingPeer && (
                    <form onSubmit={handleUpdateWgPeer} className="space-y-4 text-xs">
                        <div>
                            <label className="block text-xs font-semibold text-slate-400 mb-1">
                                Public Key (Immutable)
                            </label>
                            <input
                                type="text"
                                value={editingPeer.public_key}
                                disabled
                                className="w-full bg-black/40 border border-white/[0.06] rounded-xl px-4 py-2 text-slate-400 text-xs font-mono cursor-not-allowed"
                            />
                        </div>

                        <div>
                            <label htmlFor="edit-wg-peer-name" className="block text-xs font-semibold text-slate-300 mb-1">
                                Peer Friendly Name
                            </label>
                            <input
                                id="edit-wg-peer-name"
                                type="text"
                                value={editPeerName}
                                onChange={(e) => setEditPeerName(e.target.value)}
                                required
                                className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs"
                            />
                        </div>

                        <div>
                            <label htmlFor="edit-wg-peer-ips" className="block text-xs font-semibold text-slate-300 mb-1">
                                Allowed IPs
                            </label>
                            <input
                                id="edit-wg-peer-ips"
                                type="text"
                                value={editPeerAllowedIPs}
                                onChange={(e) => setEditPeerAllowedIPs(e.target.value)}
                                required
                                className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs font-mono"
                            />
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div>
                                <label htmlFor="edit-wg-peer-endpoint" className="block text-xs font-semibold text-slate-300 mb-1">
                                    Endpoint
                                </label>
                                <input
                                    id="edit-wg-peer-endpoint"
                                    type="text"
                                    value={editPeerEndpoint}
                                    onChange={(e) => setEditPeerEndpoint(e.target.value)}
                                    placeholder="Roaming"
                                    className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs font-mono"
                                />
                            </div>
                            <div>
                                <label htmlFor="edit-wg-peer-keepalive" className="block text-xs font-semibold text-slate-300 mb-1">
                                    Persistent Keepalive (s)
                                </label>
                                <input
                                    id="edit-wg-peer-keepalive"
                                    type="number"
                                    min={0}
                                    max={65535}
                                    value={editPeerKeepalive}
                                    onChange={(e) => setEditPeerKeepalive(e.target.value)}
                                    className="w-full bg-black/60 border border-white/[0.08] rounded-xl px-4 py-2 text-slate-100 text-xs font-mono"
                                />
                            </div>
                        </div>

                        <div className="p-3 rounded-xl bg-white/[0.03] border border-white/[0.06] text-slate-400">
                            Keys generated here are returned once and are not saved by AetherFlow. To generate a new downloadable config for a lost device key, remove this peer and enroll a new keypair.
                        </div>

                        <div className="flex justify-end gap-2.5 pt-3 border-t border-white/10">
                            <button
                                type="button"
                                onClick={() => setEditingPeer(null)}
                                className="px-4 py-2 text-xs font-bold text-slate-400 hover:text-white rounded-xl"
                            >
                                Cancel
                            </button>
                            <button
                                type="submit"
                                disabled={isUpdatingPeer}
                                className="px-5 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-xs font-bold text-white rounded-xl"
                            >
                                {isUpdatingPeer ? 'Saving...' : 'Save Changes'}
                            </button>
                        </div>
                    </form>
                )}
            </Modal>

            {/* ── Bounded Diagnostics Modal ── */}
            <Modal
                isOpen={showDiagnosticsModal}
                onClose={() => setShowDiagnosticsModal(false)}
                title={`Network Diagnostics (${diagnosticsProvider === 'wireguard' ? 'WireGuard' : 'Tailscale'})`}
                className="max-w-2xl"
            >
                <div className="space-y-4 text-xs">
                    <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5">
                            <button
                                type="button"
                                onClick={() => openDiagnostics('wireguard')}
                                className={`px-3 py-1.5 rounded-lg text-xs font-bold ${
                                    diagnosticsProvider === 'wireguard'
                                        ? 'bg-indigo-600 text-white'
                                        : 'bg-white/[0.05] text-slate-300'
                                }`}
                            >
                                WireGuard
                            </button>
                            <button
                                type="button"
                                onClick={() => openDiagnostics('tailscale')}
                                className={`px-3 py-1.5 rounded-lg text-xs font-bold ${
                                    diagnosticsProvider === 'tailscale'
                                        ? 'bg-violet-600 text-white'
                                        : 'bg-white/[0.05] text-slate-300'
                                }`}
                            >
                                Tailscale
                            </button>
                        </div>
                        <button
                            type="button"
                            onClick={() => openDiagnostics(diagnosticsProvider)}
                            className="px-3 py-1.5 rounded-lg bg-white/[0.06] hover:bg-white/[0.12] text-slate-200 font-semibold flex items-center gap-1.5"
                        >
                            <RefreshCw size={12} className={isLoadingDiagnostics ? 'animate-spin' : ''} />
                            <span>Reload</span>
                        </button>
                    </div>

                    {isLoadingDiagnostics && (
                        <div className="p-4 rounded-xl bg-black/40 border border-white/10 text-slate-300 flex items-center gap-2">
                            <RefreshCw size={14} className="animate-spin text-indigo-400" />
                            <span>Collecting bounded service checks and sanitized logs...</span>
                        </div>
                    )}

                    {diagnosticsError && (
                        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-200">
                            {diagnosticsError}
                        </div>
                    )}

                    {diagnosticsData && !isLoadingDiagnostics && (
                        <div className="space-y-4">
                            <div className="flex items-center justify-between p-3 rounded-xl bg-black/40 border border-white/10">
                                <span className="text-slate-400">Service State:</span>
                                <span className="font-mono font-bold text-slate-100">
                                    {diagnosticsData.service_state}
                                </span>
                            </div>

                            {diagnosticsData.checks && diagnosticsData.checks.length > 0 && (
                                <div className="space-y-2">
                                    <h4 className="font-bold text-slate-300 uppercase tracking-wider">Health Checks</h4>
                                    <div className="space-y-1.5">
                                        {diagnosticsData.checks.map((chk, idx) => {
                                            const passed =
                                                chk.ok ?? chk.passed ?? (chk.status === 'ok' || chk.status === 'pass');
                                            return (
                                                <div
                                                    key={idx}
                                                    className="p-2.5 rounded-xl bg-black/40 border border-white/[0.06] flex items-center justify-between gap-3"
                                                >
                                                    <div className="flex items-center gap-2">
                                                        {passed ? (
                                                            <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                                                        ) : (
                                                            <XCircle size={14} className="text-amber-400 shrink-0" />
                                                        )}
                                                        <span className="font-semibold text-slate-200">
                                                            {chk.name || chk.check || `Check #${idx + 1}`}
                                                        </span>
                                                    </div>
                                                    <span className="text-slate-400 font-mono">
                                                        {chk.detail || chk.message || chk.status || (passed ? 'OK' : 'WARN')}
                                                    </span>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </div>
                            )}

                            <div className="space-y-1.5">
                                <h4 className="font-bold text-slate-300 uppercase tracking-wider">
                                    Bounded Service Logs (Sanitized)
                                </h4>
                                <pre className="p-3 rounded-xl bg-black/70 border border-white/10 font-mono text-xs text-slate-200 max-h-64 overflow-y-auto whitespace-pre-wrap break-all">
                                    {diagnosticsData.logs || 'No recent log lines available.'}
                                </pre>
                            </div>
                        </div>
                    )}
                </div>
            </Modal>

            {/* ── Disruptive Action Confirmation Modal ── */}
            <Modal
                isOpen={Boolean(pendingConfirm)}
                onClose={() => setPendingConfirm(null)}
                title={pendingConfirm?.title || 'Confirm Action'}
            >
                {pendingConfirm && (
                    <div className="space-y-4 text-xs">
                        <p className="text-slate-300 leading-relaxed">{pendingConfirm.description}</p>
                        <div className="flex justify-end gap-2.5 pt-3 border-t border-white/10">
                            <button
                                type="button"
                                onClick={() => setPendingConfirm(null)}
                                className="px-4 py-2 text-xs font-bold text-slate-400 hover:text-white rounded-xl"
                            >
                                Cancel
                            </button>
                            <button
                                type="button"
                                onClick={async () => {
                                    const action = pendingConfirm.onConfirm;
                                    setPendingConfirm(null);
                                    await action();
                                }}
                                className={`px-5 py-2 text-xs font-bold text-white rounded-xl ${
                                    pendingConfirm.danger
                                        ? 'bg-red-600 hover:bg-red-500'
                                        : 'bg-indigo-600 hover:bg-indigo-500'
                                }`}
                            >
                                {pendingConfirm.confirmLabel}
                            </button>
                        </div>
                    </div>
                )}
            </Modal>
        </div>
    );
}
