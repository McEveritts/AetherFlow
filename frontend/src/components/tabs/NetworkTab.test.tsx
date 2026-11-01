import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import useSWR from 'swr';
import NetworkTab from '@/components/tabs/NetworkTab';
import {
    resolveWireGuardState,
    resolveTailscaleState,
    isWireGuardPeerActive,
    computeTransferRates,
    buildWireGuardClientConfig,
    deriveDefaultSplitSubnet,
    isValidSafeHttpsUrl,
    NetworkStatusResponse,
} from '@/lib/network';
import { useSystemStore } from '@/store/useSystemStore';

const mockAddToast = jest.fn();

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
    }),
}));

jest.mock('swr', () => jest.fn());

const mockedUseSWR = useSWR as jest.Mock;

function makeRunningStatusFixture(overrides?: Partial<NetworkStatusResponse>): NetworkStatusResponse {
    const nowEpoch = Math.floor(Date.now() / 1000);
    return {
        platform: 'linux',
        runner_available: true,
        checked_at: new Date().toISOString(),
        wireguard_available: true,
        tailscale_available: true,
        wireguard: {
            installed: true,
            state: 'running',
            interface: 'wg0',
            public_key: 'SERVER_PUB_KEY_BASE64_44_CHARS_1234567890=',
            listen_port: '51820',
            address: ['10.66.66.1/24'],
            next_ip: '10.66.66.2/32',
            service_state: 'active',
            config_available: true,
            peers: [
                {
                    name: 'Active-Laptop',
                    public_key: 'PEER_ACTIVE_PUB_KEY_11111111111111111111111=',
                    allowed_ips: '10.66.66.2/32',
                    endpoint: '198.51.100.10:51820',
                    latest_handshake: String(nowEpoch - 30),
                    transfer_rx: '1048576',
                    transfer_tx: '2097152',
                    active: true,
                    persistent_keepalive: 25,
                },
                {
                    name: 'Zero-Epoch-Peer',
                    public_key: 'PEER_ZERO_PUB_KEY_2222222222222222222222222=',
                    allowed_ips: '10.66.66.3/32',
                    endpoint: '',
                    latest_handshake: '0',
                    transfer_rx: '0',
                    transfer_tx: '0',
                    active: false,
                },
                {
                    name: 'Stale-Epoch-Peer',
                    public_key: 'PEER_STALE_PUB_KEY_333333333333333333333333=',
                    allowed_ips: '10.66.66.4/32',
                    endpoint: '198.51.100.20:51820',
                    latest_handshake: String(nowEpoch - 7200),
                    transfer_rx: '4096',
                    transfer_tx: '8192',
                    active: false,
                },
            ],
        },
        tailscale: {
            installed: true,
            state: 'running',
            backend_state: 'Running',
            tailnet_name: 'example.tailnet.test',
            magic_dns: true,
            health: [],
            advertised_routes: ['10.66.66.0/24', '192.168.1.0/24'],
            accept_routes: true,
            advertise_exit_node: false,
            exit_node: '',
            exit_node_allow_lan_access: false,
            route_approval: 'managed_in_admin_console',
            service_state: 'active',
            self: {
                id: 'self-node',
                hostname: 'aetherflow-core',
                dns_name: 'aetherflow-core.tailnet.ts.net',
                tailscale_ip: '100.64.0.1',
                tailscale_ips: ['100.64.0.1'],
                os: 'linux',
                online: true,
                exit_node: false,
            },
            peers: [
                {
                    id: 'peer-exit-1',
                    hostname: 'fra-exit-01',
                    dns_name: 'fra-exit-01.tailnet.ts.net',
                    tailscale_ip: '100.64.0.20',
                    tailscale_ips: ['100.64.0.20'],
                    os: 'linux',
                    online: true,
                    exit_node: false,
                    exit_node_option: true,
                    rx_bytes: 4096,
                    tx_bytes: 8192,
                },
            ],
        },
        ...overrides,
    };
}

describe('Network Helpers (frontend/src/lib/network.ts)', () => {
    it('never infers running state from *_available alone when interface/daemon is down', () => {
        const falsePositivePayload: NetworkStatusResponse = {
            platform: 'linux',
            wireguard_available: true,
            tailscale_available: true,
            wireguard: undefined,
            tailscale: undefined,
        };
        expect(resolveWireGuardState(falsePositivePayload)).toBe('stopped');
        expect(resolveTailscaleState(falsePositivePayload)).toBe('stopped');
    });

    it('counts only recent numeric handshakes as active and rejects "0", "Never", or stale epochs', () => {
        const now = 1_700_000_000;
        expect(
            isWireGuardPeerActive(
                { public_key: 'k1', allowed_ips: '10.66.66.2/32', latest_handshake: '0', active: true },
                now
            )
        ).toBe(false);
        expect(
            isWireGuardPeerActive(
                { public_key: 'k2', allowed_ips: '10.66.66.3/32', latest_handshake: 'Never' },
                now
            )
        ).toBe(false);
        expect(
            isWireGuardPeerActive(
                { public_key: 'k3', allowed_ips: '10.66.66.4/32', latest_handshake: String(now - 600) },
                now
            )
        ).toBe(false);
        expect(
            isWireGuardPeerActive(
                { public_key: 'k4', allowed_ips: '10.66.66.5/32', latest_handshake: String(now - 45) },
                now
            )
        ).toBe(true);
    });

    it('computes true byte delta transfer rates and handles counter resets gracefully', () => {
        const prev = { timestampMs: 10_000, rxBytes: 1000, txBytes: 2000 };
        const curr = { timestampMs: 20_000, rxBytes: 11_000, txBytes: 22_000 };
        const rate = computeTransferRates(prev, curr);
        expect(rate.counterReset).toBe(false);
        expect(rate.rxRateBytesPerSec).toBeCloseTo(1000);
        expect(rate.txRateBytesPerSec).toBeCloseTo(2000);

        const resetCurr = { timestampMs: 30_000, rxBytes: 500, txBytes: 100 };
        const afterReset = computeTransferRates(curr, resetCurr);
        expect(afterReset.counterReset).toBe(true);
        expect(afterReset.rxRateBytesPerSec).toBe(0);
        expect(afterReset.txRateBytesPerSec).toBe(0);
    });

    it('builds IPv4 full-tunnel client config without claiming IPv6 ::/0 by default', () => {
        const conf = buildWireGuardClientConfig({
            clientPrivateKey: 'CLIENT_PRIV_KEY_SECRET=',
            clientAddress: '10.66.66.9/32',
            serverPublicKey: 'SERVER_PUB_KEY=',
            serverEndpoint: 'vpn.aetherflow.io:51820',
            dns: '1.1.1.1',
            tunnelMode: 'full_ipv4',
            persistentKeepalive: 25,
        });
        expect(conf).toContain('PrivateKey = CLIENT_PRIV_KEY_SECRET=');
        expect(conf).toContain('Address = 10.66.66.9/32');
        expect(conf).toContain('AllowedIPs = 0.0.0.0/0');
        expect(conf).toContain('\n[Peer]\n');
        expect(conf).not.toContain(String.fromCharCode(92) + 'n');
        expect(conf).not.toContain('::/0');
    });

    it('uses actual subnet masks and only accepts the Tailscale authorization origin', () => {
        expect(deriveDefaultSplitSubnet(['10.66.67.1/16'])).toBe('10.66.0.0/16');
        expect(deriveDefaultSplitSubnet(['10.66.67.129/25'])).toBe('10.66.67.128/25');
        expect(isValidSafeHttpsUrl('https://login.tailscale.com/a/example')).toBe(true);
        expect(isValidSafeHttpsUrl('https://attacker.example/a/example')).toBe(false);
        expect(isValidSafeHttpsUrl('https://user@login.tailscale.com/a/example')).toBe(false);
    });

    it('strips config directive control characters while preserving valid disabled keepalive', () => {
        const config = buildWireGuardClientConfig({
            clientPrivateKey: 'CLIENT_KEY', clientAddress: '10.66.66.5/32',
            serverPublicKey: 'SERVER_KEY',
            serverEndpoint: 'vpn.example:51820\nPostUp = unwanted',
            dns: '1.1.1.1\r\nPreUp = unwanted',
            tunnelMode: 'split', splitAllowedIps: '10.66.0.0/16\u0000\nPostDown = unwanted',
            persistentKeepalive: 0,
        });
        expect(config).not.toContain('\nPostUp');
        expect(config).not.toContain('\nPreUp');
        expect(config).not.toContain('\nPostDown');
        expect(config).not.toContain('\r');
        expect(config).not.toContain(String.fromCharCode(0));
        expect(config).toContain('PersistentKeepalive = 0\n');
    });
});

describe('NetworkTab Component Integration & Real API Flows', () => {
    let mutateMock: jest.Mock;
    let fetchSpy: jest.SpyInstance;

    beforeEach(() => {
        jest.clearAllMocks();
        mutateMock = jest.fn().mockResolvedValue(undefined);
        useSystemStore.setState({ activeTab: 'network' });
        if (typeof document !== 'undefined') {
            document.cookie = 'csrf_token=test-csrf-token';
        }
        fetchSpy = jest.spyOn(globalThis, 'fetch');
    });

    afterEach(() => {
        fetchSpy.mockRestore();
    });

    it('uses a single unified /api/v1/admin/network/status SWR subscription and avoids duplicate peer polling', () => {
        const swrKeys: string[] = [];
        const fixture = makeRunningStatusFixture();
        mockedUseSWR.mockImplementation((key: string) => {
            swrKeys.push(key);
            return {
                data: fixture,
                isLoading: false,
                isValidating: false,
                mutate: mutateMock,
            };
        });

        render(<NetworkTab />);
        expect(Array.from(new Set(swrKeys))).toEqual(['/api/v1/admin/network/status']);
        expect(swrKeys.some((k) => k.includes('/wireguard/peers') || k.includes('/tailscale/peers'))).toBe(false);
        // Only 1 of the 3 peers has a recent handshake; "0" and stale epoch are excluded
        expect(screen.getByTestId('active-wg-peers-count')).toHaveTextContent('1');
    });

    it('displays truthful non-running state and runner warning when wireguard_available is true but state is stopped/error', () => {
        const fixture = makeRunningStatusFixture({
            runner_available: false,
            wireguard: {
                installed: true,
                state: 'error',
                error: 'Permission denied reading wg0 via af-runner',
                interface: 'wg0',
                public_key: '',
                listen_port: '51820',
                peers: [],
            },
        });
        mockedUseSWR.mockReturnValue({
            data: fixture,
            isLoading: false,
            isValidating: false,
            mutate: mutateMock,
        });

        render(<NetworkTab />);
        expect(screen.getByTestId('wg-state-badge')).toHaveTextContent(/Error/i);
        expect(screen.getByText(/Permission denied reading wg0 via af-runner/i)).toBeInTheDocument();
        expect(screen.getByText(/Privileged Runner Unavailable/i)).toBeInTheDocument();
    });

    it('purges ephemeral private key on Cancel/Escape and never retains it when reopening Add Peer modal', async () => {
        const fixture = makeRunningStatusFixture();
        mockedUseSWR.mockReturnValue({
            data: fixture,
            isLoading: false,
            isValidating: false,
            mutate: mutateMock,
        });

        fetchSpy.mockImplementation(async (input: RequestInfo | URL) => {
            const url = String(input);
            if (url.includes('/wireguard/keygen')) {
                return new Response(
                    JSON.stringify({
                        private_key: 'SUPER_SECRET_EPHEMERAL_PRIV_KEY=',
                        public_key: 'GENERATED_CLIENT_PUB_KEY_12345=',
                    }),
                    { status: 200, headers: { 'Content-Type': 'application/json' } }
                );
            }
            return new Response(JSON.stringify({}), { status: 200 });
        });

        render(<NetworkTab />);
        fireEvent.click(screen.getByRole('button', { name: /Add Peer/i }));

        fireEvent.click(screen.getByRole('button', { name: /Generate Keypair/i }));

        await waitFor(() => {
            expect(screen.getByTestId('ephemeral-private-key-box')).toHaveTextContent(
                'SUPER_SECRET_EPHEMERAL_PRIV_KEY='
            );
        });

        // Cancel modal and verify secret is wiped when reopened
        fireEvent.click(screen.getByRole('button', { name: /^Cancel$/i }));
        expect(screen.queryByTestId('ephemeral-private-key-box')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Add Peer/i }));
        expect(screen.queryByTestId('ephemeral-private-key-box')).not.toBeInTheDocument();
        expect(screen.getByLabelText(/Client Public Key/i)).toHaveValue('');
    });

    it('completes WireGuard keygen + peer enrollment and preserves one-time browser .conf + QR handoff until closed', async () => {
        const fixture = makeRunningStatusFixture();
        fixture.wireguard!.address = ['10.66.67.1/16'];
        mockedUseSWR.mockReturnValue({
            data: fixture,
            isLoading: false,
            isValidating: false,
            mutate: mutateMock,
        });

        let enrolledBody: Record<string, unknown> | null = null;
        fetchSpy.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            if (url.includes('/wireguard/keygen')) {
                return new Response(
                    JSON.stringify({
                        private_key: 'ONE_TIME_CLIENT_PRIVATE_KEY_XYZ=',
                        public_key: 'ONE_TIME_CLIENT_PUBLIC_KEY_ABC=',
                    }),
                    { status: 200, headers: { 'Content-Type': 'application/json' } }
                );
            }
            if (url.includes('/wireguard/peers') && init?.method === 'POST') {
                enrolledBody = JSON.parse(String(init.body));
                return new Response(
                    JSON.stringify({
                        message: 'Peer persisted to wg0',
                        peer: {
                            name: 'Field-iPhone',
                            public_key: 'ONE_TIME_CLIENT_PUBLIC_KEY_ABC=',
                            allowed_ips: '10.66.66.9/32',
                            persistent_keepalive: 25,
                        },
                    }),
                    { status: 200, headers: { 'Content-Type': 'application/json' } }
                );
            }
            return new Response(JSON.stringify({}), { status: 200 });
        });

        render(<NetworkTab />);
        fireEvent.click(screen.getByRole('button', { name: /Add Peer/i }));

        fireEvent.change(screen.getByLabelText(/Peer Friendly Name/i), {
            target: { value: 'Field-iPhone' },
        });
        // Clear Allowed IPs to verify automatic /32 allocation request
        fireEvent.change(screen.getByLabelText(/Tunnel Address/i), {
            target: { value: '' },
        });

        fireEvent.click(screen.getByRole('button', { name: /Generate Keypair/i }));
        await waitFor(() => {
            expect(screen.getByLabelText(/Client Public Key/i)).toHaveValue('ONE_TIME_CLIENT_PUBLIC_KEY_ABC=');
        });

        fireEvent.click(screen.getByRole('button', { name: /Enroll Peer/i }));

        await waitFor(() => {
            expect(screen.getByTestId('wg-config-handoff')).toBeInTheDocument();
        });

        expect(enrolledBody).toMatchObject({
            name: 'Field-iPhone',
            public_key: 'ONE_TIME_CLIENT_PUBLIC_KEY_ABC=',
            persistent_keepalive: 25,
        });
        // Blank allowed_ips is omitted so backend allocates next unused /32
        expect(enrolledBody).not.toHaveProperty('allowed_ips');

        const exportedConf = screen.getByTestId('wg-exported-conf');
        expect(exportedConf).toHaveTextContent('PrivateKey = ONE_TIME_CLIENT_PRIVATE_KEY_XYZ=');
        expect(exportedConf).toHaveTextContent('Address = 10.66.66.9/32');
        expect(exportedConf).toHaveTextContent('PublicKey = SERVER_PUB_KEY_BASE64_44_CHARS_1234567890=');
        expect(exportedConf).toHaveTextContent('AllowedIPs = 0.0.0.0/0');

        // Switch to Split Tunnel in live handoff view and verify config updates
        fireEvent.change(screen.getByLabelText(/Client Tunnel Routing Mode/i), {
            target: { value: 'split' },
        });
        expect(exportedConf).toHaveTextContent('AllowedIPs = 10.66.0.0/16');
        fireEvent.change(screen.getByLabelText(/Split Tunnel AllowedIPs/i), { target: { value: '' } });
        expect(exportedConf).toHaveTextContent('AllowedIPs = 10.66.0.0/16');

        // Close handoff and confirm secret is purged
        fireEvent.click(screen.getByRole('button', { name: /Done & Purge Key/i }));
        expect(screen.queryByTestId('wg-config-handoff')).not.toBeInTheDocument();
    });

    it('discards an in-flight key generation after the enrollment modal is cancelled', async () => {
        mockedUseSWR.mockReturnValue({
            data: makeRunningStatusFixture(), isLoading: false,
            isValidating: false, mutate: mutateMock,
        });
        let complete: (response: Response) => void = () => undefined;
        fetchSpy.mockImplementation(() => new Promise<Response>((resolve) => { complete = resolve; }));
        render(<NetworkTab />);
        fireEvent.click(screen.getByRole('button', { name: /Add Peer/i }));
        fireEvent.click(screen.getByRole('button', { name: /Generate Keypair/i }));
        await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
        fireEvent.click(screen.getByRole('button', { name: /^Cancel$/i }));
        await act(async () => {
            complete(new Response(JSON.stringify({
                private_key: 'LATE_PRIVATE_KEY_MUST_BE_DISCARDED',
                public_key: 'LATE_PUBLIC_KEY',
            }), { status: 200 }));
        });
        fireEvent.click(screen.getByRole('button', { name: /Add Peer/i }));
        expect(screen.queryByTestId('ephemeral-private-key-box')).not.toBeInTheDocument();
        expect(screen.getByLabelText(/Client Public Key/i)).toHaveValue('');
    });

    it('surfaces backend { code, message } errors on failed mutations (e.g., 409 duplicate peer key)', async () => {
        const fixture = makeRunningStatusFixture();
        mockedUseSWR.mockReturnValue({
            data: fixture,
            isLoading: false,
            isValidating: false,
            mutate: mutateMock,
        });

        fetchSpy.mockImplementation(async () => {
            return new Response(
                JSON.stringify({
                    code: 'CONFLICT',
                    message: 'WireGuard peer public key already exists on wg0',
                }),
                { status: 409, headers: { 'Content-Type': 'application/json' } }
            );
        });

        render(<NetworkTab />);
        fireEvent.click(screen.getByRole('button', { name: /Add Peer/i }));
        fireEvent.change(screen.getByLabelText(/Peer Friendly Name/i), { target: { value: 'Dup-Peer' } });
        fireEvent.change(screen.getByLabelText(/Client Public Key/i), {
            target: { value: 'PEER_ACTIVE_PUB_KEY_11111111111111111111111=' },
        });

        fireEvent.click(screen.getByRole('button', { name: /Enroll Peer/i }));

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith(
                'WireGuard peer public key already exists on wg0 (CONFLICT)',
                'error'
            );
        });
    });

    it('supports editing and removing a WireGuard peer, confirming disruptive service actions, and viewing bounded diagnostics', async () => {
        const fixture = makeRunningStatusFixture();
        mockedUseSWR.mockReturnValue({
            data: fixture,
            isLoading: false,
            isValidating: false,
            mutate: mutateMock,
        });

        const calls: Array<{ url: string; method?: string; body?: unknown }> = [];
        fetchSpy.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            const body = init?.body ? JSON.parse(String(init.body)) : undefined;
            calls.push({ url, method: init?.method, body });

            if (url.includes('/diagnostics')) {
                return new Response(
                    JSON.stringify({
                        provider: 'wireguard',
                        service_state: 'active (running)',
                        logs: 'Nov 01 wg-quick[102]: wg0 interface up',
                        checks: [{ name: 'UDP 51820 Reachable', ok: true, detail: 'Listening' }],
                    }),
                    { status: 200, headers: { 'Content-Type': 'application/json' } }
                );
            }
            return new Response(JSON.stringify({ message: 'Success' }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            });
        });

        render(<NetworkTab />);

        // Edit first peer
        fireEvent.click(screen.getByRole('button', { name: /Edit peer Active-Laptop/i }));
        fireEvent.change(screen.getByLabelText(/Peer Friendly Name/i), {
            target: { value: 'Renamed-Laptop' },
        });
        fireEvent.change(screen.getByLabelText(/Persistent Keepalive/i), { target: { value: '' } });
        fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }));

        await waitFor(() => {
            expect(
                calls.some(
                    (c) =>
                        c.method === 'PUT' &&
                        c.url.includes('/wireguard/peers/') &&
                        (c.body as { name?: string })?.name === 'Renamed-Laptop' &&
                        (c.body as { persistent_keepalive?: number })?.persistent_keepalive === 25
                )
            ).toBe(true);
        });

        // Remove peer with confirmation modal
        fireEvent.click(screen.getByRole('button', { name: /Remove peer Active-Laptop/i }));
        fireEvent.click(screen.getByRole('button', { name: /^Remove Peer$/i }));

        await waitFor(() => {
            expect(calls.some((c) => c.method === 'DELETE' && c.url.includes('/wireguard/peers/'))).toBe(true);
        });

        // Restart service requires confirmation
        fireEvent.click(screen.getByRole('button', { name: /^Restart$/i }));
        fireEvent.click(screen.getByRole('button', { name: /^Restart Service$/i }));

        await waitFor(() => {
            expect(
                calls.some(
                    (c) =>
                        c.url.includes('/wireguard/service') &&
                        (c.body as { action?: string })?.action === 'restart'
                )
            ).toBe(true);
        });

        // Open bounded diagnostics
        fireEvent.click(screen.getByRole('button', { name: /^Diagnostics$/i }));
        await waitFor(() => {
            expect(screen.getByText(/Nov 01 wg-quick\[102\]: wg0 interface up/i)).toBeInTheDocument();
            expect(screen.getByText(/UDP 51820 Reachable/i)).toBeInTheDocument();
        });
    });

    it('supports Tailscale login URL handoff, clearing all advertised routes with [], and exit-node selection', async () => {
        const fixture = makeRunningStatusFixture();
        mockedUseSWR.mockReturnValue({
            data: fixture,
            isLoading: false,
            isValidating: false,
            mutate: mutateMock,
        });

        const calls: Array<{ url: string; method?: string; body?: unknown }> = [];
        fetchSpy.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url = String(input);
            const body = init?.body ? JSON.parse(String(init.body)) : undefined;
            calls.push({ url, method: init?.method, body });

            if (url.includes('/tailscale/connect')) {
                return new Response(
                    JSON.stringify({
                        message: 'Interactive login required',
                        auth_url: 'https://login.tailscale.com/a/1234567890abcdef',
                        backend_state: 'NeedsLogin',
                    }),
                    { status: 200, headers: { 'Content-Type': 'application/json' } }
                );
            }
            if (url.includes('/tailscale/routes')) {
                return new Response(
                    JSON.stringify({
                        message: 'Routes updated',
                        routes: (body as { routes: string[] })?.routes ?? [],
                    }),
                    { status: 200, headers: { 'Content-Type': 'application/json' } }
                );
            }
            if (url.includes('/tailscale/settings')) {
                return new Response(
                    JSON.stringify({ message: 'Settings saved' }),
                    { status: 200, headers: { 'Content-Type': 'application/json' } }
                );
            }
            return new Response(JSON.stringify({}), { status: 200 });
        });

        render(<NetworkTab />);
        fireEvent.click(screen.getByRole('button', { name: /Tailscale Mesh/i }));

        // Verify admin console route approval guidance is explicitly rendered
        expect(
            screen.getByText(/Subnet route & exit-node approval is managed in the Tailscale Admin Console/i)
        ).toBeInTheDocument();

        // Trigger reauthentication to get login URL
        fireEvent.click(screen.getByRole('button', { name: /Reauthenticate/i }));
        await waitFor(() => {
            const authLink = screen.getByRole('link', { name: /Authenticate in Tailscale/i });
            expect(authLink).toHaveAttribute('href', 'https://login.tailscale.com/a/1234567890abcdef');
        });

        // Clear all advertised routes -> sends { routes: [] }
        fireEvent.click(screen.getByRole('button', { name: /Clear All Routes/i }));
        await waitFor(() => {
            expect(
                calls.some(
                    (c) =>
                        c.url.includes('/tailscale/routes') &&
                        Array.isArray((c.body as { routes: string[] })?.routes) &&
                        (c.body as { routes: string[] }).routes.length === 0
                )
            ).toBe(true);
        });

        // Select peer exit node
        fireEvent.change(screen.getByLabelText(/Use Peer Exit Node/i), {
            target: { value: '100.64.0.20' },
        });
        await waitFor(() => {
            expect(
                calls.some(
                    (c) =>
                        c.url.includes('/tailscale/settings') &&
                        (c.body as { exit_node?: string })?.exit_node === '100.64.0.20'
                )
            ).toBe(true);
        });
    });

    it('dismisses completed logins and removes active routes without submitting an unsaved draft', async () => {
        const fixture = makeRunningStatusFixture();
        fixture.tailscale!.state = 'needs_login';
        fixture.tailscale!.backend_state = 'NeedsLogin';
        mockedUseSWR.mockReturnValue({ data: fixture, isLoading: false, isValidating: false, mutate: mutateMock });
        let submittedRoutes: string[] | null = null;
        fetchSpy.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
            if (String(input).endsWith('/tailscale/connect')) {
                return new Response(JSON.stringify({auth_url:'https://login.tailscale.com/a/one-time',backend_state:'NeedsLogin'}),{status:200});
            }
            if (String(input).endsWith('/tailscale/routes')) {
                submittedRoutes = JSON.parse(String(init?.body)).routes;
                return new Response(JSON.stringify({message:'Saved',routes:submittedRoutes}),{status:200});
            }
            return new Response('{}',{status:200});
        });
        const view = render(<NetworkTab />);
        fireEvent.click(screen.getByRole('button', { name: /Tailscale Mesh/i }));
        fireEvent.click(screen.getByRole('button', { name: /Connect \/ Login/i }));
        await waitFor(() => expect(screen.getByRole('link',{name:/Authenticate in Tailscale/i})).toBeInTheDocument());
        const connected = makeRunningStatusFixture({
            checked_at: new Date(Date.parse(fixture.checked_at!) + 1000).toISOString(),
        });
        mockedUseSWR.mockReturnValue({data:connected,isLoading:false,isValidating:false,mutate:mutateMock});
        view.rerender(<NetworkTab />);
        await waitFor(() => expect(screen.queryByRole('link',{name:/Authenticate in Tailscale/i})).not.toBeInTheDocument());
        expect(screen.getByText('Tailnet: example.tailnet.test')).toBeInTheDocument();
        fireEvent.change(screen.getByLabelText(/Advertised Subnet Routes/i),{target:{value:'10.99.0.0/16'}});
        fireEvent.click(screen.getByRole('button',{name:'Remove route 10.66.66.0/24'}));
        await waitFor(() => expect(submittedRoutes).toEqual(['192.168.1.0/24']));
    });

    it('links to Marketplace and Services via Zustand store when packages are not installed', async () => {
        const fixture = makeRunningStatusFixture({
            wireguard_available: false,
            wireguard: {
                installed: false,
                state: 'not_installed',
                interface: 'wg0',
                public_key: '',
                listen_port: '51820',
                peers: [],
            },
        });
        mockedUseSWR.mockReturnValue({
            data: fixture,
            isLoading: false,
            isValidating: false,
            mutate: mutateMock,
        });

        render(<NetworkTab />);
        // Click Open Marketplace when not installed
        fireEvent.click(screen.getByRole('button', { name: /Open Marketplace/i }));
        expect(useSystemStore.getState().activeTab).toBe('marketplace');

        // Click Services button in top bar
        fireEvent.click(screen.getByRole('button', { name: /^Services$/i }));
        expect(useSystemStore.getState().activeTab).toBe('services');
    });
});
