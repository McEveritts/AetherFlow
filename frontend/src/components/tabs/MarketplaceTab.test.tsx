import React from 'react';
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import MarketplaceTab, {
    versionsMatchTarget,
    singleVersionMatch,
    normalizeVersion,
    isDebianPlusRevision,
    checkIsAuthError,
} from './MarketplaceTab';
import { App, PendingAction } from '@/hooks/useMarketplace';
const mockAddToast = jest.fn();
let mockMarketplaceApps: App[] | undefined;
let mockPendingJobs = new Map<string, PendingAction>();
let mockUnconfirmedJobs = new Map<string, string>();
let mockInventoryAuthenticated: boolean | null | undefined;
let mockInventoryMode: 'authenticated' | 'public_redacted' | null | undefined;
let mockIsError = false;
let mockError: unknown = undefined;

jest.mock('@/hooks/useMarketplace', () => ({
    ...jest.requireActual('@/hooks/useMarketplace'),
    useMarketplace: () => {
        const apps = mockMarketplaceApps || [
            {
                id: 'jellyfin',
                name: 'Jellyfin',
                desc: 'Media server',
                category: 'Media',
                status: 'installed',
                progress: 100,
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            },
        ];
        const rawMeta = apps as unknown as Record<string, unknown>;
        const hasAffirmative = Array.isArray(apps) && apps.length > 0 && apps.every(
            (item) => item && (item.inventory_known === true || item.inventory_authenticated === true || item.inventory_mode === 'authenticated')
        );
        const hasNegative = Array.isArray(apps) && apps.some(
            (item) => item && (item.inventory_known === false || item.inventory_authenticated === false || item.inventory_mode === 'public_redacted')
        );
        const isAuth = (mockError && ((mockError as { status?: number })?.status === 403 || (mockError as { status?: number })?.status === 401))
            ? false
            : (mockInventoryAuthenticated !== undefined
                ? (mockInventoryAuthenticated === null ? undefined : mockInventoryAuthenticated)
                : (rawMeta?.inventory_authenticated !== undefined
                    ? rawMeta.inventory_authenticated === true
                    : (rawMeta?.inventory_mode !== undefined
                        ? rawMeta.inventory_mode !== 'public_redacted'
                        : (!hasNegative && hasAffirmative))));
        const mode = (mockError && ((mockError as { status?: number })?.status === 403 || (mockError as { status?: number })?.status === 401))
            ? 'public_redacted'
            : (mockInventoryMode !== undefined
                ? (mockInventoryMode === null ? undefined : mockInventoryMode)
                : (isAuth !== undefined ? (isAuth ? 'authenticated' : 'public_redacted') : undefined));

        return {
            apps,
            packages: apps,
            isLoading: false,
            isError: mockIsError || Boolean(mockError),
            error: mockError,
            mutate: jest.fn(),
            pendingJobs: mockPendingJobs,
            unconfirmedJobs: mockUnconfirmedJobs,
            markPending: (id: string, action: PendingAction) => { mockPendingJobs.set(id, action); },
            clearPending: (id: string) => { mockPendingJobs.delete(id); },
            registerJob: jest.fn((_id: string, receipt: { job_id?: string; started_at?: string }) => receipt.job_id || receipt.started_at),
            inventoryAuthenticated: isAuth,
            inventoryMode: mode,
        };
    },
    useGithubDownloads: () => 5000,
}));

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
    }),
}));

jest.mock('@/lib/svgl', () => ({
    getSVGLCatalog: jest.fn().mockResolvedValue([]),
    matchSVGLLogo: jest.fn().mockReturnValue(null),
}));

jest.mock('@/components/ingress/ExternalAccessCard', () => ({
    ExternalAccessCard: () => <div data-testid="external-access-card" />,
}));

jest.mock('@/components/deploy/DeploymentStatus', () => ({
    DeploymentStatus: () => <div data-testid="deployment-status" />,
}));

const mockApiFetch = jest.fn();
jest.mock('@/lib/fetcher', () => ({
    apiFetch: (...args: unknown[]) => mockApiFetch(...args),
}));

describe('MarketplaceTab Sandboxed Plugin Runtime Integration', () => {
    beforeEach(() => {
        mockApiFetch.mockReset();
        mockAddToast.mockReset();
        mockMarketplaceApps = undefined;
        mockPendingJobs = new Map();
        mockUnconfirmedJobs = new Map();
        mockInventoryAuthenticated = undefined;
        mockInventoryMode = undefined;
        mockIsError = false;
        mockError = undefined;
    });

    it('discovers plugins, renders granted scopes, and mounts UI in an isolated sandbox="allow-scripts" iframe without allow-same-origin', async () => {
        const demoPlugin = {
            id: 'telemetry-inspector',
            name: 'Telemetry Inspector',
            version: '0.1.0',
            sdk: 'rust',
            contract_version: 'v1',
            runtime_status: 'managed',
            description: 'Inspects scoped system telemetry safely.',
            author: 'AetherFlow',
            permissions: ['system:metrics:read'],
            granted_scopes: [
                { method: 'GET', route: '/api/v1/auth/system/metrics' },
            ],
            enabled: true,
            status: 'running',
            healthy: true,
            allocated_port: 21005,
            health_path: '/healthz',
            ui_url: '/api/v1/auth/plugins/telemetry-inspector/ui',
            proxy_base_url: '/api/v1/auth/plugins/telemetry-inspector/proxy',
            slot: 'marketplace',
            capabilities: ['sandbox-iframe', 'postmessage-bridge', 'scoped-proxy'],
        };

        mockApiFetch.mockImplementation(async (url: string) => {
            if (url === '/api/v1/auth/plugins') {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        plugins: [demoPlugin],
                        rejected: [{ id: 'bad-symlink', error: 'Plugin directory cannot be a symbolic link' }],
                    }),
                };
            }
            return {
                ok: true,
                status: 200,
                json: async () => ({}),
            };
        });

        render(<MarketplaceTab />);

        await waitFor(() => {
            expect(screen.getByTestId('plugin-card-telemetry-inspector')).toBeInTheDocument();
        });

        expect(screen.getByText('Telemetry Inspector')).toBeInTheDocument();
        expect(screen.getByText('GET /api/v1/auth/system/metrics')).toBeInTheDocument();
        expect(screen.getByTestId('rejected-plugins-banner')).toHaveTextContent('bad-symlink');

        // Open sandboxed plugin UI
        fireEvent.click(screen.getByTestId('open-plugin-ui-telemetry-inspector'));

        const iframe = await screen.findByTestId('plugin-sandbox-iframe');
        expect(iframe).toBeInTheDocument();
        expect(iframe).toHaveAttribute('src', '/api/v1/auth/plugins/telemetry-inspector/ui');
        expect(iframe).toHaveAttribute('sandbox', 'allow-scripts');
        expect(iframe.getAttribute('sandbox')).not.toContain('allow-same-origin');
    });

    it('enables a stopped plugin via control endpoint, mounts sandboxed UI, and disables it cleanly', async () => {
        const stoppedPlugin = {
            id: 'telemetry-inspector',
            name: 'Telemetry Inspector',
            version: '1.0.0',
            sdk: 'managed-sample',
            contract_version: 'v1',
            runtime_status: 'managed',
            description: 'Managed loopback telemetry companion.',
            author: 'AetherFlow',
            permissions: ['system:metrics:read'],
            granted_scopes: [
                { method: 'GET', route: '/api/v1/auth/system/metrics' },
            ],
            enabled: false,
            status: 'stopped',
            healthy: false,
            allocated_port: 0,
            health_path: '/healthz',
            ui_url: '/api/v1/auth/plugins/telemetry-inspector/ui',
            proxy_base_url: '/api/v1/auth/plugins/telemetry-inspector/proxy',
            slot: 'marketplace',
            capabilities: ['sandbox-iframe', 'postmessage-bridge', 'scoped-proxy'],
        };

        const runningPlugin = {
            ...stoppedPlugin,
            enabled: true,
            status: 'running',
            healthy: true,
            allocated_port: 21007,
        };

        mockApiFetch.mockImplementation(async (url: string, init?: { body?: string }) => {
            if (url === '/api/v1/auth/plugins') {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        plugins: [stoppedPlugin],
                        rejected: [],
                    }),
                };
            }
            if (url === '/api/v1/admin/plugins/telemetry-inspector/control') {
                const parsed = init?.body ? JSON.parse(init.body) : {};
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        message: `Plugin action ${parsed.action} completed`,
                        plugin: parsed.action === 'start' ? runningPlugin : stoppedPlugin,
                    }),
                };
            }
            return {
                ok: true,
                status: 200,
                json: async () => ({}),
            };
        });

        render(<MarketplaceTab />);

        await waitFor(() => {
            expect(screen.getByTestId('plugin-card-telemetry-inspector')).toBeInTheDocument();
        });

        expect(screen.queryByTestId('open-plugin-ui-telemetry-inspector')).not.toBeInTheDocument();
        fireEvent.click(screen.getByTestId('toggle-plugin-telemetry-inspector'));

        await waitFor(() => {
            expect(screen.getByTestId('open-plugin-ui-telemetry-inspector')).toBeInTheDocument();
        });
        expect(screen.getByText('Healthy')).toBeInTheDocument();
        expect(screen.getByText('127.0.0.1:21007')).toBeInTheDocument();

        fireEvent.click(screen.getByTestId('open-plugin-ui-telemetry-inspector'));
        expect(await screen.findByTestId('plugin-sandbox-iframe')).toBeInTheDocument();

        fireEvent.click(screen.getByTestId('toggle-plugin-telemetry-inspector'));
        await waitFor(() => {
            expect(screen.queryByTestId('plugin-sandbox-iframe')).not.toBeInTheDocument();
        });
        expect(screen.getByText('Stopped')).toBeInTheDocument();
    });
});

describe('Marketplace lifecycle workflows', () => {
    const app = (extra: Partial<App> = {}): App => ({ id: 'fixture', name: 'Fixture', desc: 'Application', hits: 0, category: 'Media', status: 'installed', progress: 0, update_available: true, latest_version: '1.0.0', installed_version: '1.0.0', inventory_known: true, inventory_authenticated: true, inventory_mode: 'authenticated', ...extra });
    beforeEach(() => {
        mockPendingJobs = new Map(); mockUnconfirmedJobs = new Map(); mockMarketplaceApps = [app()]; mockAddToast.mockReset();
        mockInventoryAuthenticated = undefined; mockInventoryMode = undefined;
        mockIsError = false; mockError = undefined;
        mockApiFetch.mockReset();
        mockApiFetch.mockImplementation(async (url: string) => ({ ok: true, json: async () => url === '/api/v1/auth/plugins' ? { plugins: [] } : { job_id: 'accepted', started_at: 'now' } }));
    });

    it('does not call a superseding client job success for an expired local receipt', async () => {
        const view = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Update' }));
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));
        mockMarketplaceApps = [app({ last_job: { job_id: 'other-client-B', action: 'update', status: 'completed', started_at: 'later', finished_at: 'later', achieved_version: '1.0.0' } })];
        view.rerender(<MarketplaceTab />);
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
        mockPendingJobs = new Map();
        mockUnconfirmedJobs = new Map([['fixture', 'accepted']]);
        view.rerender(<MarketplaceTab />);
        expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('receipt may have been superseded'), 'error');
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
        expect(screen.getByRole('button', { name: 'Update' })).not.toBeDisabled();
        const count = mockAddToast.mock.calls.length;
        view.rerender(<MarketplaceTab />);
        expect(mockAddToast.mock.calls.length).toBe(count);
    });

    it.each(['completed', 'failed', 'interrupted', 'unknown'])('never attributes a stale snapshot to a new update (%s)', async status => {
        const { rerender } = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Update' }));
        await waitFor(() => expect(mockApiFetch).toHaveBeenCalledWith('/api/v1/admin/packages/fixture/update', expect.objectContaining({ method: 'POST' })));
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));
        mockMarketplaceApps = [app({ last_job: { job_id: 'older', action: 'update', status: 'completed', started_at: 'old', finished_at: 'old', achieved_version: '1.0.0' } })];
        rerender(<MarketplaceTab />);
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
        mockMarketplaceApps = [app({ installed_version: '1.0.0', last_job: { job_id: 'accepted', action: 'update', status, started_at: 'now', finished_at: 'later', achieved_version: '1.0.0', expected_target_version: '1.0.0' } })];
        rerender(<MarketplaceTab />);
        expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining(status === 'completed' ? 'successfully updated' : status === 'failed' ? 'failed' : 'could not be confirmed'), status === 'completed' ? 'success' : 'error');
        expect(mockAddToast.mock.calls.some(call => String(call[0]).includes('previously installed version was kept'))).toBe(false);
        const count = mockAddToast.mock.calls.length;
        rerender(<MarketplaceTab />);
        expect(mockAddToast.mock.calls.length).toBe(count);
    });

    it.each(['Uninstall', 'Reinstall'])('contains %s confirmation focus and dismisses without dispatching lifecycle work', async (operation) => {
        const user = userEvent.setup();
        render(<MarketplaceTab />);
        const opener = screen.getByRole('button', { name: operation });
        await user.click(opener);
        const dialog = screen.getByRole('dialog', { name: `${operation} Fixture` });
        const close = within(dialog).getByRole('button', { name: `Close ${operation} Fixture` });
        expect(close).toHaveFocus();
        await user.tab({ shift: true });
        expect(dialog).toContainElement(document.activeElement as HTMLElement);
        await user.tab();
        expect(close).toHaveFocus();
        expect(within(dialog).getByRole('button', { name: 'Cancel' })).toHaveClass('glass-button', 'obs-touch-target-standard');
        await user.keyboard('{Escape}');
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(opener).toHaveFocus();
        expect(mockApiFetch.mock.calls.some(([url]) => String(url).includes('/packages/'))).toBe(false);
    });

    it('requires a deliberate purge confirmation and retains edits through refresh', async () => {
        const { rerender } = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Uninstall' }));
        fireEvent.click(screen.getByRole('checkbox'));
        expect(screen.getByRole('button', { name: 'Permanently purge' })).toBeDisabled();
        fireEvent.change(screen.getByLabelText('Purge confirmation'), { target: { value: 'fixture' } });
        mockMarketplaceApps = [app({ installed_version: '2.0' })];
        rerender(<MarketplaceTab />);
        expect(screen.getByLabelText('Purge confirmation')).toHaveValue('fixture');
        fireEvent.click(screen.getByRole('button', { name: 'Permanently purge' }));
        await waitFor(() => expect(mockApiFetch).toHaveBeenCalledWith('/api/v1/admin/packages/fixture/uninstall?purge=true', { method: 'POST' }));
    });

    it('defaults to retained-data uninstall and offers an in-place reinstall', async () => {
        const view = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Uninstall' }));
        fireEvent.click(screen.getByRole('button', { name: 'Uninstall and keep data' }));
        await waitFor(() => expect(mockApiFetch).toHaveBeenCalledWith('/api/v1/admin/packages/fixture/uninstall', { method: 'POST' }));
        view.unmount(); mockPendingJobs = new Map();
        render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Reinstall' }));
        fireEvent.click(screen.getByRole('button', { name: 'Reinstall and keep data' }));
        await waitFor(() => expect(mockApiFetch).toHaveBeenCalledWith('/api/v1/admin/packages/fixture/install', { method: 'POST' }));
    });
});

describe('Marketplace open-canvas presentation and layout', () => {
    const apps: App[] = [
        {
            id: 'jellyfin',
            name: 'Jellyfin',
            desc: 'The Free Software Media System',
            hits: 120,
            category: 'Media',
            status: 'installed',
            progress: 100,
            update_available: false,
            public_domain: 'jellyfin.local',
            tls_enabled: true,
            web_path: '/web',
            inventory_known: true,
            inventory_authenticated: true,
            inventory_mode: 'authenticated',
        },
        {
            id: 'qbittorrent',
            name: 'qBittorrent',
            desc: 'Bittorrent client in C++ / Qt',
            hits: 80,
            category: 'Torrents',
            status: 'available',
            progress: 0,
            update_available: false,
            inventory_known: true,
            inventory_authenticated: true,
            inventory_mode: 'authenticated',
        },
    ];

    beforeEach(() => {
        mockPendingJobs = new Map();
        mockUnconfirmedJobs = new Map();
        mockMarketplaceApps = apps;
        mockAddToast.mockReset();
        mockIsError = false;
        mockError = undefined;
        mockApiFetch.mockReset();
        mockApiFetch.mockImplementation(async (url: string) => {
            if (url === '/api/v1/auth/plugins') return { ok: true, json: async () => ({ plugins: [] }) };
            return { ok: true, json: async () => ({}) };
        });
    });

    it('renders contiguous divider matrix without floating glass-card surfaces', async () => {
        render(<MarketplaceTab />);

        await waitFor(() => {
            expect(screen.getByRole('article', { name: 'Jellyfin application' })).toBeInTheDocument();
        });

        const jellyfinArticle = screen.getByRole('article', { name: 'Jellyfin application' });
        expect(jellyfinArticle).not.toHaveClass('glass-card', 'glass-panel', 'rounded-3xl');
        expect(jellyfinArticle).toHaveClass('relative', 'min-w-0');

        const qbittorrentArticle = screen.getByRole('article', { name: 'qBittorrent application' });
        expect(qbittorrentArticle).toBeInTheDocument();
        expect(qbittorrentArticle).not.toHaveClass('glass-card', 'glass-panel', 'rounded-3xl');

        const searchInput = screen.getByPlaceholderText('Find apps and services...');
        expect(searchInput).toBeInTheDocument();
        expect(searchInput).not.toHaveClass('backdrop-blur-md');
    });

    it('filters applications by category and search query correctly', async () => {
        render(<MarketplaceTab />);

        await waitFor(() => {
            expect(screen.getByText('Jellyfin')).toBeInTheDocument();
        });
        expect(screen.getByText('qBittorrent')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Torrents' }));
        expect(screen.queryByText('Jellyfin')).not.toBeInTheDocument();
        expect(screen.getByText('qBittorrent')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'All' }));
        expect(screen.getByText('Jellyfin')).toBeInTheDocument();
        expect(screen.getByText('qBittorrent')).toBeInTheDocument();

        fireEvent.change(screen.getByPlaceholderText('Find apps and services...'), { target: { value: 'jelly' } });
        expect(screen.getByText('Jellyfin')).toBeInTheDocument();
        expect(screen.queryByText('qBittorrent')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Clear search' }));
        expect(screen.getByText('Jellyfin')).toBeInTheDocument();
        expect(screen.getByText('qBittorrent')).toBeInTheDocument();
    });

    it('opens ingress modal with deployment status without blanket viewport clipping', async () => {
        render(<MarketplaceTab />);

        await waitFor(() => {
            expect(screen.getByRole('button', { name: 'Jellyfin Ingress and Deployment' })).toBeInTheDocument();
        });

        const ingressButton = screen.getByRole('button', { name: 'Jellyfin Ingress and Deployment' });
        fireEvent.click(ingressButton);

        expect(screen.getByText('jellyfin Ingress & Deploy')).toBeInTheDocument();
        expect(screen.getByTestId('external-access-card')).toBeInTheDocument();
        expect(screen.getByTestId('deployment-status')).toBeInTheDocument();
    });
});

describe('Marketplace update freshness, public catalog mode, and target certification', () => {
    const app = (extra: Partial<App> = {}): App => ({
        id: 'fixture',
        name: 'Fixture',
        desc: 'Application',
        hits: 0,
        category: 'Media',
        status: 'installed',
        progress: 0,
        update_available: true,
        inventory_known: true,
        inventory_authenticated: true,
        inventory_mode: 'authenticated',
        ...extra,
    });

    beforeEach(() => {
        mockPendingJobs = new Map();
        mockUnconfirmedJobs = new Map();
        mockMarketplaceApps = [app()];
        mockInventoryAuthenticated = undefined;
        mockInventoryMode = undefined;
        mockIsError = false;
        mockError = undefined;
        mockAddToast.mockReset();
        mockApiFetch.mockReset();
        mockApiFetch.mockImplementation(async (url: string) => ({
            ok: true,
            json: async () => (url === '/api/v1/auth/plugins' ? { plugins: [] } : { job_id: 'accepted', started_at: 'now' }),
        }));
    });

    it('displays the update badge, stale check warning, and update/recheck controls when update_available is true despite a non-empty update_error', async () => {
        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                update_available: true,
                latest_version: '1.76.0',
                update_error: 'GitHub API rate limit reached',
                update_checked_at: '2026-11-08T12:00:00.000Z',
            }),
        ];

        render(<MarketplaceTab />);

        // 1. Update Available badge is displayed with target version and last confirmed notice
        expect(screen.getByText(/v1\.76\.0/)).toBeInTheDocument();
        expect(screen.getByText(/\(last confirmed\)/)).toBeInTheDocument();

        // 2. Distinct stale-check warning indicator is displayed
        expect(screen.getByText(/Check stale: GitHub API rate limit reached/i)).toBeInTheDocument();

        // 3. Freshness timestamp is displayed
        expect(screen.getByText(/Checked/i)).toBeInTheDocument();

        // 4. Both Recheck and Update controls are available
        const recheckBtn = screen.getByRole('button', { name: /Recheck/i });
        const updateBtn = screen.getByRole('button', { name: 'Update' });
        expect(recheckBtn).toBeInTheDocument();
        expect(updateBtn).toBeInTheDocument();
        expect(updateBtn).toHaveAttribute('title', 'Update to v1.76.0 (last confirmed)');

        // 5. Clicking Recheck dispatches POST check-update
        fireEvent.click(recheckBtn);
        await waitFor(() => {
            expect(mockApiFetch).toHaveBeenCalledWith(
                '/api/v1/admin/packages/fixture/check-update',
                { method: 'POST' }
            );
        });
    });

    it('shows the unauthenticated catalog notice and does not render misleading Provision buttons when in public redacted mode', async () => {
        const unauthenticatedApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'not_installed',
                update_available: false,
                last_job: undefined,
            }),
        ];
        mockMarketplaceApps = unauthenticatedApps;
        mockInventoryAuthenticated = false;
        mockInventoryMode = 'public_redacted';

        render(<MarketplaceTab />);

        // 1. Prominent public catalog notice banner is displayed
        expect(screen.getByTestId('unauthenticated-catalog-banner')).toBeInTheDocument();
        expect(screen.getByText(/Session verification required — showing public catalog only\. Installed status, versions, and lifecycle actions are hidden until you re-authenticate\./i)).toBeInTheDocument();

        // 2. Does NOT render misleading Provision button
        expect(screen.queryByRole('button', { name: 'Provision' })).not.toBeInTheDocument();

        // 3. Renders Inventory Locked state on the card
        const lockedBtn = screen.getByRole('button', { name: 'Inventory Locked' });
        expect(lockedBtn).toBeInTheDocument();
        expect(lockedBtn).toBeDisabled();
        expect(lockedBtn).toHaveAttribute('title', 'Sign in to view status');
    });

    it('suppresses lifecycle fields and closes open lifecycle dialogs when entering public redacted mode', async () => {
        const retainedLifecyclePackage = app({
            id: 'fixture',
            name: 'Fixture',
            status: 'updating',
            progress: 42,
            log_line: 'running secret migration',
            update_available: true,
            ...({ installed: true } as Partial<App>),
        });

        // 1. Initial render with open lifecycle confirmation dialog in authenticated mode
        mockMarketplaceApps = [app({ id: 'fixture', name: 'Fixture', status: 'installed' })];
        mockInventoryAuthenticated = true;
        mockInventoryMode = 'authenticated';

        const { rerender } = render(<MarketplaceTab />);

        // Open uninstall lifecycle dialog
        const uninstallBtn = screen.getByRole('button', { name: 'Uninstall' });
        fireEvent.click(uninstallBtn);
        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();

        // 2. Transition to public_redacted mode with retained lifecycle fields
        mockMarketplaceApps = [retainedLifecyclePackage];
        mockInventoryAuthenticated = false;
        mockInventoryMode = 'public_redacted';

        rerender(<MarketplaceTab />);

        // Public catalog banner is rendered
        expect(screen.getByTestId('unauthenticated-catalog-banner')).toBeInTheDocument();

        // Lifecycle dialog is closed immediately
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

        // Retained lifecycle fields are suppressed from the card presentation
        expect(screen.queryByText(/updating/i)).not.toBeInTheDocument();
        expect(screen.queryByText(/42%/)).not.toBeInTheDocument();
        expect(screen.queryByText('running secret migration')).not.toBeInTheDocument();

        // Inventory Locked state is rendered instead of active lifecycle buttons
        expect(screen.getByRole('button', { name: 'Inventory Locked' })).toBeInTheDocument();
    });

    it('immediately closes and suppresses open lifecycle confirmation modals (uninstall, reinstall, purge) when HTTP 403 Forbidden error occurs', async () => {
        mockMarketplaceApps = [app({ id: 'fixture', name: 'Fixture', status: 'installed' })];
        mockInventoryAuthenticated = true;
        mockInventoryMode = 'authenticated';

        const { rerender } = render(<MarketplaceTab />);

        // 1. Open uninstall lifecycle dialog
        fireEvent.click(screen.getByRole('button', { name: 'Uninstall' }));
        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();

        // 2. HTTP 403 Forbidden error occurs
        mockError = Object.assign(new Error('Request failed with status 403'), { status: 403 });
        rerender(<MarketplaceTab />);

        // 3. Dialog is closed immediately and not rendered in error state
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(screen.getByText('Marketplace Unreachable')).toBeInTheDocument();
    });

    it('immediately closes and suppresses open ingress modal when HTTP 403 error occurs', async () => {
        mockMarketplaceApps = [app({ id: 'fixture', name: 'Fixture', status: 'installed' })];
        mockInventoryAuthenticated = true;
        mockInventoryMode = 'authenticated';

        const { rerender } = render(<MarketplaceTab />);

        // Open ingress dialog
        fireEvent.click(screen.getByRole('button', { name: 'Fixture Ingress and Deployment' }));
        expect(screen.getByText('fixture Ingress & Deploy')).toBeInTheDocument();

        // 403 error occurs
        mockError = Object.assign(new Error('Request failed with status 403'), { status: 403 });
        rerender(<MarketplaceTab />);

        // Ingress dialog should be closed immediately and not rendered
        expect(screen.queryByText('fixture Ingress & Deploy')).not.toBeInTheDocument();
    });

    it('does not close confirmation modals or clear purge confirmation or operating state on transient background errors when authenticated cached inventory is usable', async () => {
        let resolveInstall!: (value: Response) => void;
        mockApiFetch.mockImplementation(() => new Promise<Response>((resolve) => {
            resolveInstall = resolve;
        }));

        mockMarketplaceApps = [
            app({ id: 'fixture', name: 'Fixture', status: 'installed' }),
            app({ id: 'app-provision', name: 'Provision App', status: 'not_installed' }),
        ];
        mockInventoryAuthenticated = true;
        mockInventoryMode = 'authenticated';

        const { rerender } = render(<MarketplaceTab />);

        // 1. Open uninstall confirmation modal on installed app
        fireEvent.click(screen.getByRole('button', { name: 'Uninstall' }));
        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();

        // 2. Select purge data checkbox and fill purge confirmation text
        const purgeCheckbox = screen.getByLabelText(/Permanently delete application data/i);
        fireEvent.click(purgeCheckbox);
        const purgeInput = screen.getByLabelText('Purge confirmation');
        fireEvent.change(purgeInput, { target: { value: 'fixture' } });
        expect(purgeInput).toHaveValue('fixture');

        // 3. Start provisioning app-provision to set operatingApp state
        const provisionBtn = screen.getByRole('button', { name: 'Provision' });
        fireEvent.click(provisionBtn);
        expect(screen.getByRole('button', { name: 'Deploying...' })).toBeInTheDocument();

        // 4. Simulate transient background error (HTTP 500) during inventory polling/revalidation
        mockError = Object.assign(new Error('Internal Server Error 500'), { status: 500 });
        mockIsError = true;
        rerender(<MarketplaceTab />);

        // 5. Verify modal is NOT closed, purgeConfirmation is preserved, operatingApp is retained, and cached apps remain rendered
        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();
        expect(screen.getByLabelText('Purge confirmation')).toHaveValue('fixture');
        expect(screen.getByRole('button', { name: 'Deploying...' })).toBeInTheDocument();
        expect(screen.queryByText('Marketplace Unreachable')).not.toBeInTheDocument();
        expect(screen.getByTestId('marketplace-transient-error-banner')).toBeInTheDocument();

        // 6. Simulate network error as well
        mockError = new Error('Network error: connection reset');
        mockIsError = true;
        rerender(<MarketplaceTab />);

        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();
        expect(screen.getByLabelText('Purge confirmation')).toHaveValue('fixture');
        expect(screen.getByRole('button', { name: 'Deploying...' })).toBeInTheDocument();
        expect(screen.queryByText('Marketplace Unreachable')).not.toBeInTheDocument();

        // 7. When an HTTP 403 Forbidden auth error occurs, modals close and confirmation/operation state is cleared
        mockError = Object.assign(new Error('Request failed with status 403'), { status: 403 });
        rerender(<MarketplaceTab />);

        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(screen.getByText('Marketplace Unreachable')).toBeInTheDocument();

        // 8. Re-authenticate, open modal, and verify transition to public_redacted mode also immediately closes modal
        mockError = undefined;
        mockIsError = false;
        mockInventoryAuthenticated = true;
        mockInventoryMode = 'authenticated';
        rerender(<MarketplaceTab />);
        expect(screen.queryByText('Marketplace Unreachable')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Uninstall' }));
        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();

        mockInventoryAuthenticated = false;
        mockInventoryMode = 'public_redacted';
        rerender(<MarketplaceTab />);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(screen.getByTestId('unauthenticated-catalog-banner')).toBeInTheDocument();

        // Clean up pending promise
        resolveInstall(new Response(JSON.stringify({ status: 'ok' }), { status: 200 }));
    });

    it('defaults defensively to unauthenticated public_redacted when useMarketplace omits auth fields', () => {
        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                update_available: false,
            }),
        ];
        mockInventoryAuthenticated = null;
        mockInventoryMode = null;

        render(<MarketplaceTab />);

        expect(screen.getByTestId('unauthenticated-catalog-banner')).toBeInTheDocument();
        const lockedBtn = screen.getByRole('button', { name: 'Inventory Locked' });
        expect(lockedBtn).toBeInTheDocument();
        expect(lockedBtn).toBeDisabled();
    });

    it('locks inventory when array payload has public_redacted transport header attached even if items look affirmative', () => {
        const affirmativeApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                update_available: false,
                inventory_known: true,
                inventory_authenticated: true,
                inventory_mode: 'authenticated',
            }),
        ];
        // Simulate transport header state attached to the array payload
        (affirmativeApps as unknown as Record<string, unknown>).inventory_mode = 'public_redacted';
        (affirmativeApps as unknown as Record<string, unknown>).inventory_authenticated = false;

        mockMarketplaceApps = affirmativeApps;
        mockInventoryAuthenticated = undefined;
        mockInventoryMode = undefined;

        render(<MarketplaceTab />);

        expect(screen.getByTestId('unauthenticated-catalog-banner')).toBeInTheDocument();
        const lockedBtn = screen.getByRole('button', { name: 'Inventory Locked' });
        expect(lockedBtn).toBeInTheDocument();
        expect(lockedBtn).toBeDisabled();
    });

    it('sends expected_target_version when triggering an update and displays structured diagnostic stage/exit info on failure', async () => {
        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                update_available: true,
                latest_version: '1.76.0',
            }),
        ];

        const { rerender } = render(<MarketplaceTab />);

        // 1. Click Update button
        const updateBtn = screen.getByRole('button', { name: 'Update' });
        fireEvent.click(updateBtn);

        // 2. Verify expected_target_version is passed in the request body
        await waitFor(() => {
            expect(mockApiFetch).toHaveBeenCalledWith(
                '/api/v1/admin/packages/fixture/update',
                expect.objectContaining({
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ expected_target_version: '1.76.0' }),
                })
            );
        });
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));

        // 3. Simulate failure with structured diagnostics
        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                last_job: {
                    job_id: 'accepted',
                    action: 'update',
                    status: 'failed',
                    started_at: 'now',
                    finished_at: 'later',
                    failed_stage: 'installer',
                    exit_code: 1,
                    sanitized_summary: 'Binary checksum mismatch in downloaded artifact',
                },
            }),
        ];

        rerender(<MarketplaceTab />);

        // 4. Verify structured failure details are surfaced in the toast
        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith(
                expect.stringMatching(/failed.*stage: installer.*exit code: 1.*Binary checksum mismatch/i),
                'error'
            );
        });
    });

    it('includes certified version in success toast when update completes successfully', async () => {
        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                update_available: true,
                latest_version: '1.76.0',
            }),
        ];

        const { rerender } = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Update' }));
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));

        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                installed_version: '1.76.0',
                last_job: {
                    job_id: 'accepted',
                    action: 'update',
                    status: 'completed',
                    started_at: 'now',
                    finished_at: 'later',
                    achieved_version: '1.76.0',
                    expected_target_version: '1.76.0',
                },
            }),
        ];

        rerender(<MarketplaceTab />);

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith(
                expect.stringContaining('Fixture has been successfully updated to v1.76.0.'),
                'success'
            );
        });
    });

    it('verifies versionsMatchTarget and shows error toast when achieved_version is missing', async () => {
        expect(versionsMatchTarget('1.76.0', 'v1.76.0')).toBe(true);
        expect(versionsMatchTarget('6e840ac', '6e840acbda8d1234567890abcdef1234567890ab')).toBe(true);
        expect(versionsMatchTarget('1.2.3-rc1', '1.2.3')).toBe(false);

        // Case-insensitive hex commit comparison
        expect(versionsMatchTarget('ABCDEF12', 'abcdef1234567890abcdef1234567890abcdef12')).toBe(true);
        expect(versionsMatchTarget('abcdef1234567890abcdef1234567890abcdef12', 'ABCDEF12')).toBe(true);

        // Accept all-digit 7..40 char short Git SHAs only when the other side is an unambiguous Git SHA
        expect(versionsMatchTarget('1234567', '1234567890abcdef1234567890abcdef12345678')).toBe(true);
        expect(versionsMatchTarget('1234567890abcdef1234567890abcdef12345678', '1234567')).toBe(true);
        expect(versionsMatchTarget('1234567', '1234567000000000000000000000000000000000')).toBe(true);

        // Decimal dates: exact match is true, but decimal dates are NOT treated as hex commit prefixes
        expect(versionsMatchTarget('20261108', '20261108')).toBe(true);
        expect(versionsMatchTarget('20261108', '202611080')).toBe(false);
        expect(versionsMatchTarget('202611080', '20261108')).toBe(false);

        // Non-SHA release versions do NOT prefix match
        expect(versionsMatchTarget('1.1', '1.10')).toBe(false);
        expect(versionsMatchTarget('1.10', '1.1')).toBe(false);

        // Multi-component manifests: non-SHA versions do NOT prefix-match
        expect(versionsMatchTarget('comp1:1.1,comp2:2.0', 'comp1:1.10,comp2:2.0')).toBe(false);
        expect(versionsMatchTarget('comp1:1.10,comp2:2.0', 'comp1:1.1,comp2:2.0')).toBe(false);

        // Multi-component manifests: frontend,backend,proxy Git manifests
        expect(versionsMatchTarget('frontend:6e840ac,backend:a1b2c3d,proxy:9f8e7d6', 'frontend:6e840acbda8d,backend:a1b2c3d4e5f6,proxy:9f8e7d6c5b4a')).toBe(true);
        expect(versionsMatchTarget('frontend:ABCDEF12,backend:a1b2c3d,proxy:9f8e7d6', 'frontend:abcdef123456,backend:a1b2c3d4e5f6,proxy:9f8e7d6c5b4a')).toBe(true);
        expect(versionsMatchTarget('frontend:1234567,backend:2345678,proxy:3456789', 'frontend:1234567000000000000000000000000000000000,backend:2345678000000000000000000000000000000000,proxy:3456789000000000000000000000000000000000')).toBe(true);
        expect(versionsMatchTarget('frontend:6e840ac,backend:deadbeef,proxy:9f8e7d6', 'frontend:6e840ac,backend:a1b2c3d,proxy:9f8e7d6')).toBe(false);
        expect(versionsMatchTarget('frontend:6e840ac,backend:a1b2c3d', 'frontend:6e840ac,backend:a1b2c3d,proxy:9f8e7d6')).toBe(false);
        expect(versionsMatchTarget('frontend:6e840ac,backend:a1b2c3d,proxy:9f8e7d6', 'frontend:6e840ac,backend:a1b2c3d,other:9f8e7d6')).toBe(false);
        expect(versionsMatchTarget('frontend:6e840ac,frontend:a1b2c3d', 'frontend:6e840ac,frontend:a1b2c3d')).toBe(false);

        // Version prefix normalization (release_, release-, rel_, rel-, v/V) and SemVer build metadata
        expect(versionsMatchTarget('release_1.2.3', 'v1.2.3')).toBe(true);
        expect(versionsMatchTarget('rel_1.2.3', '1.2.3')).toBe(true);
        expect(versionsMatchTarget('rel-1.2.3', '1.2.3')).toBe(true);
        expect(versionsMatchTarget('release-1.2.3', '1.2.3')).toBe(true);
        expect(versionsMatchTarget('1.0.0+build.2', '1.0.0')).toBe(false);
        expect(versionsMatchTarget('1.0.0', '1.0.0+build.2')).toBe(false);
        expect(versionsMatchTarget('1.0.0+build.2', 'v1.0.0+build.2')).toBe(true);
        expect(versionsMatchTarget('release_1.0.0+build.2', 'v1.0.0+build.2')).toBe(true);

        // Debian revision markers in build metadata are NOT stripped
        expect(versionsMatchTarget('1.0.0+deb11u1', '1.0.0')).toBe(false);
        expect(versionsMatchTarget('1.0.0+dfsg-1', '1.0.0')).toBe(false);
        expect(versionsMatchTarget('1.0.0+ds1', '1.0.0')).toBe(false);
        expect(versionsMatchTarget('1.0.0+really1.2', '1.0.0')).toBe(false);
        expect(versionsMatchTarget('1.0.0+nmu1', '1.0.0')).toBe(false);
        expect(versionsMatchTarget('1.0.0+u2', '1.0.0')).toBe(false);
        expect(versionsMatchTarget('1.0.0+b1', '1.0.0+b2')).toBe(false);
        expect(versionsMatchTarget('1.0.0+b1', '1.0.0')).toBe(false);
        expect(versionsMatchTarget('1.0.0', '1.0.0+debug')).toBe(false);
        expect(versionsMatchTarget('1.0.0+debug', '1.0.0')).toBe(false);
        expect(versionsMatchTarget('1.0.0+debug', 'v1.0.0+debug')).toBe(true);
        expect(versionsMatchTarget('frontend=1.0,backend=2.0,proxy=3.0', 'frontend:v1.0,backend:v2.0,proxy:v3.0')).toBe(true);
        expect(versionsMatchTarget('release-v1.2.3', '1.2.3')).toBe(true);
        expect(versionsMatchTarget('rel_v1.2.3', '1.2.3')).toBe(true);
        expect(versionsMatchTarget('rel-v2.0', '2.0')).toBe(true);

        // normalizeVersion unit tests
        expect(normalizeVersion('release-v1.2.3')).toBe('1.2.3');
        expect(normalizeVersion('release_v1.2.3')).toBe('1.2.3');
        expect(normalizeVersion('rel-v2.0')).toBe('2.0');
        expect(normalizeVersion('release_1.2.3')).toBe('1.2.3');
        expect(normalizeVersion('release-1.2.3')).toBe('1.2.3');
        expect(normalizeVersion('rel_1.2.3')).toBe('1.2.3');
        expect(normalizeVersion('rel-1.2.3')).toBe('1.2.3');
        expect(normalizeVersion('v1.2.3')).toBe('1.2.3');
        expect(normalizeVersion('V1.2.3')).toBe('1.2.3');
        expect(normalizeVersion('1.0.0+build.2')).toBe('1.0.0+build.2');
        expect(normalizeVersion('1.0.0+debug')).toBe('1.0.0+debug');
        expect(normalizeVersion('v1.0.0+debug')).toBe('1.0.0+debug');
        expect(normalizeVersion('1.0.0+Debug')).toBe('1.0.0+Debug');
        expect(normalizeVersion('v1.0.0+Debug')).toBe('1.0.0+Debug');
        expect(versionsMatchTarget('1.0.0+Debug', '1.0.0+debug')).toBe(false);
        expect(versionsMatchTarget('1.0.0+Debug', 'v1.0.0+Debug')).toBe(true);
        expect(normalizeVersion('1.0.0+b1')).toBe('1.0.0+b1');
        expect(normalizeVersion('1.0.0+b2')).toBe('1.0.0+b2');
        expect(normalizeVersion('1.0.0+deb11u1')).toBe('1.0.0+deb11u1');

        expect(isDebianPlusRevision('b1')).toBe(true);
        expect(isDebianPlusRevision('b2')).toBe(true);
        expect(isDebianPlusRevision('debug')).toBe(false);

        // singleVersionMatch unit tests
        expect(singleVersionMatch('ABCDEF12', 'abcdef1234567890abcdef1234567890abcdef12')).toBe(true);
        expect(singleVersionMatch('1234567', '1234567890abcdef1234567890abcdef12345678')).toBe(true);
        expect(singleVersionMatch('1234567', '12345678', false)).toBe(false);
        expect(singleVersionMatch('1234567', '12345678', true)).toBe(true);
        expect(singleVersionMatch('20261108', '202611080')).toBe(false);
        expect(singleVersionMatch('1.1', '1.10')).toBe(false);
        expect(singleVersionMatch('release_1.2.3', 'v1.2.3')).toBe(true);
        expect(singleVersionMatch('rel_1.2.3', '1.2.3')).toBe(true);
        expect(singleVersionMatch('1.0.0+build.2', 'v1.0.0+build.2')).toBe(true);
        expect(singleVersionMatch('1.0.0+build.2', '1.0.0')).toBe(false);

        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                update_available: true,
                latest_version: '1.76.0',
                installed_version: undefined,
            }),
        ];

        const { rerender } = render(<MarketplaceTab />);
        const updateBtn = screen.getByRole('button', { name: 'Update' });
        fireEvent.click(updateBtn);
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));

        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                installed_version: undefined,
                last_job: {
                    job_id: 'accepted',
                    action: 'update',
                    status: 'completed',
                    started_at: 'now',
                    finished_at: 'later',
                    expected_target_version: '1.76.0',
                    achieved_version: undefined,
                },
            }),
        ];

        rerender(<MarketplaceTab />);

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith(
                expect.stringContaining('update target version (1.76.0) could not be verified (observed: unknown).'),
                'error'
            );
        });
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
    });

    it('shows error toast when expected_target_version is missing on update completion', async () => {
        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                update_available: true,
                latest_version: '1.76.0',
            }),
        ];

        const { rerender } = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Update' }));
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));

        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                last_job: {
                    job_id: 'accepted',
                    action: 'update',
                    status: 'completed',
                    started_at: 'now',
                    finished_at: 'later',
                    expected_target_version: undefined,
                    achieved_version: '1.76.0',
                },
            }),
        ];

        rerender(<MarketplaceTab />);

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith(
                expect.stringContaining('update target version (target) could not be verified (observed: 1.76.0).'),
                'error'
            );
        });
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
    });

    it('certifies 3-component Piped manifest when all components match', async () => {
        const expectedManifest = 'frontend:6e840acbda8d,backend:a1b2c3d4e5f6,proxy:9f8e7d6c5b4a';
        const matchingAchieved = 'frontend:6e840ac,backend:a1b2c3d,proxy:9f8e7d6';

        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                update_available: true,
                latest_version: expectedManifest,
            }),
        ];

        const { rerender } = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Update' }));
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));

        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                last_job: {
                    job_id: 'accepted',
                    action: 'update',
                    status: 'completed',
                    started_at: 'now',
                    finished_at: 'later',
                    expected_target_version: expectedManifest,
                    achieved_version: matchingAchieved,
                },
            }),
        ];

        rerender(<MarketplaceTab />);

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith(
                expect.stringContaining('Fixture has been successfully updated'),
                'success'
            );
        });
    });

    it('fails certification for 3-component Piped manifest when any component diverges', async () => {
        const expectedManifest = 'frontend:6e840acbda8d,backend:a1b2c3d4e5f6,proxy:9f8e7d6c5b4a';
        const divergingAchieved = 'frontend:6e840ac,backend:deadbeef,proxy:9f8e7d6';

        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                update_available: true,
                latest_version: expectedManifest,
            }),
        ];

        const { rerender } = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Update' }));
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));

        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                last_job: {
                    job_id: 'accepted',
                    action: 'update',
                    status: 'completed',
                    started_at: 'now',
                    finished_at: 'later',
                    expected_target_version: expectedManifest,
                    achieved_version: divergingAchieved,
                },
            }),
        ];

        rerender(<MarketplaceTab />);

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith(
                expect.stringContaining('could not be verified'),
                'error'
            );
        });
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
    });

    it('shows error toast when achieved_version mismatches expected_target_version', async () => {
        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                update_available: true,
                latest_version: '2.0.0',
            }),
        ];

        const { rerender } = render(<MarketplaceTab />);
        fireEvent.click(screen.getByRole('button', { name: 'Update' }));
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(expect.stringContaining('Updating Fixture'), 'info'));

        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                last_job: {
                    job_id: 'accepted',
                    action: 'update',
                    status: 'completed',
                    started_at: 'now',
                    finished_at: 'later',
                    expected_target_version: '2.0.0',
                    achieved_version: '1.9.0',
                },
            }),
        ];

        rerender(<MarketplaceTab />);

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith(
                expect.stringContaining('update target version (2.0.0) could not be verified (observed: 1.9.0).'),
                'error'
            );
        });
        expect(mockAddToast.mock.calls.some(call => call[1] === 'success')).toBe(false);
    });

    it('disables the Update button when app.latest_version is missing', () => {
        mockMarketplaceApps = [
            app({
                id: 'fixture',
                name: 'Fixture',
                status: 'installed',
                update_available: true,
                latest_version: undefined,
            }),
        ];

        render(<MarketplaceTab />);
        const updateBtn = screen.getByRole('button', { name: 'Update' });
        expect(updateBtn).toBeDisabled();
    });

    describe('checkIsAuthError classification', () => {
        it('classifies explicit numeric auth status codes as auth errors', () => {
            expect(checkIsAuthError({ status: 401 })).toBe(true);
            expect(checkIsAuthError({ status: 403 })).toBe(true);
            expect(checkIsAuthError({ statusCode: 401 })).toBe(true);
            expect(checkIsAuthError({ statusCode: 403 })).toBe(true);
            expect(checkIsAuthError({ response: { status: 401 } })).toBe(true);
            expect(checkIsAuthError({ response: { status: 403 } })).toBe(true);
        });

        it('does not classify known non-auth numeric HTTP status codes as auth errors even if message contains 401 or 403', () => {
            expect(checkIsAuthError({ status: 500, message: 'Backend failed on port 8403 after 4010ms' })).toBe(false);
            expect(checkIsAuthError({ status: 502, message: 'Upstream 401 / 4030ms timeout' })).toBe(false);
            expect(checkIsAuthError({ statusCode: 503, message: 'Service unavailable: upstream 401' })).toBe(false);
            expect(checkIsAuthError({ response: { status: 500 }, message: 'HTTP 401 Unauthorized' })).toBe(false);
        });

        it('correctly classifies error messages without status properties', () => {
            // Incidental numbers must NOT be treated as auth errors
            expect(checkIsAuthError(new Error('Request timed out after 4010ms (req 14039, port 8403)'))).toBe(false);
            expect(checkIsAuthError(new Error('Gateway timeout after 4010ms on port 8403 (req 94012)'))).toBe(false);
            expect(checkIsAuthError(new Error('Worker port 8403 connection refused'))).toBe(false);
            expect(checkIsAuthError(new Error('Gateway error 502 (request id 94012)'))).toBe(false);
            expect(checkIsAuthError('Worker port 8403 connection refused')).toBe(false);
            expect(checkIsAuthError('Request timed out after 4010ms')).toBe(false);

            // Valid word-bounded or prefix-bounded auth errors MUST be treated as auth errors
            expect(checkIsAuthError(new Error('401 Unauthorized'))).toBe(true);
            expect(checkIsAuthError(new Error('403 Forbidden'))).toBe(true);
            expect(checkIsAuthError(new Error('HTTP 401 Unauthorized'))).toBe(true);
            expect(checkIsAuthError(new Error('HTTP 403 Forbidden'))).toBe(true);
            expect(checkIsAuthError(new Error('HTTP 403'))).toBe(true);
            expect(checkIsAuthError(new Error('Status: 401'))).toBe(true);
            expect(checkIsAuthError(new Error('status code: 403'))).toBe(true);
            expect(checkIsAuthError(new Error('Error: 401'))).toBe(true);
            expect(checkIsAuthError(new Error('Forbidden'))).toBe(true);
            expect(checkIsAuthError(new Error('Unauthorized request'))).toBe(true);
            expect(checkIsAuthError('401 Unauthorized')).toBe(true);
            expect(checkIsAuthError('HTTP 403 Forbidden')).toBe(true);
            expect(checkIsAuthError('Forbidden')).toBe(true);
        });

        it('returns false for non-error or non-matching inputs', () => {
            expect(checkIsAuthError(null)).toBe(false);
            expect(checkIsAuthError(undefined)).toBe(false);
            expect(checkIsAuthError(123)).toBe(false);
            expect(checkIsAuthError({})).toBe(false);
            expect(checkIsAuthError(new Error('Connection reset by peer'))).toBe(false);
        });
    });

    it('does not close open modals or clear purge / operating state when transient errors have incidental 401/403 digits', async () => {
        let resolveInstall!: (value: Response) => void;
        mockApiFetch.mockImplementation(() => new Promise<Response>((resolve) => {
            resolveInstall = resolve;
        }));

        mockMarketplaceApps = [
            app({ id: 'fixture', name: 'Fixture', status: 'installed' }),
            app({ id: 'app-provision', name: 'Provision App', status: 'not_installed' }),
        ];
        mockInventoryAuthenticated = true;
        mockInventoryMode = 'authenticated';
        mockIsError = false;
        mockError = undefined;

        const { rerender } = render(<MarketplaceTab />);

        // Open uninstall modal, check purge, enter confirmation text
        fireEvent.click(screen.getByRole('button', { name: 'Uninstall' }));
        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();
        fireEvent.click(screen.getByLabelText(/Permanently delete application data/i));
        const purgeInput = screen.getByLabelText('Purge confirmation');
        fireEvent.change(purgeInput, { target: { value: 'fixture' } });
        expect(purgeInput).toHaveValue('fixture');

        // Start provisioning to set operatingApp state
        fireEvent.click(screen.getByRole('button', { name: 'Provision' }));
        expect(screen.getByRole('button', { name: 'Deploying...' })).toBeInTheDocument();

        // 1. Transient error with incidental 4010ms / 8403 port / 94012 req id
        mockError = new Error('Gateway timeout after 4010ms on port 8403 (req 94012)');
        mockIsError = true;
        rerender(<MarketplaceTab />);

        // Modal stays open, purge input preserved, operatingApp retained, banner rendered, unreachable alert NOT rendered
        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();
        expect(screen.getByLabelText('Purge confirmation')).toHaveValue('fixture');
        expect(screen.getByRole('button', { name: 'Deploying...' })).toBeInTheDocument();
        expect(screen.queryByText('Marketplace Unreachable')).not.toBeInTheDocument();
        expect(screen.getByTestId('marketplace-transient-error-banner')).toBeInTheDocument();

        // 2. Transient error with HTTP 502 status and incidental 401 / 4030ms message
        mockError = Object.assign(new Error('Upstream 401 / 4030ms timeout'), { status: 502 });
        mockIsError = true;
        rerender(<MarketplaceTab />);

        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();
        expect(screen.getByLabelText('Purge confirmation')).toHaveValue('fixture');
        expect(screen.getByRole('button', { name: 'Deploying...' })).toBeInTheDocument();
        expect(screen.queryByText('Marketplace Unreachable')).not.toBeInTheDocument();
        expect(screen.getByTestId('marketplace-transient-error-banner')).toBeInTheDocument();

        await act(async () => {
            resolveInstall(new Response(JSON.stringify({ status: 'ok' }), { status: 200 }));
        });
    });

    it('immediately closes open modals and clears confirmation / operating state on explicit auth errors', async () => {
        mockMarketplaceApps = [
            app({ id: 'fixture', name: 'Fixture', status: 'installed' }),
            app({ id: 'app-provision', name: 'Provision App', status: 'not_installed' }),
        ];
        mockInventoryAuthenticated = true;
        mockInventoryMode = 'authenticated';
        mockIsError = false;
        mockError = undefined;

        const { rerender } = render(<MarketplaceTab />);

        // 1. Explicit { status: 401 } auth error
        fireEvent.click(screen.getByRole('button', { name: 'Uninstall' }));
        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();
        fireEvent.click(screen.getByLabelText(/Permanently delete application data/i));
        fireEvent.change(screen.getByLabelText('Purge confirmation'), { target: { value: 'fixture' } });

        mockError = Object.assign(new Error('Session expired'), { status: 401 });
        mockIsError = true;
        rerender(<MarketplaceTab />);

        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(screen.getByText('Marketplace Unreachable')).toBeInTheDocument();

        // 2. Explicit new Error("HTTP 401 Unauthorized") without status property
        mockError = undefined;
        mockIsError = false;
        mockInventoryAuthenticated = true;
        mockInventoryMode = 'authenticated';
        rerender(<MarketplaceTab />);
        expect(screen.queryByText('Marketplace Unreachable')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Uninstall' }));
        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();
        fireEvent.click(screen.getByLabelText(/Permanently delete application data/i));
        fireEvent.change(screen.getByLabelText('Purge confirmation'), { target: { value: 'fixture' } });

        mockError = new Error('HTTP 401 Unauthorized');
        mockIsError = true;
        rerender(<MarketplaceTab />);

        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(screen.getByText('Marketplace Unreachable')).toBeInTheDocument();

        // 3. Explicit new Error("403 Forbidden") without status property
        mockError = undefined;
        mockIsError = false;
        mockInventoryAuthenticated = true;
        mockInventoryMode = 'authenticated';
        rerender(<MarketplaceTab />);
        expect(screen.queryByText('Marketplace Unreachable')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Uninstall' }));
        expect(screen.getByRole('dialog', { name: 'Uninstall Fixture' })).toBeInTheDocument();

        mockError = new Error('403 Forbidden');
        mockIsError = true;
        rerender(<MarketplaceTab />);

        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(screen.getByText('Marketplace Unreachable')).toBeInTheDocument();
    });
});
