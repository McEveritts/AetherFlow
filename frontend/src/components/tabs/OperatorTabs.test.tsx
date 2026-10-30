import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import NetworkTab from '@/components/tabs/NetworkTab';
import NotificationsSettingsTab from '@/components/tabs/NotificationsSettingsTab';
import QuotasBillingTab from '@/components/tabs/QuotasBillingTab';
import ClusterTab from '@/components/tabs/ClusterTab';

// Mock ToastContext
jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: jest.fn(),
    }),
}));

// Mock SWR to return deterministic fixture data
jest.mock('swr', () => {
    return jest.fn((key: string) => {
        if (key.includes('/network/status')) {
            return {
                data: {
                    wireguard_available: true,
                    tailscale_available: true,
                    platform: 'linux',
                    wireguard: {
                        interface: 'wg0',
                        public_key: 'mock-wg-key',
                        listen_port: '51820',
                        peers: [],
                    },
                },
                mutate: jest.fn(),
            };
        }
        if (key.includes('/network/wireguard/peers')) {
            return {
                data: { peers: [] },
                mutate: jest.fn(),
            };
        }
        if (key.includes('/network/tailscale/peers')) {
            return {
                data: { peers: [] },
                mutate: jest.fn(),
            };
        }
        if (key.includes('/notifications/rules')) {
            return {
                data: {
                    rules: [
                        {
                            id: 1,
                            name: 'High CPU Alert',
                            condition_type: 'cpu_usage',
                            condition_value: '90',
                            level: 'warning',
                            enabled: true,
                        },
                    ],
                },
                mutate: jest.fn(),
            };
        }
        if (key.includes('/notifications/channels')) {
            return {
                data: {
                    channels: [
                        {
                            id: 1,
                            name: 'DevOps Discord',
                            type: 'discord',
                            config: JSON.stringify({ webhook_url: 'https://discord.com/api/webhooks/test' }),
                            enabled: true,
                        },
                    ],
                },
                mutate: jest.fn(),
            };
        }
        if (key.includes('/quotas')) {
            return {
                data: {
                    quotas: [
                        {
                            user_id: 1,
                            username: 'operator',
                            quota_bytes: 107374182400, // 100 GB
                            used_bytes: 53687091200,   // 50 GB
                            available_bytes: 53687091200,
                            usage_pct: 50.0,
                            configured: true,
                            status: 'active',
                            source: 'manual',
                        },
                    ],
                },
                mutate: jest.fn(),
            };
        }
        if (key.includes('/billing/webhooks')) {
            return {
                data: {
                    events: [
                        {
                            id: 1,
                            provider: 'whmcs',
                            event_id: 'evt_101',
                            event_type: 'service_created',
                            username: 'operator',
                            quota_bytes: 107374182400,
                            status: 'success',
                            processed_at: new Date().toISOString(),
                        },
                    ],
                },
                mutate: jest.fn(),
            };
        }
        if (key.includes('/cluster/nodes')) {
            return {
                data: {
                    nodes: [
                        {
                            id: 'node-worker-01',
                            hostname: 'worker-fra-01',
                            address: '10.0.0.15:50051',
                            role: 'worker',
                            status: 'online',
                            version: '3.1.7',
                            last_heartbeat: new Date().toISOString(),
                            enrolled_at: new Date().toISOString(),
                            metrics: {
                                cpu_usage: 18.5,
                                mem_used_gb: 4.2,
                                mem_total_gb: 32.0,
                                disk_used_gb: 120.0,
                                disk_total_gb: 2000.0,
                                net_rx_speed: '12 MB/s',
                                net_tx_speed: '45 MB/s',
                                uptime: '14 days',
                                load_average: [0.4, 0.5, 0.6],
                            },
                        },
                    ],
                    summary: {
                        total_nodes: 1,
                        online_nodes: 1,
                        degraded_nodes: 0,
                        offline_nodes: 0,
                    },
                },
                mutate: jest.fn(),
            };
        }
        return { data: null, mutate: jest.fn() };
    });
});

describe('Operator Management Panels (M3 Features F24-F27)', () => {
    describe('NetworkTab (F24)', () => {
        it('renders WireGuard and Tailscale segmented switcher', () => {
            render(<NetworkTab />);
            expect(screen.getByText(/Network & VPN Mesh/i)).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /WireGuard VPN/i })).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Tailscale Mesh/i })).toBeInTheDocument();
        });

        it('switches between WireGuard and Tailscale sections', () => {
            render(<NetworkTab />);
            const tailscaleBtn = screen.getByRole('button', { name: /Tailscale Mesh/i });
            fireEvent.click(tailscaleBtn);
            expect(screen.getByText(/Tailnet Mesh Devices/i)).toBeInTheDocument();
        });
    });

    describe('NotificationsSettingsTab (F25)', () => {
        it('renders Alert Rules and Delivery Channels', () => {
            render(<NotificationsSettingsTab />);
            expect(screen.getByText(/Alert Dispatcher & Rules/i)).toBeInTheDocument();
            expect(screen.getByText(/High CPU Alert/i)).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Add Rule/i })).toBeInTheDocument();
        });

        it('switches to Delivery Channels section and displays configured channels', () => {
            render(<NotificationsSettingsTab />);
            const channelsBtn = screen.getByRole('button', { name: /Delivery Channels/i });
            fireEvent.click(channelsBtn);
            expect(screen.getByText(/DevOps Discord/i)).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Add Channel/i })).toBeInTheDocument();
        });
    });

    describe('QuotasBillingTab (F26)', () => {
        it('renders user disk quotas and summary telemetry cards', () => {
            render(<QuotasBillingTab />);
            expect(screen.getByText(/Storage Quotas & Billing Sync/i)).toBeInTheDocument();
            expect(screen.getByText(/Total Allocated Storage/i)).toBeInTheDocument();
            expect(screen.getByText(/operator/i)).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Scan Disk/i })).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Edit Quota/i })).toBeInTheDocument();
        });

        it('switches to Billing Webhook Audit Log section', () => {
            render(<QuotasBillingTab />);
            const auditBtn = screen.getByRole('button', { name: /Billing Audit Log/i });
            fireEvent.click(auditBtn);
            expect(screen.getByText(/service_created/i)).toBeInTheDocument();
            expect(screen.getAllByText(/whmcs/i).length).toBeGreaterThan(0);
        });
    });

    describe('ClusterTab (F27)', () => {
        it('renders multi-node cluster mesh with worker node card and metrics', () => {
            render(<ClusterTab />);
            expect(screen.getByText(/Cluster Fleet & Topology/i)).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Enroll Worker Node/i })).toBeInTheDocument();
            expect(screen.getByText(/worker-fra-01/i)).toBeInTheDocument();
            expect(screen.getByText(/10.0.0.15:50051/i)).toBeInTheDocument();
            expect(screen.getByText(/18.5%/i)).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Telemetry & Services/i })).toBeInTheDocument();
        });
    });
});
