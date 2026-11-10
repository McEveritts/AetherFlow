import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import NetworkTab from '@/components/tabs/NetworkTab';
import NotificationsSettingsTab from '@/components/tabs/NotificationsSettingsTab';
import QuotasTab from '@/components/tabs/QuotasTab';
import ClusterTab from '@/components/tabs/ClusterTab';
import AuditTab from '@/components/tabs/AuditTab';

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
        if (key.includes('/admin/audit-log')) {
            return {
                data: {
                    entries: [
                        {
                            id: 1,
                            user_id: 1,
                            username: 'operator',
                            action: 'system_update',
                            target_type: 'service',
                            target_id: 'aetherflow-core',
                            detail: 'Applied core security and networking update',
                            ip_address: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
                            user_agent: 'AetherFlow-Console/4.0',
                            created_at: '2026-11-09T08:00:00Z',
                        },
                    ],
                    total: 1,
                    limit: 25,
                    offset: 0,
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

    describe('QuotasTab (F26)', () => {
        it('renders user disk quotas and summary telemetry cards', () => {
            render(<QuotasTab />);
            expect(screen.getByText(/Storage Quotas/i)).toBeInTheDocument();
            expect(screen.getByText(/Total Allocated Storage/i)).toBeInTheDocument();
            expect(screen.getByText(/Quota Enforcement Status/i)).toBeInTheDocument();
            expect(screen.getByText(/operator/i)).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Scan Disk/i })).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Edit Quota/i })).toBeInTheDocument();
        });

        it('opens Edit Disk Quota with readable allocation and exact byte context', () => {
            render(<QuotasTab />);
            const editBtn = screen.getByRole('button', { name: /Edit Quota/i });
            fireEvent.click(editBtn);
            expect(screen.getByText(/Update Disk Quota/i)).toBeInTheDocument();
            expect(screen.getByRole('textbox', { name: 'Allocated Disk Space' })).toHaveValue('100GB');
            expect(screen.getByText('107,374,182,400 bytes exactly')).toBeInTheDocument();
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

    describe('AuditTab (Compliance)', () => {
        it('renders scoped table constraints and wraps long IP addresses without clipping', () => {
            render(<AuditTab />);
            const auditTable = screen.getByRole('table', { name: /Audit records/i });
            expect(auditTable).toHaveClass('obs-mobile-ledger', 'lg:table-fixed', 'w-full', 'min-w-0');
            expect(auditTable.parentElement).toHaveClass('overflow-x-auto', 'min-w-0', 'max-w-full');

            const ipHeader = screen.getByRole('columnheader', { name: 'IP' });
            expect(ipHeader).toHaveClass('lg:w-[140px]');

            const ipCell = screen.getByRole('cell', { name: '2001:0db8:85a3:0000:0000:8a2e:0370:7334' });
            expect(ipCell).toHaveAttribute('data-label', 'IP');
            expect(ipCell).toHaveClass('break-words', '[overflow-wrap:anywhere]', 'min-w-0');
            expect(ipCell).not.toHaveClass('truncate', 'overflow-hidden');
            for (const recordAction of screen.getAllByRole('button', { name: /View full audit record/i })) {
                expect(recordAction).toHaveClass('w-full', 'min-w-0', 'max-w-[220px]');
            }
        });
    });
});
