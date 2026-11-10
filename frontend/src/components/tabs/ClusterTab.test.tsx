import React from 'react';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ClusterTab from './ClusterTab';
import { apiFetch } from '@/lib/fetcher';

const mockAddToast = jest.fn();
const mockMutate = jest.fn();
const mockNode = {
    id: 'worker-fixture', hostname: 'fixture-worker', address: '192.0.2.7',
    role: 'worker', status: 'online', version: '4.0.0',
    last_heartbeat: '2026-11-06T04:00:00Z', enrolled_at: '2026-11-05T00:00:00Z',
};

jest.mock('swr', () => ({
    __esModule: true,
    default: () => ({ data: { nodes: [mockNode], summary: {} }, isLoading: false, isValidating: false, mutate: mockMutate }),
}));
jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ addToast: mockAddToast }) }));
const mockedApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;

async function inspect(metrics: Record<string, unknown>) {
    mockedApiFetch.mockResolvedValue({ ok: true, json: async () => metrics } as Response);
    render(<ClusterTab />);
    fireEvent.click(screen.getByRole('button', { name: 'Telemetry & Services' }));
    await waitFor(() => expect(mockedApiFetch).toHaveBeenCalledWith('/api/v1/admin/cluster/nodes/worker-fixture/metrics'));
}

beforeEach(() => jest.clearAllMocks());

it('keeps node identity bounded while preserving the full hostname and address', () => {
    render(<ClusterTab />);
    const heading = screen.getByRole('heading', { name: mockNode.hostname });
    expect(heading).toHaveClass('truncate');
    expect(heading).toHaveAttribute('title', mockNode.hostname);
    expect(heading.parentElement).toHaveClass('min-w-0');
    expect(screen.getByText(mockNode.address)).toHaveClass('truncate');
    expect(screen.getByText(mockNode.address)).toHaveAttribute('title', mockNode.address);
});

it('does not describe unknown service inventory as an empty inventory', async () => {
    await inspect({ status: 'online', services: null, services_status: 'unknown', services_observed_at: null });
    expect(await screen.findByText(/Service inventory is unavailable/)).toBeInTheDocument();
    expect(screen.queryByText('No isolated daemon services reported on this worker.')).not.toBeInTheDocument();
});

it('labels retained service states as stale independently of the live node heartbeat', async () => {
    await inspect({
        status: 'online', services_status: 'stale', services_observed_at: 1793937600,
        services: [{ name: 'fixture-app', status: 'running', managed_by: 'systemd', uptime: '1h' }],
    });
    expect(await screen.findByText(/Service inventory is stale/)).toBeInTheDocument();
    expect(screen.getByText('fixture-app')).toBeInTheDocument();
    expect(screen.getByText(/Last observed:/)).toBeInTheDocument();
});

it('describes a fresh successful empty inventory as empty', async () => {
    await inspect({ services: [], services_status: 'fresh', services_observed_at: 1793937600 });
    expect(await screen.findByText('No isolated daemon services reported on this worker.')).toBeInTheDocument();
    expect(screen.queryByText(/Service inventory is unavailable/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Service inventory is stale/)).not.toBeInTheDocument();
});

it('accepts a legacy successful service array without freshness metadata', async () => {
    await inspect({ services: [{ name: 'legacy-fixture-app', status: 'running', managed_by: 'systemd', uptime: '1h' }] });
    expect(await screen.findByText('legacy-fixture-app')).toBeInTheDocument();
    expect(screen.queryByText(/Service inventory is unavailable/)).not.toBeInTheDocument();
});

it('contains inspector focus, dismisses neutrally and restores the telemetry opener', async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValue({ ok: true, json: async () => ({ services: [] }) } as Response);
    render(<ClusterTab />);
    const opener = screen.getByRole('button', { name: 'Telemetry & Services' });
    await user.click(opener);
    const dialog = screen.getByRole('dialog', { name: 'Node Telemetry Inspector' });
    const close = within(dialog).getByRole('button', { name: 'Close Node Telemetry Inspector' });
    expect(close).toHaveFocus();
    await user.tab({ shift: true });
    expect(within(dialog).getByRole('button', { name: 'Decommission Node' })).toHaveFocus();
    await user.tab();
    expect(close).toHaveFocus();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
    expect(mockedApiFetch).toHaveBeenCalledTimes(1);
});

it('does not reopen a dismissed inspector when its metrics response arrives late', async () => {
    const user = userEvent.setup();
    let resolveMetrics!: (response: Response) => void;
    mockedApiFetch.mockImplementation(() => new Promise<Response>((resolve) => { resolveMetrics = resolve; }));
    render(<ClusterTab />);
    await user.click(screen.getByRole('button', { name: 'Telemetry & Services' }));
    await user.keyboard('{Escape}');
    await act(async () => {
        resolveMetrics({ ok: true, json: async () => ({ id: mockNode.id, services: [] }) } as Response);
    });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});

it('keeps full operating-system and network values readable inside the inspector', async () => {
    await inspect({
        system_info: { os: 'Debian GNU/Linux 13 Enterprise Worker', arch: 'aarch64', cpu_cores: 32 },
        metrics: { net_rx_speed: '1234.56 MiB/s', net_tx_speed: '9876.54 MiB/s', uptime: '124 days 18 hours' },
    });
    const os = await screen.findByText('Debian GNU/Linux 13 Enterprise Worker (aarch64)');
    expect(os).toHaveClass('break-words');
    expect(os).not.toHaveClass('truncate');
    expect(screen.getByText('↓ 1234.56 MiB/s')).toHaveClass('block');
    expect(screen.getByText('↑ 9876.54 MiB/s')).toHaveClass('block');
    expect(screen.getByText('124 days 18 hours')).not.toHaveClass('truncate');
});

it('contains enrollment focus and preserves the Done refresh and return-focus behavior', async () => {
    const user = userEvent.setup();
    mockedApiFetch.mockResolvedValue({ ok: true, json: async () => ({ enrollment_token: 'fixture-enrollment-token' }) } as Response);
    render(<ClusterTab />);
    const opener = screen.getByRole('button', { name: /Enroll Worker/ });
    await user.click(opener);
    const dialog = await screen.findByRole('dialog', { name: 'Enroll Remote Worker Node' });
    const close = within(dialog).getByRole('button', { name: 'Close Enroll Remote Worker Node' });
    expect(close).toHaveFocus();
    await user.tab({ shift: true });
    const done = within(dialog).getByRole('button', { name: 'Done' });
    expect(done).toHaveFocus();
    await user.click(done);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
    expect(mockMutate).toHaveBeenCalledTimes(1);
});
