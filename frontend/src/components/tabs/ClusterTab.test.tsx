import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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
