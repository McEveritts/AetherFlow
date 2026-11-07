// Scratch proof (not part of the repo). REAL swr 2.4.1, mocked network only.
// Question: can a tracked Services update deadline be renewed by locally
// fabricated/stale SWR data (optimistic control mutate) during a fetch outage?
import React from 'react';
import { act, render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import { SWRConfig } from 'swr';
import ServicesTab from '@/components/tabs/ServicesTab';
import { apiFetch } from '@/lib/fetcher';

const mockAddToast = jest.fn();
jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ addToast: mockAddToast }) }));
jest.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ user: { id: 1, username: 'admin', role: 'admin' }, isAuthenticated: true }) }));
jest.mock('@/store/useSystemStore', () => ({ useSystemStore: () => ({ setActiveTab: jest.fn() }) }));
jest.mock('@/components/auth/RequireClaim', () => function MockRequireClaim({ children }: { children: React.ReactNode }) { return <>{children}</>; });
jest.mock('@/components/tabs/ServiceLogsModal', () => function MockLogs() { return null; });
jest.mock('@/components/ingress/ExternalAccessCard', () => ({ ExternalAccessCard: () => null }));
jest.mock('@/components/deploy/DeploymentStatus', () => ({ DeploymentStatus: () => null }));

const mockedApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;
const svc = (id: string, extra: Record<string, unknown> = {}) => ({ id, process: id, managed_by: 'systemd', status: 'running', version: '1.0', installed_version: '1.0', latest_version: '2.0', update_available: true, uptime: '1h', ...extra });

let mode: 'idle' | 'active' | 'down' | 'failed' = 'idle';
const fetcher = async () => {
    if (mode === 'down') throw new Error('offline');
    if (mode === 'failed') return { Fixture: svc('fixture', { last_job: { job_id: 'accepted-A', action: 'update', status: 'failed', started_at: 'now', finished_at: 'later' } }), Other: svc('other', { update_available: false }) };
    return mode === 'idle'
        ? { Fixture: svc('fixture'), Other: svc('other', { update_available: false, latest_version: '1.0' }) }
        : { Fixture: svc('fixture', { job_id: 'accepted-A', job_status: 'updating', started_at: 'now' }), Other: svc('other', { update_available: false, latest_version: '1.0' }) };
};
const superseded = () => mockAddToast.mock.calls.filter(c => String(c[0]).includes('receipt may have been superseded')).length;

async function scenario(clickOtherControlDuringOutage: boolean) {
    jest.useFakeTimers();
    mode = 'idle'; mockAddToast.mockReset(); mockedApiFetch.mockReset();
    mockedApiFetch.mockImplementation(async (url: RequestInfo | URL) => {
        if (String(url).endsWith('/update')) return { ok: true, json: async () => ({ job_id: 'accepted-A', started_at: 'now' }) } as Response;
        if (String(url).endsWith('/control')) throw new Error('network down');
        return { ok: false, json: async () => ({}) } as Response;
    });
    const view = render(<SWRConfig value={{ provider: () => new Map(), fetcher, dedupingInterval: 0, shouldRetryOnError: false }}><ServicesTab /></SWRConfig>);
    await act(async () => { await jest.advanceTimersByTimeAsync(50); });
    const t0 = Date.now();
    await act(async () => { fireEvent.click(screen.getByTitle('Update Fixture to v2.0')); });
    mode = 'active';
    await act(async () => { await jest.advanceTimersByTimeAsync(1600); }); // one fresh matching active poll
    mode = 'down';
    await act(async () => { await jest.advanceTimersByTimeAsync(3000); }); // fetch now fails; SWR error set
    await act(async () => { await jest.advanceTimersByTimeAsync(100000 - (Date.now() - t0)); });
    if (clickOtherControlDuringOutage) {
        const otherManageButton = screen.getByRole('button', { name: 'Manage Other service actions' });
        fireEvent.click(otherManageButton);
        const enabledRestart = screen.getAllByTitle('Restart service').filter(buttonElement => !(buttonElement as HTMLButtonElement).disabled);
        expect(enabledRestart).toHaveLength(1);
        await act(async () => { fireEvent.click(enabledRestart[0]); });
    }
    await act(async () => { await jest.advanceTimersByTimeAsync(130000 - (Date.now() - t0)); });
    const at130 = superseded();
    await act(async () => { await jest.advanceTimersByTimeAsync(240000 - (Date.now() - t0)); });
    const at240 = superseded();
    view.unmount(); jest.useRealTimers();
    return { at130, at240 };
}

it('control: fetch outage expires the tracked update by ~121.6 s', async () => {
    const r = await scenario(false);
    expect(r.at130).toBe(1);
});

it('an unrelated service control during an outage cannot renew a cached update receipt', async () => {
    const r = await scenario(true);
    // Contract under test (PCR-01): only fresh successful observations renew.
    // Expected: unknown notice by ~121.6 s exactly as in the control run.
    expect(r.at130).toBe(1);
});

it('recovers from a long Services outage and delivers a late failure once', async () => {
    jest.useFakeTimers();
    mode = 'idle'; mockAddToast.mockReset(); mockedApiFetch.mockReset();
    mockedApiFetch.mockResolvedValue({ ok: true, json: async () => ({ job_id: 'accepted-A', started_at: 'now' }) } as Response);
    const view = render(<SWRConfig value={{ provider: () => new Map(), fetcher, dedupingInterval: 5000, errorRetryCount: 3, revalidateOnFocus: false }}><ServicesTab /></SWRConfig>);
    await act(async () => { await jest.advanceTimersByTimeAsync(100); });
    await act(async () => { fireEvent.click(screen.getByTitle('Update Fixture to v2.0')); });
    mode = 'active';
    await act(async () => { await jest.advanceTimersByTimeAsync(10000); });
    mode = 'down';
    await act(async () => { await jest.advanceTimersByTimeAsync(200000); });
    expect(superseded()).toBe(1);
    mode = 'failed';
    await act(async () => { await jest.advanceTimersByTimeAsync(45000); });
    expect(mockAddToast.mock.calls.filter(call => String(call[0]).includes('Fixture: update failed'))).toHaveLength(1);
    view.unmount(); jest.useRealTimers();
});
