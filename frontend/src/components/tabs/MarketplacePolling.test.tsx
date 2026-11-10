// Exercise the actual SWR cache, retries and shared subscribers; mock network only.
import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import '@testing-library/jest-dom';
import { SWRConfig } from 'swr';
import MarketplaceTab from '@/components/tabs/MarketplaceTab';
import { App, useMarketplace } from '@/hooks/useMarketplace';

jest.mock('@/hooks/useMarketplace', () => ({ ...jest.requireActual('@/hooks/useMarketplace'), useGithubDownloads: () => 5000 }));
const mockAddToast = jest.fn();
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ addToast: mockAddToast }) }));
jest.mock('@/lib/svgl', () => ({ getSVGLCatalog: jest.fn().mockResolvedValue([]), matchSVGLLogo: jest.fn().mockReturnValue(null) }));
jest.mock('@/components/ingress/ExternalAccessCard', () => ({ ExternalAccessCard: () => <div /> }));
jest.mock('@/components/deploy/DeploymentStatus', () => ({ DeploymentStatus: () => <div /> }));
const mockApiFetch = jest.fn();
jest.mock('@/lib/fetcher', () => ({ apiFetch: (...args: unknown[]) => mockApiFetch(...args) }));

const app = (extra: Partial<App> = {}): App => ({ id: 'fixture', name: 'Fixture', desc: 'Application', hits: 0, category: 'Media', status: 'installed', progress: 0, update_available: true, latest_version: '2.0', inventory_authenticated: true, ...extra });
let server: 'idle' | 'active' | 'down' | 'failed' = 'idle';
let fetches = 0;
const fetcher = async () => {
    fetches++;
    if (server === 'down') throw Object.assign(new Error('Request failed: 503'), { status: 503 });
    if (server === 'active') return [app({ status: 'updating', job_id: 'A', started_at: 'now', progress: 40 })];
    if (server === 'failed') return [app({ last_job: { job_id: 'A', action: 'update', status: 'failed', started_at: 'now', finished_at: 'later' } })];
    return [app()];
};
function SecondSubscriber() { useMarketplace(); return null; } // like NotificationDrawer
const prodLike = { provider: () => new Map(), fetcher, dedupingInterval: 5000, errorRetryCount: 3, revalidateOnFocus: false, shouldRetryOnError: true };
const count = (needle: string) => mockAddToast.mock.calls.filter(c => String(c[0]).includes(needle)).length;

async function start() {
    jest.useFakeTimers(); jest.spyOn(Math, 'random').mockReturnValue(0.5);
    server = 'idle'; fetches = 0; mockAddToast.mockReset();
    mockApiFetch.mockImplementation(async (url: string) => ({ ok: true, json: async () => url === '/api/v1/auth/plugins' ? { plugins: [] } : { job_id: 'A', started_at: 'now' } }));
    const view = render(<SWRConfig value={prodLike}><MarketplaceTab /><SecondSubscriber /></SWRConfig>);
    await act(async () => { await jest.advanceTimersByTimeAsync(100); });
    await act(async () => { fireEvent.click(screen.getByTitle('Update to v2.0')); });
    server = 'active';
    return view;
}

it('keeps a shared identical active receipt alive, then reports its failure once', async () => {
    const view = await start();
    await act(async () => { await jest.advanceTimersByTimeAsync(300000); });
    const unknownWhileActive = count('may have been superseded');
    const pollsWhileActive = fetches;
    server = 'failed';
    await act(async () => { await jest.advanceTimersByTimeAsync(20000); });
    expect(pollsWhileActive).toBeGreaterThan(30);
    expect(unknownWhileActive).toBe(0);
    expect(count('update failed')).toBe(1);
    view.unmount(); jest.useRealTimers(); jest.restoreAllMocks();
});

it('automatically recovers after a prolonged outage and reports the late exact failure', async () => {
    const view = await start();
    await act(async () => { await jest.advanceTimersByTimeAsync(10000); });
    server = 'down';
    await act(async () => { await jest.advanceTimersByTimeAsync(200000); });
    const unknownDuringOutage = count('may have been superseded');
    const fetchesAtRecovery = fetches;
    const unreachableShown = !!(screen.queryByText(/Marketplace (?:API )?unreachable/i) || screen.queryByText(/cached inventory/i));
    server = 'failed';
    await act(async () => { await jest.advanceTimersByTimeAsync(300000); });
    const fetchesAfterRecovery = fetches - fetchesAtRecovery;
    const lateFailureAutoShown = count('update failed');

    expect(unknownDuringOutage).toBe(1);
    expect(unreachableShown).toBe(true);
    expect(fetchesAfterRecovery).toBeGreaterThan(0);
    expect(lateFailureAutoShown).toBe(1);
    view.unmount(); jest.useRealTimers(); jest.restoreAllMocks();
});
