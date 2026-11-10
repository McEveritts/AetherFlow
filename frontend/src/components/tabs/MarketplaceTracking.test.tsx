import React from 'react';
import { render, screen, fireEvent, act } from '@testing-library/react';
import MarketplaceTab from './MarketplaceTab';
import { App, LIFECYCLE_RECEIPT_TIMEOUT_MS } from '@/hooks/useMarketplace';

// Exercise the real hook and component together; only the transport is mocked.
let mockApps: App[] = [];
let mockOptions: { onSuccess: (apps: App[]) => void };
let mockError: Error | undefined;
const mockMutate = jest.fn();
jest.mock('swr', () => ({
    ...jest.requireActual('swr'),
    __esModule: true,
    default: (_key: string, options: typeof mockOptions) => {
        mockOptions = options;
        return { data: mockApps, error: mockError, mutate: mockMutate, isLoading: false };
    },
}));
jest.mock('@/hooks/useMarketplace', () => ({ ...jest.requireActual('@/hooks/useMarketplace'), useGithubDownloads: () => 5000 }));
const mockAddToast = jest.fn();
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ addToast: mockAddToast }) }));
jest.mock('@/lib/svgl', () => ({ getSVGLCatalog: jest.fn().mockResolvedValue([]), matchSVGLLogo: jest.fn().mockReturnValue(null) }));
jest.mock('@/components/ingress/ExternalAccessCard', () => ({ ExternalAccessCard: () => null }));
jest.mock('@/components/deploy/DeploymentStatus', () => ({ DeploymentStatus: () => null }));
const mockApiFetch = jest.fn();
jest.mock('@/lib/fetcher', () => ({ apiFetch: (...args: unknown[]) => mockApiFetch(...args) }));

const app = (extra: Partial<App> = {}): App => ({ id: 'fixture', name: 'Fixture', desc: 'Application', hits: 0, category: 'Media', status: 'installed', progress: 0, update_available: true, latest_version: '2.0', inventory_authenticated: true, ...extra });

describe('Marketplace mounted receipt tracking', () => {
    beforeEach(() => {
        jest.useFakeTimers();
        mockApps = [app()]; mockError = undefined; mockAddToast.mockReset();
        mockApiFetch.mockImplementation(async (url: string) => ({ ok: true, json: async () => url === '/api/v1/auth/plugins' ? { plugins: [] } : { job_id: 'A', started_at: 'now' } }));
    });
    afterEach(() => jest.useRealTimers());

    it.each(['completed', 'failed'])('tracks six minutes of identical active polls, then reports %s once', async status => {
        const view = render(<MarketplaceTab />);
        await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Update' })); });
        mockApps = [app({ status: 'updating', job_id: 'A', progress: 40 })];
        view.rerender(<MarketplaceTab />);
        for (let poll = 0; poll < 6; poll++) {
            act(() => jest.advanceTimersByTime(60000));
            act(() => mockOptions.onSuccess(mockApps));
            expect(mockAddToast.mock.calls.some(call => String(call[0]).includes('may have been superseded'))).toBe(false);
        }
        mockApps = [app({ last_job: { job_id: 'A', action: 'update', status, started_at: 'now', finished_at: 'later', expected_target_version: '2.0', achieved_version: '2.0' } })];
        view.rerender(<MarketplaceTab />);
        const outcomeText = status === 'failed' ? 'update failed' : 'successfully updated';
        expect(mockAddToast.mock.calls.filter(call => String(call[0]).includes(outcomeText))).toHaveLength(1);
        view.rerender(<MarketplaceTab />);
        expect(mockAddToast.mock.calls.filter(call => String(call[0]).includes(outcomeText))).toHaveLength(1);
        expect(screen.getByRole('button', { name: 'Update' })).toBeEnabled();
        view.unmount(); expect(jest.getTimerCount()).toBe(0);
    });

    it.each(['completed', 'failed'])('reports a late %s after the observation deadline without confusing unknown and terminal deduplication', async status => {
        const view = render(<MarketplaceTab />);
        await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Update' })); });
        mockError = new Error('offline');
        view.rerender(<MarketplaceTab />);
        act(() => jest.advanceTimersByTime(LIFECYCLE_RECEIPT_TIMEOUT_MS));
        expect(mockAddToast.mock.calls.filter(call => String(call[0]).includes('may have been superseded'))).toHaveLength(1);
        mockError = undefined;
        // No active observation is required between unknown and the late receipt.
        mockApps = [app({ last_job: { job_id: 'A', action: 'update', status, started_at: 'now', finished_at: 'later', expected_target_version: '2.0', achieved_version: '2.0' } })];
        view.rerender(<MarketplaceTab />);
        const outcomeText = status === 'failed' ? 'update failed' : 'successfully updated';
        expect(mockAddToast.mock.calls.filter(call => String(call[0]).includes(outcomeText))).toHaveLength(1);
        view.rerender(<MarketplaceTab />);
        expect(mockAddToast.mock.calls.filter(call => String(call[0]).includes(outcomeText))).toHaveLength(1);
        view.unmount(); expect(jest.getTimerCount()).toBe(0);
    });
});
