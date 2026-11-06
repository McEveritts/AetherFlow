import React from 'react';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { SWRConfig } from 'swr';
import SettingsTab from './SettingsTab';
import { apiFetch } from '@/lib/fetcher';

jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ addToast: jest.fn() }) }));
jest.mock('next-intl', () => ({ useTranslations: () => (key: string) => key }));
jest.mock('next/dynamic', () => () => function Empty() { return null; });
jest.mock('@/components/ui/FlowAiMarkdown', () => function Markdown() { return null; });
jest.mock('@/components/ui/GlassSelect', () => function Select() { return null; });
jest.mock('@/store/useSystemStore', () => ({ useSystemStore: () => ({
    theme: 'dark', language: 'en', ambientColor1: '#111111', ambientColor2: '#222222',
    activeSettingsTab: 'system', setActiveTab: jest.fn(), setActiveSettingsTab: jest.fn(), setLanguage: jest.fn(),
}) }));

const request = jest.mocked(apiFetch);
const unit = 'aetherflow-self-update-deploy-stable-01234567.service';
const storageKey = 'aetherflow_active_update_job_unit';
const running = { job_unit: unit, status: 'running', completed: false, success: false, error: '', exit_code: null };
const response = (body: unknown, status = 200) => ({
    ok: status >= 200 && status < 300, status, json: async () => body,
}) as Response;
let discovery: Response | Error;
let receipt: Response | Error;
let release: Response;
const idle = { state: 'idle', status: 'idle', job_unit: '', active_job_unit: '', completed: true, success: false, error: '', exit_code: null };

async function mount() {
    const cache = new Map();
    let view!: ReturnType<typeof render>;
    await act(async () => {
        view = render(<SWRConfig value={{
            provider: () => cache, fetcher: async (url: string) => (await apiFetch(url)).json(),
            dedupingInterval: 0, revalidateOnFocus: false, isVisible: () => true, isOnline: () => true,
        }}><SettingsTab updatePollIntervalMs={1000} updateMaxPollAttempts={2} /></SWRConfig>);
    });
    return view;
}

const count = (url: string) => request.mock.calls.filter(([target]) => target === url).length;
const receiptUrl = `/api/v1/auth/system/update/status?job_unit=${unit}`;

beforeEach(() => {
    jest.useFakeTimers();
    window.sessionStorage.clear();
    discovery = response({ ...running, state: 'running', action: 'deploy', active_job_unit: unit });
    receipt = response(running);
    release = response({ currentVersion: 'v4.0.0', latestVersion: 'v4.0.1', updateAvailable: true });
    request.mockReset();
    request.mockImplementation(async url => {
        let reply: Response | Error;
        if (url === '/api/v1/auth/settings') return response({ timezone: 'UTC', updateChannel: 'stable' });
        if (url === '/api/v1/auth/system/update/check') return release;
        if (url === '/api/v1/auth/system/update/status') reply = discovery;
        else if (url === receiptUrl || String(url).includes('?job_unit=')) reply = receipt;
        else throw new Error(`Unexpected fixture route ${url}`);
        if (reply instanceof Error) throw reply;
        return reply;
    });
});

afterEach(() => { cleanup(); jest.clearAllTimers(); jest.useRealTimers(); });

it('discovers the real Rust response shape and polls its durable job without launching', async () => {
    await mount();
    expect(count(receiptUrl)).toBe(1);
    expect(window.sessionStorage.getItem(storageKey)).toBe(unit);
    expect(screen.getByTestId('run-system-update-button')).toBeDisabled();
    expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'pending');
});

it.each([401, 403, 404, 400, 422])('stops discovery retries on permanent HTTP %s and never enables launch', async status => {
    discovery = response({ message: 'Observation rejected' }, status);
    await mount();
    await act(async () => { await jest.advanceTimersByTimeAsync(120000); });
    expect(count('/api/v1/auth/system/update/status')).toBe(1);
    expect(screen.getByTestId('run-system-update-button')).toBeDisabled();
    expect(screen.getByRole('alert')).toHaveTextContent(/authorization|unavailable|rejected|authenticate/i);
});

it.each([401, 403, 404])('retains the tracked job but stops scoped retries on permanent HTTP %s', async status => {
    receipt = response({ message: 'Tracked observation rejected' }, status);
    await mount();
    await act(async () => { await jest.advanceTimersByTimeAsync(90000); });
    expect(count(receiptUrl)).toBe(1);
    expect(window.sessionStorage.getItem(storageKey)).toBe(unit);
    expect(screen.getByTestId('run-system-update-button')).toBeDisabled();
});

it('does not turn failed discovery or an unsupported old backend into idle', async () => {
    discovery = response({ message: 'job_unit query parameter is required' }, 400);
    await mount();
    expect(screen.getByTestId('run-system-update-button')).toBeDisabled();
    expect(count(receiptUrl)).toBe(0);
});

it('permits a verified available release only after successful idle discovery, without asserting runtime completion', async () => {
    discovery = response(idle);
    await mount();
    expect(screen.getByTestId('run-system-update-button')).toBeEnabled();
    expect(screen.queryByText(/running the latest release/i)).not.toBeInTheDocument();
});

it('does not follow a discovery action that disagrees with the durable identity', async () => {
    discovery = response({ ...running, state: 'running', action: 'rollback', active_job_unit: unit });
    await mount();
    expect(count(receiptUrl)).toBe(0);
    expect(screen.getByTestId('run-system-update-button')).toBeDisabled();
});

it('retains the original job when a terminal scoped receipt belongs to another action', async () => {
    receipt = response({ ...running, action: 'rollback', status: 'succeeded', completed: true, success: true, exit_code: 0 });
    await mount();
    expect(window.sessionStorage.getItem(storageKey)).toBe(unit);
    expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'error');
    expect(screen.getByTestId('run-system-update-button')).toBeDisabled();
});

it.each([408, 429, 500, 503])('recovers transient discovery HTTP %s without an idle or duplicate-launch gap', async status => {
    discovery = response({ message: 'Temporarily unavailable' }, status);
    await mount();
    expect(screen.getByTestId('run-system-update-button')).toBeDisabled();
    discovery = response({ ...running, state: 'running', action: 'deploy', active_job_unit: unit });
    await act(async () => { await jest.advanceTimersByTimeAsync(2100); });
    expect(count(receiptUrl)).toBe(1);
    expect(screen.getByTestId('run-system-update-button')).toBeDisabled();
});

it('stops release-check authorization retries even when discovery succeeds', async () => {
    discovery = response(idle);
    release = response({ message: 'Release authorization revoked' }, 403);
    await mount();
    await act(async () => { await jest.advanceTimersByTimeAsync(120000); });
    expect(count('/api/v1/auth/system/update/check')).toBe(1);
    expect(screen.getByRole('alert')).toHaveTextContent(/authorization/i);
});

it('does not refresh the successful observation timestamp during transport failures', async () => {
    await mount();
    receipt = new Error('API still restarting');
    discovery = new Error('API still restarting');
    await act(async () => { await jest.advanceTimersByTimeAsync(18000); });
    expect(screen.getByTestId('run-system-update-button')).toBeDisabled();
    expect(screen.getByTestId('system-update-status')).toHaveTextContent(/Reconnecting/i);
    expect(screen.getByRole('status')).toHaveTextContent(/stale|unverified/i);
});

it('keeps an unknown durable job until a matching late terminal receipt arrives', async () => {
    receipt = response({ ...running, status: 'unknown' });
    await mount();
    expect(window.sessionStorage.getItem(storageKey)).toBe(unit);
    expect(screen.getByTestId('run-system-update-button')).toBeDisabled();
    receipt = response({ ...running, status: 'succeeded', completed: true, success: true, exit_code: 0 });
    await act(async () => { await jest.advanceTimersByTimeAsync(16000); });
    expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'success');
    expect(window.sessionStorage.getItem(storageKey)).toBeNull();
    expect(screen.queryByText(/running the latest release/i)).not.toBeInTheDocument();
});

it('preserves the stored identity when global discovery advertises a different job', async () => {
    const previous = 'aetherflow-self-update-deploy-nightly-89abcdef.service';
    window.sessionStorage.setItem(storageKey, previous);
    receipt = new Error('API restarting');
    await mount();
    expect(count(`/api/v1/auth/system/update/status?job_unit=${previous}`)).toBe(1);
    expect(count(receiptUrl)).toBe(0);
    expect(window.sessionStorage.getItem(storageKey)).toBe(previous);
});

it('cleans pending scoped and discovery recovery timers on unmount', async () => {
    receipt = new Error('API restarting');
    const view = await mount();
    await act(async () => { await jest.advanceTimersByTimeAsync(100); });
    view.unmount();
    const before = request.mock.calls.length;
    await act(async () => { await jest.advanceTimersByTimeAsync(120000); });
    expect(request).toHaveBeenCalledTimes(before);
    expect(jest.getTimerCount()).toBe(0);
});

it('cleans SWR transport-recovery timers on unmount', async () => {
    discovery = new Error('Offline');
    const view = await mount();
    view.unmount();
    const before = request.mock.calls.length;
    await act(async () => { await jest.advanceTimersByTimeAsync(120000); });
    expect(request).toHaveBeenCalledTimes(before);
    expect(jest.getTimerCount()).toBe(0);
});

it('aborts a pending launch on unmount without a late observation request', async () => {
    discovery = response(idle);
    const route = request.getMockImplementation()!;
    request.mockImplementation((url, init) => url === '/api/v1/admin/system/update/run'
        ? new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () => reject(new Error('Aborted')));
        }) : route(url, init));
    const view = await mount();
    await act(async () => { fireEvent.click(screen.getByTestId('run-system-update-button')); });
    view.unmount();
    const before = request.mock.calls.length;
    await act(async () => { await jest.advanceTimersByTimeAsync(120000); });
    expect(request).toHaveBeenCalledTimes(before);
    expect(jest.getTimerCount()).toBe(0);
});

it('allows an explicit refresh after authorization has been restored', async () => {
    discovery = response({ message: 'Authorization revoked' }, 403);
    await mount();
    discovery = response({ ...running, state: 'running', action: 'deploy', active_job_unit: unit });
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: /Check for Updates/ })); });
    expect(count(receiptUrl)).toBe(1);
});
