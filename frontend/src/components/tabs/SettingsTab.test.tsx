import React from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { SWRConfig, useSWRConfig } from 'swr';
import SettingsTab from './SettingsTab';
import { apiFetch } from '@/lib/fetcher';
import type { SystemUpdateCheck, SystemUpdateStatus } from '@/lib/system-update';

const mockAddToast = jest.fn();
let mockActiveTab = 'system';

jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ addToast: mockAddToast }) }));
jest.mock('next-intl', () => ({ useTranslations: () => (key: string) => key }));
jest.mock('next/dynamic', () => () => function MockDynamicTab() { return null; });
jest.mock('@/components/ui/FlowAiMarkdown', () => function MockMarkdown({ content }: { content: string }) {
    return <p>{content}</p>;
});
jest.mock('@/components/ui/GlassSelect', () => function MockSelect({
    value, onChange, ariaLabel, options,
}: { value: string; onChange: (value: string) => void; ariaLabel: string; options: { value: string; label: string }[] }) {
    return <select aria-label={ariaLabel} value={value} onChange={event => onChange(event.target.value)}>
        {options.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
    </select>;
});
jest.mock('@/store/useSystemStore', () => ({
    useSystemStore: () => ({
        theme: 'dark', language: 'en', ambientColor1: '#111111', ambientColor2: '#222222',
        activeSettingsTab: mockActiveTab, setActiveTab: jest.fn(), setActiveSettingsTab: jest.fn(), setLanguage: jest.fn(),
    }),
}));

const mockedApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;

function response(data: unknown, status = 200): Response {
    return { ok: status >= 200 && status < 300, status, json: async () => data } as Response;
}

function deferredResponse() {
    let resolve!: (value: Response) => void;
    const promise = new Promise<Response>(done => { resolve = done; });
    return { promise, resolve };
}

function RefreshSettings() {
    const { mutate } = useSWRConfig();
    return <button onClick={() => void mutate('/api/v1/auth/settings')}>Refresh settings data</button>;
}

async function renderSettings(props: React.ComponentProps<typeof SettingsTab> = {}) {
    const cache = new Map();
    await act(async () => {
        render(
            <SWRConfig value={{
                provider: () => cache,
                fetcher: async (url: string) => (await apiFetch(url)).json(),
                dedupingInterval: 0, errorRetryCount: 3, revalidateOnFocus: false,
                isVisible: () => true, isOnline: () => true,
            }}>
                <SettingsTab {...props} />
                <RefreshSettings />
            </SWRConfig>
        );
    });
}

async function click(element: HTMLElement) {
    await act(async () => { fireEvent.click(element); });
}

function mockJobStatus(jobUnit: string, replies: (Response | Error)[]) {
    const route = mockedApiFetch.getMockImplementation()!;
    let index = 0;
    const poll = jest.fn(async () => {
        const reply = replies[Math.min(index++, replies.length - 1)];
        if (reply instanceof Error) throw reply;
        return reply;
    });
    mockedApiFetch.mockImplementation((url, init) => {
        if (url === `/api/v1/auth/system/update/status?job_unit=${encodeURIComponent(jobUnit)}`) return poll();
        return route(url, init);
    });
    return poll;
}

describe('SettingsTab system update lifecycle and settings drafts', () => {
    let status: SystemUpdateStatus;
    let check: SystemUpdateCheck;
    let settings: Record<string, string>;
    let statusFailures: number;
    let runUpdate: jest.Mock<Promise<Response>, []>;
    let saveSettings: jest.Mock<Promise<Response>, []>;

    beforeEach(() => {
        jest.useFakeTimers();
        jest.spyOn(Math, 'random').mockReturnValue(0.5);
        mockActiveTab = 'system';
        window.sessionStorage.clear();
        mockAddToast.mockReset();
        status = {
            state: 'idle', operationId: null, phase: null, error: null, selectedVersion: 'v4.0.0',
            currentVersion: 'v4.0.0', runnerVersion: 'v4.0.0',
        };
        check = { currentVersion: 'v4.0.0', latestVersion: 'v4.0.1', updateAvailable: true };
        settings = { baseDomain: 'saved.example.test', timezone: 'UTC', updateChannel: 'stable' };
        statusFailures = 0;
        runUpdate = jest.fn(async () => response({ message: 'Launcher acknowledged', operationId: 'update-2' }, 202));
        saveSettings = jest.fn(async () => response({ message: 'Saved' }));
        mockedApiFetch.mockReset();
        mockedApiFetch.mockImplementation(async (url, init) => {
            if (url === '/api/v1/auth/settings') return response(settings);
            if (url === '/api/v1/admin/settings' && init?.method === 'PUT') return saveSettings();
            if (url === '/api/v1/auth/system/update/check') return response(check);
            if (url === '/api/v1/auth/system/update/status') {
                if (statusFailures > 0) {
                    statusFailures -= 1;
                    throw new Error('API restarting');
                }
                return response(status);
            }
            if (url === '/api/v1/admin/system/update/run') return runUpdate();
            throw new Error(`Unexpected request: ${url}`);
        });
    });

    afterEach(() => {
        cleanup();
        window.sessionStorage.clear();
        jest.clearAllTimers();
        jest.useRealTimers();
        jest.restoreAllMocks();
    });

    it('never infers latest from an unsuccessful GitHub check returning updateAvailable=false', async () => {
        check = { ...check, updateAvailable: false, latestVersion: 'Unknown (API Error or Rate Limited)', error: 'github_rate_limited' };
        await renderSettings();
        expect(await screen.findByText(/upstream release is unknown/i)).toBeInTheDocument();
        expect(screen.queryByText(/running the latest release/i)).not.toBeInTheDocument();
    });

    it('does not report completion when selected release B is not the actual runtime A', async () => {
        status = { ...status, state: 'complete', operationId: 'update-1', selectedVersion: 'v4.0.1' };
        await renderSettings();
        expect(await screen.findByText(/Runtime verification required/)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Update to v4.0.1' })).toBeDisabled();
        expect(screen.queryByText(/running the latest release/i)).not.toBeInTheDocument();
    });

    it('blocks duplicate clicks during acknowledgement and displays restart-surviving progress', async () => {
        const acknowledgement = deferredResponse();
        runUpdate.mockReturnValue(acknowledgement.promise);
        await renderSettings();
        const button = await screen.findByRole('button', { name: 'Update to v4.0.1' });
        await waitFor(() => expect(button).toBeEnabled());
        await act(async () => {
            fireEvent.click(button);
            fireEvent.click(button);
        });
        expect(runUpdate).toHaveBeenCalledTimes(1);
        expect(screen.getByRole('button', { name: 'Updating System...' })).toBeDisabled();
        status = { ...status, state: 'running', operationId: 'update-2', phase: 'snapshot', selectedVersion: 'v4.0.1' };
        await act(async () => acknowledgement.resolve(response({ operationId: 'update-2' }, 202)));
        expect(await screen.findByText(/Updating system: snapshot/)).toBeInTheDocument();
        expect(screen.queryByText(/running the latest release/i)).not.toBeInTheDocument();
    });

    it('shows message-only backend rejection errors rather than silently reporting success', async () => {
        runUpdate.mockResolvedValue(response({ message: 'Native launcher is unavailable' }, 503));
        await renderSettings();
        const button = await screen.findByRole('button', { name: 'Update to v4.0.1' });
        await waitFor(() => expect(button).toBeEnabled());
        await click(button);
        expect(await screen.findByRole('alert')).toHaveTextContent('Native launcher is unavailable');
        expect(screen.queryByText(/running the latest release/i)).not.toBeInTheDocument();
    });

    it('prevents a launch when the independent updater reports interrupted recovery', async () => {
        status = { ...status, state: 'interrupted', operationId: 'update-1', error: 'Restore the native recovery journal' };
        await renderSettings();
        expect(await screen.findByRole('alert')).toHaveTextContent('Recovery required');
        await click(screen.getByRole('button', { name: 'Update to v4.0.1' }));
        expect(runUpdate).not.toHaveBeenCalled();
    });

    it('continues reconnecting beyond the global three-retry limit and verifies the restarted runtime', async () => {
        status = { ...status, state: 'running', operationId: 'update-2', phase: 'restart', selectedVersion: 'v4.0.1' };
        await renderSettings();
        await screen.findByText(/Updating system: restart/);
        statusFailures = 5;
        status = { ...status, state: 'complete', currentVersion: 'v4.0.1', runnerVersion: 'v4.0.1', phase: 'complete' };
        check = { currentVersion: 'v4.0.1', latestVersion: 'v4.0.1', updateAvailable: false };
        await act(async () => { await jest.advanceTimersByTimeAsync(2000); });
        expect(screen.getByText(/Reconnecting automatically/)).toBeInTheDocument();
        expect(screen.queryByText(/running the latest release/i)).not.toBeInTheDocument();
        await act(async () => { await jest.advanceTimersByTimeAsync(15000); });
        expect(statusFailures).toBe(0);
        expect(screen.getByText(/running the latest release on the stable channel/)).toBeInTheDocument();
        expect(mockedApiFetch.mock.calls.filter(([url]) => url === '/api/v1/auth/system/update/status').length).toBeGreaterThan(6);
    });

    it('does not resubmit an ambiguous POST and resumes from its confirmed operation', async () => {
        runUpdate.mockRejectedValue(new Error('Connection reset'));
        await renderSettings();
        const button = await screen.findByRole('button', { name: 'Update to v4.0.1' });
        await waitFor(() => expect(button).toBeEnabled());
        await click(button);
        expect(await screen.findByText(/trigger response was lost/)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Updating System...' })).toBeDisabled();
        status = { ...status, state: 'running', operationId: 'update-2', phase: 'verify' };
        await act(async () => { await jest.advanceTimersByTimeAsync(2000); });
        expect(screen.getByText(/Updating system: verify/)).toBeInTheDocument();
        expect(runUpdate).toHaveBeenCalledTimes(1);
    });

    it('preserves an unsaved channel across background SWR refreshes without changing the launch target', async () => {
        settings = { ...settings, updateChannel: 'nightly' };
        await renderSettings();
        const channel = await screen.findByRole('combobox', { name: 'Update Channel' });
        fireEvent.change(channel, { target: { value: 'stable' } });
        settings = { ...settings, updateChannel: 'experimental' };
        await click(screen.getByRole('button', { name: 'Refresh settings data' }));
        await waitFor(() => expect(mockedApiFetch.mock.calls.filter(([url]) => url === '/api/v1/auth/settings')).toHaveLength(2));
        expect(channel).toHaveValue('stable');
        expect(screen.getByRole('button', { name: 'Update to v4.0.1' })).toBeDisabled();
    });

    it('preserves dirty settings while following untouched server values on background refresh', async () => {
        mockActiveTab = 'preferences';
        await renderSettings();
        const domain = await screen.findByDisplayValue('saved.example.test');
        fireEvent.change(domain, { target: { value: 'unsaved.example.test' } });
        settings = { ...settings, baseDomain: 'remote.example.test', timezone: 'Europe/London' };
        await click(screen.getByRole('button', { name: 'Refresh settings data' }));
        await waitFor(() => expect(screen.getByRole('combobox', { name: 'Timezone' })).toHaveValue('Europe/London'));
        expect(domain).toHaveValue('unsaved.example.test');
    });

    it('follows authoritative normalized values after a save rather than retaining the old draft', async () => {
        mockActiveTab = 'preferences';
        const save = deferredResponse();
        saveSettings.mockReturnValue(save.promise);
        await renderSettings();
        const domain = await screen.findByDisplayValue('saved.example.test');
        fireEvent.change(domain, { target: { value: '  Draft.Example.Test  ' } });
        await click(screen.getByRole('button', { name: 'Save Configuration' }));
        settings = { ...settings, baseDomain: 'draft.example.test' };
        await act(async () => save.resolve(response({ message: 'Saved' })));
        expect(await screen.findByDisplayValue('draft.example.test')).toBeInTheDocument();
    });

    it('preserves edits made while a save is pending and still follows authoritative untouched fields', async () => {
        mockActiveTab = 'preferences';
        const save = deferredResponse();
        saveSettings.mockReturnValue(save.promise);
        await renderSettings();
        const domain = await screen.findByDisplayValue('saved.example.test');
        fireEvent.change(domain, { target: { value: 'submitted.example.test' } });
        await click(screen.getByRole('button', { name: 'Save Configuration' }));
        fireEvent.change(domain, { target: { value: 'newer.example.test' } });
        settings = { ...settings, baseDomain: 'submitted.example.test', timezone: 'Europe/London' };
        await act(async () => save.resolve(response({ message: 'Saved' })));
        await waitFor(() => expect(screen.getByRole('combobox', { name: 'Timezone' })).toHaveValue('Europe/London'));
        expect(domain).toHaveValue('newer.example.test');
        expect(saveSettings).toHaveBeenCalledTimes(1);
    });

    it('displays the independent updater failure even when release checking succeeds', async () => {
        status = { ...status, state: 'failed', operationId: 'update-1', error: 'Downloaded binary verification failed' };
        await renderSettings();
        expect(screen.getByRole('alert')).toHaveTextContent('Downloaded binary verification failed');
        expect(screen.queryByText(/running the latest release/i)).not.toBeInTheDocument();
    });

    it('follows later external operations after this tab has completed its own launch', async () => {
        await renderSettings();
        await click(screen.getByRole('button', { name: 'Update to v4.0.1' }));
        status = { ...status, state: 'complete', operationId: 'update-2', selectedVersion: 'v4.0.1', currentVersion: 'v4.0.1', runnerVersion: 'v4.0.1' };
        check = { ...check, currentVersion: 'v4.0.1', latestVersion: 'v4.0.1', updateAvailable: false };
        await act(async () => { await jest.advanceTimersByTimeAsync(2500); });
        expect(screen.getByText(/running the latest release/)).toBeInTheDocument();
        status = { ...status, state: 'running', operationId: 'update-3', phase: 'restart' };
        await act(async () => { await jest.advanceTimersByTimeAsync(2500); });
        expect(screen.getByRole('button', { name: 'Updating System...' })).toBeDisabled();
        status = { ...status, state: 'complete', selectedVersion: 'v4.0.2', currentVersion: 'v4.0.2', runnerVersion: 'v4.0.2' };
        check = { ...check, currentVersion: 'v4.0.2', latestVersion: 'v4.0.2', updateAvailable: false };
        await act(async () => { await jest.advanceTimersByTimeAsync(2500); });
        expect(screen.getByText(/running the latest release/)).toBeInTheDocument();
        check = { ...check, latestVersion: 'v4.0.3', updateAvailable: true };
        await click(screen.getByRole('button', { name: /Check for Updates/ }));
        expect(screen.getByRole('button', { name: 'Update to v4.0.3' })).toBeEnabled();
    });

    it('does not reuse a previous channel check after saving a new release channel', async () => {
        check = { currentVersion: 'v4.0.0', latestVersion: 'v4.0.0', updateAvailable: false };
        await renderSettings();
        expect(screen.getByText(/running the latest release on the stable channel/)).toBeInTheDocument();
        fireEvent.change(screen.getByRole('combobox', { name: 'Update Channel' }), { target: { value: 'nightly' } });
        settings = { ...settings, updateChannel: 'nightly' };
        check = { ...check, latestVersion: 'Unknown (API Error or Rate Limited)', error: 'github_rate_limited' };
        await click(screen.getByRole('button', { name: 'Save Configuration' }));
        expect(screen.getByText(/upstream release is unknown/i)).toBeInTheDocument();
        expect(screen.queryByText(/running the latest release/i)).not.toBeInTheDocument();
        expect(mockedApiFetch.mock.calls.filter(([url]) => url === '/api/v1/auth/system/update/check')).toHaveLength(2);
    });

    it('times out a hung launch response without blindly retrying the POST', async () => {
        const route = mockedApiFetch.getMockImplementation()!;
        mockedApiFetch.mockImplementation((url, init) => {
            if (url === '/api/v1/admin/system/update/run') {
                return new Promise<Response>((resolve, reject) => {
                    init?.signal?.addEventListener('abort', () => reject(new Error('Request timed out')));
                });
            }
            return route(url, init);
        });
        await renderSettings();
        await click(screen.getByRole('button', { name: 'Update to v4.0.1' }));
        await act(async () => { await jest.advanceTimersByTimeAsync(10000); });
        expect(screen.getByText(/trigger response was lost/)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Updating System...' })).toBeDisabled();
        expect(mockedApiFetch.mock.calls.filter(([url]) => url === '/api/v1/admin/system/update/run')).toHaveLength(1);
    });

    it('offers only stable and nightly and normalizes legacy experimental settings and release checks to nightly', async () => {
        settings = { ...settings, updateChannel: 'experimental' };
        Object.assign(check, { channel: 'experimental' });
        await renderSettings();
        const channel = screen.getByRole('combobox', { name: 'Update Channel' });
        expect(channel).toHaveValue('nightly');
        expect(screen.getAllByRole('option').filter(option => option.closest('select') === channel)).toHaveLength(2);
        expect(screen.queryByRole('option', { name: 'Experimental' })).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Update to v4.0.1' })).toBeEnabled();
        await click(screen.getByRole('button', { name: 'Save Configuration' }));
        const request = mockedApiFetch.mock.calls.find(([url]) => url === '/api/v1/admin/settings');
        expect(JSON.parse(String(request?.[1]?.body)).updateChannel).toBe('nightly');
    });

    it('polls the exact initiated job and accepts only its confirmed terminal success without duplicate POSTs', async () => {
        const jobUnit = 'aetherflow-self-update-deploy-stable-a1b2c3d4.service';
        runUpdate.mockResolvedValue(response({ status: 'initiated', completed: false, job_unit: jobUnit }));
        const poll = mockJobStatus(jobUnit, [
            response({ status: 'running', completed: false, success: false, job_unit: jobUnit, error: '', exit_code: null }),
            response({ status: 'succeeded', completed: true, success: true, job_unit: jobUnit, error: '', exit_code: 0 }),
        ]);
        await renderSettings({ updatePollIntervalMs: 10, updateMaxPollAttempts: 5 });
        const button = screen.getByRole('button', { name: 'Update to v4.0.1' });
        await act(async () => { fireEvent.click(button); fireEvent.click(button); });
        expect(runUpdate).toHaveBeenCalledTimes(1);
        expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'pending');
        expect(window.sessionStorage.getItem('aetherflow_active_update_job_unit')).toBe(jobUnit);
        expect(screen.getByRole('button', { name: 'Updating System...' })).toBeDisabled();
        await act(async () => { await jest.advanceTimersByTimeAsync(10); });
        expect(poll).toHaveBeenCalledTimes(2);
        expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'success');
        expect(screen.getByTestId('system-update-status')).toHaveTextContent(`System update completed successfully (${jobUnit}).`);
        expect(window.sessionStorage.getItem('aetherflow_active_update_job_unit')).toBeNull();
        expect(screen.queryByText(/running the latest release/i)).not.toBeInTheDocument();
        expect(mockedApiFetch.mock.calls.filter(([url]) => url === '/api/v1/auth/system/update/check').length).toBeGreaterThan(1);
    });

    it('surfaces a terminal nonzero exit as failure rather than a completed update', async () => {
        const jobUnit = 'aetherflow-self-update-deploy-stable-deadbeef.service';
        runUpdate.mockResolvedValue(response({ status: 'initiated', completed: false, job_unit: jobUnit }));
        mockJobStatus(jobUnit, [response({
            status: 'failed', completed: true, success: false, job_unit: jobUnit,
            error: 'Release verification failed during stage3_health_probe.', exit_code: 12,
        })]);
        await renderSettings();
        await click(screen.getByRole('button', { name: 'Update to v4.0.1' }));
        expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'error');
        expect(screen.getByTestId('system-update-status')).toHaveTextContent('Release verification failed during stage3_health_probe.');
        expect(screen.queryByText(/completed successfully/)).not.toBeInTheDocument();
        expect(window.sessionStorage.getItem('aetherflow_active_update_job_unit')).toBeNull();
    });

    it.each([
        { status: 'unknown', completed: false },
        { status: 'missing', completed: false },
        { status: 'succeeded', completed: false, success: true, exit_code: 0 },
        { status: 'succeeded', completed: true, success: false, exit_code: 0 },
        { status: 'succeeded', completed: true, success: true, exit_code: 7 },
        { status: 'succeeded', completed: true, success: true },
        { status: 'running', completed: false, exit_code: 3 },
        { status: 'succeeded', completed: true, success: true, exit_code: 0, job_unit: 'nginx.service' },
        { status: 'succeeded', completed: true, success: true, exit_code: 0, job_unit: '' },
    ])('rejects unknown, inconsistent, or mismatched durable status: %j', async payload => {
        const jobUnit = 'aetherflow-self-update-deploy-stable-11223344.service';
        runUpdate.mockResolvedValue(response({ status: 'initiated', completed: false, job_unit: jobUnit }));
        mockJobStatus(jobUnit, [response({ job_unit: jobUnit, ...payload })]);
        await renderSettings();
        await click(screen.getByRole('button', { name: 'Update to v4.0.1' }));
        expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'error');
        expect(screen.queryByText(/completed successfully/)).not.toBeInTheDocument();
    });

    it('treats a missing tracked job HTTP response as an error rather than success', async () => {
        const jobUnit = 'aetherflow-self-update-deploy-nightly-feedface.service';
        runUpdate.mockResolvedValue(response({ status: 'initiated', completed: false, job_unit: jobUnit }));
        mockJobStatus(jobUnit, [response({ error: 'Tracked update unit could not be found' }, 404)]);
        await renderSettings();
        await click(screen.getByRole('button', { name: 'Update to v4.0.1' }));
        expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'error');
        expect(screen.getByTestId('system-update-status')).toHaveTextContent('Tracked update unit could not be found');
    });

    it.each(['', 'nginx.service'])('does not poll an invalid initiation job unit: %s', async jobUnit => {
        runUpdate.mockResolvedValue(response({ status: 'initiated', completed: false, job_unit: jobUnit }));
        await renderSettings();
        await click(screen.getByRole('button', { name: 'Update to v4.0.1' }));
        expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'error');
        expect(screen.getByTestId('system-update-status')).toHaveTextContent('invalid or missing self-update job unit');
        expect(mockedApiFetch.mock.calls.some(([url]) => String(url).includes('?job_unit='))).toBe(false);
    });

    it('keeps the durable job across API restarts and polling batches until it really completes', async () => {
        const jobUnit = 'aetherflow-self-update-deploy-stable-1234abcd.service';
        runUpdate.mockResolvedValue(response({ status: 'initiated', completed: false, job_unit: jobUnit }));
        const poll = mockJobStatus(jobUnit, [
            new Error('API restarting'),
            response({ error: 'API is still restarting' }, 503),
            response({ status: 'running', completed: false, success: false, job_unit: jobUnit, error: '', exit_code: null }),
            response({ status: 'succeeded', completed: true, success: true, job_unit: jobUnit, error: '', exit_code: 0 }),
        ]);
        await renderSettings({ updatePollIntervalMs: 10, updateMaxPollAttempts: 2 });
        await click(screen.getByRole('button', { name: 'Update to v4.0.1' }));
        expect(window.sessionStorage.getItem('aetherflow_active_update_job_unit')).toBe(jobUnit);
        expect(screen.getByRole('button', { name: 'Updating System...' })).toBeDisabled();
        await act(async () => { await jest.advanceTimersByTimeAsync(10); });
        expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'pending');
        expect(window.sessionStorage.getItem('aetherflow_active_update_job_unit')).toBe(jobUnit);
        await act(async () => { await jest.advanceTimersByTimeAsync(30); });
        expect(poll).toHaveBeenCalledTimes(4);
        expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'success');
        expect(runUpdate).toHaveBeenCalledTimes(1);
    });

    it('recovers an in-flight job from session storage without resubmitting an update', async () => {
        const jobUnit = 'aetherflow-self-update-deploy-stable-0123456789abcdef.service';
        window.sessionStorage.setItem('aetherflow_active_update_job_unit', jobUnit);
        const poll = mockJobStatus(jobUnit, [response({
            status: 'succeeded', completed: true, success: true, job_unit: jobUnit, error: '', exit_code: 0,
        })]);
        await renderSettings();
        expect(poll).toHaveBeenCalledTimes(1);
        expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'success');
        expect(window.sessionStorage.getItem('aetherflow_active_update_job_unit')).toBeNull();
        expect(runUpdate).not.toHaveBeenCalled();
    });

    it('recovers a backend-advertised active durable job even without browser storage', async () => {
        const jobUnit = 'aetherflow-self-update-deploy-nightly-abcddcba.service';
        Object.assign(check, { active_job_unit: jobUnit });
        mockJobStatus(jobUnit, [response({
            status: 'succeeded', completed: true, success: true, job_unit: jobUnit, error: '', exit_code: 0,
        })]);
        await renderSettings();
        expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'success');
        expect(runUpdate).not.toHaveBeenCalled();
    });

    it('ignores an invalid stored unit instead of querying another service', async () => {
        window.sessionStorage.setItem('aetherflow_active_update_job_unit', 'nginx.service');
        await renderSettings();
        expect(window.sessionStorage.getItem('aetherflow_active_update_job_unit')).toBeNull();
        expect(mockedApiFetch.mock.calls.some(([url]) => String(url).includes('?job_unit='))).toBe(false);
        expect(screen.getByRole('button', { name: 'Update to v4.0.1' })).toBeEnabled();
    });

    it('uses scoped flat polling when the backend requires job_unit without inventing runtime verification', async () => {
        const jobUnit = 'aetherflow-self-update-deploy-stable-abcd1234.service';
        const route = mockedApiFetch.getMockImplementation()!;
        mockedApiFetch.mockImplementation((url, init) => url === '/api/v1/auth/system/update/status'
            ? Promise.resolve(response({ error: 'job_unit query parameter is required' }, 400))
            : route(url, init));
        runUpdate.mockResolvedValue(response({ status: 'initiated', completed: false, job_unit: jobUnit }));
        mockJobStatus(jobUnit, [response({
            status: 'succeeded', completed: true, success: true, job_unit: jobUnit, error: '', exit_code: 0,
        })]);
        await renderSettings();
        expect(screen.getByRole('button', { name: 'Update to v4.0.1' })).toBeEnabled();
        await click(screen.getByRole('button', { name: 'Update to v4.0.1' }));
        expect(screen.getByTestId('system-update-status')).toHaveAttribute('data-status', 'success');
        expect(screen.queryByText(/running the latest release/i)).not.toBeInTheDocument();
    });
});
