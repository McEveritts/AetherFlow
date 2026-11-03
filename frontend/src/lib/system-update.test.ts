import {
    getSystemUpdateView, isSystemUpdateLaunchTerminal, UPDATE_CHECK_MAX_AGE_MS, UPDATE_STATUS_MAX_AGE_MS,
    type SystemUpdateCheck, type SystemUpdateLaunch, type SystemUpdateStatus, type UpdateSnapshot,
} from './system-update';

const now = 1_800_000_000_000;
const status: UpdateSnapshot<SystemUpdateStatus> = {
    state: 'idle', operationId: null, phase: null, error: null, selectedVersion: 'v4.0.0',
    currentVersion: 'v4.0.0', runnerVersion: 'v4.0.0', checkedAt: now,
};
const check: UpdateSnapshot<SystemUpdateCheck> = {
    currentVersion: 'v4.0.0', latestVersion: 'v4.0.0', updateAvailable: false, checkedAt: now,
};
const input = { status, check, channel: 'nightly', savedChannel: 'nightly', now };
const launch: SystemUpdateLaunch = {
    state: 'accepted', startedAt: now, previousOperationId: null, operationId: 'update-2',
    message: 'Launcher acknowledged.',
};

describe('system updater release verification', () => {
    it('requires fresh agreement between the runtime, runner, selected release, and upstream', () => {
        expect(getSystemUpdateView(input)).toMatchObject({ kind: 'latest', isLatest: true, canLaunch: false });
        expect(getSystemUpdateView({
            ...input, status: { ...status, state: 'complete', selectedVersion: '4.0.0' },
        }).isLatest).toBe(true);
    });

    it('does not mistake runtime A and selected release B for a completed update', () => {
        expect(getSystemUpdateView({
            ...input, status: { ...status, state: 'complete', selectedVersion: 'v4.0.1' },
        })).toMatchObject({ kind: 'mismatch', isLatest: false, canLaunch: false });
    });

    it.each(['running', 'failed', 'interrupted'] as const)('never labels a %s operation latest', state => {
        const view = getSystemUpdateView({ ...input, status: { ...status, state } });
        expect(view.kind).toBe(state);
        expect(view.isLatest).toBe(false);
        expect(view.canLaunch).toBe(false);
    });

    it('surfaces a backend failure and blocks interrupted recovery even when an update is available', () => {
        const view = getSystemUpdateView({
            ...input, status: { ...status, state: 'interrupted', error: 'Recovery journal needs operator action' },
            check: { ...check, latestVersion: 'v4.0.1', updateAvailable: true },
        });
        expect(view.message).toContain('Recovery journal needs operator action');
        expect(view.canLaunch).toBe(false);
        expect(getSystemUpdateView({ ...input, launchError: 'Launcher unavailable' }))
            .toMatchObject({ kind: 'failed', message: 'Launcher unavailable', isLatest: false });
    });

    it.each(['Unknown (API Error or Rate Limited)', 'unknown', '', 'N/A', 'unavailable'])('rejects unknown upstream version %j despite updateAvailable=false', latestVersion => {
        expect(getSystemUpdateView({ ...input, check: { ...check, latestVersion } }).isLatest).toBe(false);
    });

    it('rejects both HTTP and successful-HTTP GitHub check failures', () => {
        expect(getSystemUpdateView({ ...input, checkError: new Error('HTTP 503') }).isLatest).toBe(false);
        expect(getSystemUpdateView({ ...input, check: { ...check, error: 'github_rate_limited' } }).isLatest).toBe(false);
    });

    it.each([
        { status: undefined },
        { status: { ...status, checkedAt: now - UPDATE_STATUS_MAX_AGE_MS } },
        { check: { ...check, checkedAt: now - UPDATE_CHECK_MAX_AGE_MS } },
        { statusError: new Error('Restarting') },
        { status: { ...status, selectedVersion: null } },
        { status: { ...status, selectedVersion: '' } },
        { status: { ...status, runnerVersion: 'v4.0.1' } },
        { check: { ...check, currentVersion: 'v3.9.0' } },
        { check: { ...check, latestVersion: 'v4.0.1', updateAvailable: false } },
        { check: { ...check, channel: 'stable' } },
        { channel: 'experimental' },
        { settingsPending: true },
    ])('does not claim latest with missing, stale, or conflicting evidence: %j', overrides => {
        expect(getSystemUpdateView({ ...input, ...overrides }).isLatest).toBe(false);
    });

    it('permits launching only with fresh runtime status and a verified update on the saved channel', () => {
        const available = { ...input, check: { ...check, latestVersion: 'v4.0.1', updateAvailable: true } };
        expect(getSystemUpdateView(available)).toMatchObject({ kind: 'available', canLaunch: true });
        expect(getSystemUpdateView({ ...available, status: undefined }).canLaunch).toBe(false);
        expect(getSystemUpdateView({ ...available, channel: 'stable' }).canLaunch).toBe(false);
        expect(getSystemUpdateView({ ...available, checkError: new Error('offline') }).canLaunch).toBe(false);
        expect(getSystemUpdateView({ ...available, settingsPending: true }).canLaunch).toBe(false);
        expect(getSystemUpdateView({
            ...available, status: { ...status, state: 'failed', error: 'Download failed', selectedVersion: 'v4.0.1' },
        })).toMatchObject({ kind: 'failed', isLatest: false, canLaunch: true });
    });
});

describe('system updater restart and launch tracking', () => {
    it('retires only a fresh terminal operation that matches the launch', () => {
        const terminal = { ...status, state: 'complete' as const, operationId: launch.operationId };
        expect(isSystemUpdateLaunchTerminal(launch, terminal, now)).toBe(true);
        expect(isSystemUpdateLaunchTerminal(null, terminal, now)).toBe(false);
        expect(isSystemUpdateLaunchTerminal(launch, { ...terminal, operationId: 'other-operation' }, now)).toBe(false);
        expect(isSystemUpdateLaunchTerminal(launch, { ...terminal, state: 'running' }, now)).toBe(false);
        expect(isSystemUpdateLaunchTerminal(launch, { ...terminal, checkedAt: now - UPDATE_STATUS_MAX_AGE_MS }, now)).toBe(false);
        expect(isSystemUpdateLaunchTerminal({ ...launch, operationId: null, previousOperationId: 'old-operation' }, terminal, now)).toBe(true);
    });

    it('blocks duplicate launches until an acknowledged operation is observed', () => {
        expect(getSystemUpdateView({ ...input, launch })).toMatchObject({
            kind: 'launching', isBusy: true, isLatest: false, canLaunch: false,
        });
        expect(getSystemUpdateView({
            ...input, launch, status: { ...status, state: 'complete', operationId: 'old-operation' },
        }).isBusy).toBe(true);
    });

    it('handles an optional acknowledgement operation ID without trusting the old terminal journal', () => {
        const withoutId = { ...launch, operationId: null, previousOperationId: 'old-operation' };
        expect(getSystemUpdateView({
            ...input, launch: withoutId, status: { ...status, state: 'complete', operationId: 'old-operation' },
        }).isBusy).toBe(true);
        expect(getSystemUpdateView({
            ...input, launch: withoutId, status: { ...status, state: 'complete', operationId: 'new-operation' },
        })).toMatchObject({ isBusy: false, isLatest: true });
    });

    it('keeps an uncertain POST pending rather than blindly retrying it', () => {
        expect(getSystemUpdateView({ ...input, launch: { ...launch, state: 'uncertain' } }))
            .toMatchObject({ kind: 'reconnecting', isBusy: true, canLaunch: false, isLatest: false });
    });

    it('retains progress during API loss and confirms success only after reconnecting to matching runtime versions', () => {
        const running = { ...status, state: 'running' as const, operationId: 'update-2', phase: 'restarting' };
        expect(getSystemUpdateView({ ...input, launch, status: running }).message).toContain('restarting');
        expect(getSystemUpdateView({ ...input, launch, status: running, statusError: new Error('Connection refused') }))
            .toMatchObject({ kind: 'reconnecting', isBusy: true, isLatest: false });
        expect(getSystemUpdateView({
            ...input, launch,
            status: { ...status, state: 'complete', operationId: 'update-2', selectedVersion: 'v4.0.1', currentVersion: 'v4.0.1', runnerVersion: 'v4.0.1' },
            check: { ...check, currentVersion: 'v4.0.1', latestVersion: 'v4.0.1' },
        })).toMatchObject({ kind: 'latest', isBusy: false, isLatest: true, canLaunch: false });
    });
});
