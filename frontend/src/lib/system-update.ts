export interface SystemUpdateStatus {
    state: 'idle' | 'running' | 'complete' | 'failed' | 'interrupted';
    operationId: string | null;
    phase: string | null;
    error: string | null;
    selectedVersion: string | null;
    runnerVersion: string;
    currentVersion: string;
}

export interface SystemUpdateCheck {
    currentVersion: string;
    latestVersion: string;
    updateAvailable: boolean;
    channel?: string;
    message?: string;
    error?: string | null;
    url?: string;
}

export type UpdateSnapshot<Value> = Value & { checkedAt: number };

export interface SystemUpdateLaunch {
    state: 'launching' | 'accepted' | 'uncertain';
    startedAt: number;
    previousOperationId: string | null;
    operationId: string | null;
    message: string;
}

export const UPDATE_STATUS_POLL_MS = 2000;
export const UPDATE_STATUS_MAX_AGE_MS = 15000;
export const UPDATE_CHECK_MAX_AGE_MS = 90000;

type UpdateViewKind = 'unknown' | 'reconnecting' | 'launching' | 'running' | 'failed'
    | 'interrupted' | 'mismatch' | 'available' | 'latest';

export interface SystemUpdateView {
    kind: UpdateViewKind;
    message: string;
    isBusy: boolean;
    canLaunch: boolean;
    isLatest: boolean;
    updateAvailable: boolean;
}

interface SystemUpdateViewInput {
    status?: UpdateSnapshot<SystemUpdateStatus>;
    check?: UpdateSnapshot<SystemUpdateCheck>;
    statusError?: unknown;
    checkError?: unknown;
    launch?: SystemUpdateLaunch | null;
    launchError?: string;
    settingsPending?: boolean;
    channel: string;
    savedChannel: string;
    now: number;
}

function versionIdentity(value: unknown): string | null {
    if (typeof value !== 'string') return null;
    const version = value.trim();
    if (!/^(?:v?\d[\w.+-]*|(?:nightly|experimental)-[0-9a-f]{7,40})$/i.test(version)) return null;
    return version.replace(/^v(?=\d)/i, '');
}

function isFresh(checkedAt: number | undefined, now: number, maxAge: number): boolean {
    return typeof checkedAt === 'number' && Number.isFinite(checkedAt)
        && checkedAt <= now && now - checkedAt < maxAge;
}

export function isSystemUpdateLaunchTerminal(
    launch: SystemUpdateLaunch | null,
    status: UpdateSnapshot<SystemUpdateStatus>,
    now: number,
): boolean {
    return Boolean(launch && ['complete', 'failed', 'interrupted'].includes(status.state)
        && isFresh(status.checkedAt, now, UPDATE_STATUS_MAX_AGE_MS)
        && status.operationId && status.checkedAt >= launch.startedAt
        && (launch.operationId
            ? status.operationId === launch.operationId
            : status.operationId !== launch.previousOperationId));
}

export function getSystemUpdateView({
    status, check, statusError, checkError, launch, launchError, settingsPending, channel, savedChannel, now,
}: SystemUpdateViewInput): SystemUpdateView {
    const statusFresh = Boolean(status && !statusError
        && ['idle', 'running', 'complete', 'failed', 'interrupted'].includes(status.state)
        && isFresh(status.checkedAt, now, UPDATE_STATUS_MAX_AGE_MS));
    const currentVersion = versionIdentity(status?.currentVersion);
    const runnerVersion = versionIdentity(status?.runnerVersion);
    const selectedVersion = versionIdentity(status?.selectedVersion);
    const latestVersion = versionIdentity(check?.latestVersion);
    const runtimeAgrees = Boolean(currentVersion && currentVersion === runnerVersion);
    const selectionAgrees = Boolean(selectedVersion && currentVersion === selectedVersion);
    const checkVerified = Boolean(check && !checkError && !check.error && latestVersion
        && isFresh(check.checkedAt, now, UPDATE_CHECK_MAX_AGE_MS)
        && currentVersion && versionIdentity(check.currentVersion) === currentVersion
        && (!check.channel || check.channel === savedChannel));
    const launchObserved = Boolean(launch && statusFresh && status?.operationId
        && status.checkedAt >= launch.startedAt && status.state !== 'idle'
        && (launch.operationId
            ? status.operationId === launch.operationId
            : status.operationId !== launch.previousOperationId));
    const launchPending = Boolean(launch && (launch.state === 'launching' || !launchObserved));
    const isBusy = launchPending || status?.state === 'running';
    const updateAvailable = Boolean(checkVerified && check?.updateAvailable === true
        && currentVersion !== latestVersion);
    const canLaunch = Boolean(statusFresh && runtimeAgrees && updateAvailable && !isBusy
        && !settingsPending && channel === savedChannel && (!status?.error || status.state === 'failed')
        && (status?.state === 'idle' || status?.state === 'failed'
            || (status?.state === 'complete' && selectionAgrees)));
    const view = (kind: UpdateViewKind, message: string): SystemUpdateView => ({
        kind, message, isBusy, canLaunch, isLatest: kind === 'latest', updateAvailable,
    });

    if (launch?.state === 'launching') {
        return view('launching', 'Waiting for the update launcher to acknowledge the request...');
    }
    if (!statusFresh) {
        return view(isBusy ? 'reconnecting' : 'unknown',
            'Update status unavailable or stale. Reconnecting automatically; release status is unverified.');
    }
    if (status?.state === 'interrupted') {
        return view('interrupted', `Recovery required: ${status.error || 'The previous update was interrupted.'} Resolve the recovery journal before starting another update.`);
    }
    if (status?.state === 'running') {
        return view('running', `Updating system${status.phase ? `: ${status.phase}` : ''}. Status will reconnect automatically if the API restarts.`);
    }
    if (launchPending) {
        return view(launch?.state === 'uncertain' ? 'reconnecting' : 'launching',
            `${launch?.message || 'Update accepted.'} Waiting for confirmed operation status before allowing another update.`);
    }
    if (status?.state === 'failed' || status?.error || launchError) {
        return view('failed', status?.error || launchError || 'The update failed. Review the updater diagnostics before retrying.');
    }
    if (!runtimeAgrees || !selectionAgrees) {
        return view('mismatch', 'Runtime verification required: the API, runner, and selected release versions do not agree. The update is not confirmed complete.');
    }
    if (settingsPending) {
        return view('unknown', 'Waiting for configuration to finish saving before verifying the release channel.');
    }
    if (channel !== savedChannel) {
        return view('unknown', 'Save the selected release channel before checking or starting an update.');
    }
    if (!checkVerified) {
        return view('unknown', 'The upstream release is unknown, stale, or could not be verified. Check for updates again; no latest-release status is confirmed.');
    }
    if (check?.updateAvailable === false && currentVersion === latestVersion) {
        return view('latest', `Your system is running the latest release on the ${savedChannel} channel.`);
    }
    if (updateAvailable) {
        return view('available', `A verified update to ${check?.latestVersion} is available.`);
    }
    return view('mismatch', 'The running and upstream versions do not agree. Release status is unverified.');
}
