import { McBrowserRequestError } from '@/lib/mcbrowser';
import { McBrowserUploadUncertaintyError } from '@/lib/mcbrowser-resumable';
import {
    DEFAULT_MAX_TOTAL_UPLOAD_BYTES,
    DEFAULT_MAX_UPLOAD_FILES,
    DEFAULT_UPLOAD_CONCURRENCY,
    McBrowserUploadQueue,
    UploadQueueItem,
    scanTransferItems,
    summarizeMcBrowserUploadQueue,
    formatMcBrowserUploadEta,
} from '@/lib/mcbrowser-uploads';

interface Deferred<Value> {
    promise: Promise<Value>;
    resolve: (value: Value | PromiseLike<Value>) => void;
    reject: (reason?: unknown) => void;
}

function createDeferred<Value = unknown>(): Deferred<Value> {
    let resolveFn!: (value: Value | PromiseLike<Value>) => void;
    let rejectFn!: (reason?: unknown) => void;
    const promise = new Promise<Value>((resolve, reject) => {
        resolveFn = resolve;
        rejectFn = reject;
    });
    return {
        promise,
        resolve: resolveFn,
        reject: rejectFn,
    };
}

function createMockFile(
    name: string,
    sizeBytes: number,
    relativePath?: string
): File {
    const content = new Uint8Array(sizeBytes);
    const file = new File([content], name, { type: 'application/octet-stream' });
    if (relativePath !== undefined) {
        Object.defineProperty(file, 'webkitRelativePath', {
            value: relativePath,
            configurable: true,
            enumerable: true,
        });
    }
    return file;
}

async function flushMicrotasks(ticks = 6): Promise<void> {
    for (let index = 0; index < ticks; index += 1) {
        await Promise.resolve();
    }
}

describe('McBrowserUploadQueue', () => {
    it('summarizes confirmed offsets, aggregate speed and ETA without counting skipped files', () => {
        const base = { id: 'upload', name: 'file', targetPath: 'file', size: 1000 };
        const items: UploadQueueItem[] = [
            { ...base, status: 'uploading', uploadedBytes: 200, speedBytesPerSecond: 100 },
            { ...base, id: 'second', status: 'uploading', uploadedBytes: 400, speedBytesPerSecond: 200 },
            { ...base, id: 'pending', status: 'pending' },
            { ...base, id: 'complete', status: 'success' },
            { ...base, id: 'skip', status: 'success', skipped: true },
            { ...base, id: 'directory', status: 'success', kind: 'directory' },
        ];
        expect(summarizeMcBrowserUploadQueue(items)).toEqual({
            confirmedBytes: 1600, totalBytes: 4000, speedBytesPerSecond: 300, etaSeconds: 8,
        });
        expect(summarizeMcBrowserUploadQueue([...items, { ...base, status: 'paused' }]).etaSeconds).toBeUndefined();
        expect(formatMcBrowserUploadEta(8)).toBe('00:00:08');
        expect(formatMcBrowserUploadEta(3661)).toBe('01:01:01');
        expect(formatMcBrowserUploadEta(undefined)).toBeUndefined();
        expect(formatMcBrowserUploadEta(Number.NaN)).toBeUndefined();
    });

    it('bounds invalid progress and excludes stale rates from inactive transfers', () => {
        const base = { id: 'upload', name: 'file', targetPath: 'file', size: 1000 };
        expect(summarizeMcBrowserUploadQueue([
            { ...base, status: 'uploading', uploadedBytes: 9000, speedBytesPerSecond: Number.POSITIVE_INFINITY },
            { ...base, status: 'error', uploadedBytes: -5, speedBytesPerSecond: 100 },
        ])).toEqual({ confirmedBytes: 1000, totalBytes: 2000, speedBytesPerSecond: 0, etaSeconds: undefined });
    });

    it('requires an explicit choice before retrying a destination conflict and reports skipped files', async () => {
        const upload = jest.fn()
            .mockRejectedValueOnce(new McBrowserRequestError(409, 'CONFLICT', 'Target exists'))
            .mockResolvedValueOnce({ success: true, path: 'existing.txt', skipped: true });
        const queue = new McBrowserUploadQueue({ upload, onChange: () => {} });
        queue.enqueue([createMockFile('existing.txt', 10)], '', 1024);
        await flushMicrotasks();
        expect(queue.snapshot()[0]).toMatchObject({ status: 'error', conflictDetected: true });
        expect(upload).toHaveBeenCalledTimes(1);
        queue.resolveConflict('upload-1', 'skip');
        await flushMicrotasks();
        expect(upload).toHaveBeenNthCalledWith(2, 'existing.txt', expect.any(File), expect.any(AbortSignal), expect.any(Function), 'skip');
        expect(queue.snapshot()[0]).toMatchObject({ status: 'success', skipped: true, conflictDetected: false });
        queue.resolveConflict('upload-1', 'overwrite');
        expect(upload).toHaveBeenCalledTimes(2);
        queue.dispose();
    });

    it('does not apply conflict resolution to unrelated errors or uncertain commits', async () => {
        const upload = jest.fn().mockRejectedValue(new McBrowserRequestError(413, 'QUOTA_EXCEEDED', 'Quota exceeded'));
        const queue = new McBrowserUploadQueue({ upload, onChange: () => {} });
        queue.enqueue([createMockFile('quota.txt', 10)], '', 1024);
        await flushMicrotasks();
        queue.resolveConflict('upload-1', 'overwrite');
        await flushMicrotasks();
        expect(upload).toHaveBeenCalledTimes(1);
        expect(queue.snapshot()[0]).toMatchObject({ status: 'error', conflictDetected: false });
        queue.dispose();
    });

    it('exports expected default constants', () => {
        expect(DEFAULT_UPLOAD_CONCURRENCY).toBe(5);
        expect(DEFAULT_MAX_UPLOAD_FILES).toBe(1000);
        expect(DEFAULT_MAX_TOTAL_UPLOAD_BYTES).toBe(16 * 1024 * 1024 * 1024);
    });

    it('processes uploads with bounded concurrency, supports appending while running, and assigns stable monotonic IDs', async () => {
        const activeUploads = new Map<string, Deferred<unknown>>();
        const uploadOrder: string[] = [];
        const changeSnapshots: UploadQueueItem[][] = [];
        let idleCallCount = 0;

        const queue = new McBrowserUploadQueue({
            concurrency: 2,
            upload: (targetPath) => {
                uploadOrder.push(targetPath);
                const deferred = createDeferred();
                activeUploads.set(targetPath, deferred);
                return deferred.promise;
            },
            onChange: (items) => {
                changeSnapshots.push(items);
            },
            onIdle: () => {
                idleCallCount += 1;
            },
        });

        const firstBatch = [
            createMockFile('alpha.jar', 100),
            createMockFile('beta.jar', 200),
            createMockFile('gamma.jar', 300),
        ];

        queue.enqueue(firstBatch, 'mods', 1024);
        await flushMicrotasks();

        expect(uploadOrder).toEqual(['mods/alpha.jar', 'mods/beta.jar']);
        expect(queue.snapshot().map((item) => ({ id: item.id, status: item.status }))).toEqual([
            { id: 'upload-1', status: 'uploading' },
            { id: 'upload-2', status: 'uploading' },
            { id: 'upload-3', status: 'pending' },
        ]);

        queue.enqueue([createMockFile('delta.jar', 400)], 'mods', 1024);
        await flushMicrotasks();

        expect(queue.snapshot().map((item) => ({ id: item.id, status: item.status }))).toEqual([
            { id: 'upload-1', status: 'uploading' },
            { id: 'upload-2', status: 'uploading' },
            { id: 'upload-3', status: 'pending' },
            { id: 'upload-4', status: 'pending' },
        ]);

        activeUploads.get('mods/alpha.jar')!.resolve({ success: true });
        await flushMicrotasks();

        expect(uploadOrder).toEqual(['mods/alpha.jar', 'mods/beta.jar', 'mods/gamma.jar']);
        expect(queue.snapshot().map((item) => ({ id: item.id, status: item.status }))).toEqual([
            { id: 'upload-1', status: 'success' },
            { id: 'upload-2', status: 'uploading' },
            { id: 'upload-3', status: 'uploading' },
            { id: 'upload-4', status: 'pending' },
        ]);
        expect(idleCallCount).toBe(0);

        activeUploads.get('mods/beta.jar')!.resolve({ success: true });
        await flushMicrotasks();

        expect(uploadOrder).toEqual([
            'mods/alpha.jar',
            'mods/beta.jar',
            'mods/gamma.jar',
            'mods/delta.jar',
        ]);

        activeUploads.get('mods/gamma.jar')!.resolve({ success: true });
        activeUploads.get('mods/delta.jar')!.resolve({ success: true });
        await flushMicrotasks();

        expect(queue.snapshot().every((item) => item.status === 'success')).toBe(true);
        expect(idleCallCount).toBe(1);
        expect(changeSnapshots.length).toBeGreaterThan(0);
    });

    it('clamps concurrency between 1 and 5 and defaults to 5', async () => {
        const startedHigh: string[] = [];
        const queueHigh = new McBrowserUploadQueue({
            concurrency: 99,
            upload: (targetPath) => {
                startedHigh.push(targetPath);
                return createDeferred().promise;
            },
            onChange: () => {},
        });

        const eightFiles = Array.from({ length: 8 }, (_, index) =>
            createMockFile(`file-${index + 1}.txt`, 10)
        );
        queueHigh.enqueue(eightFiles, '', 1024);
        await flushMicrotasks();
        expect(startedHigh).toHaveLength(5);
        queueHigh.dispose();

        const startedLow: string[] = [];
        const queueLow = new McBrowserUploadQueue({
            concurrency: 0,
            upload: (targetPath) => {
                startedLow.push(targetPath);
                return createDeferred().promise;
            },
            onChange: () => {},
        });
        queueLow.enqueue(
            [createMockFile('one.txt', 10), createMockFile('two.txt', 10)],
            '',
            1024
        );
        await flushMicrotasks();
        expect(startedLow).toHaveLength(1);
        queueLow.dispose();
    });

    it('enforces all-or-nothing admission caps for maxFiles and maxTotalBytes with McBrowserRequestError', async () => {
        const uploadedPaths: string[] = [];
        const queue = new McBrowserUploadQueue({
            maxFiles: 3,
            maxTotalBytes: 500,
            upload: async (targetPath) => {
                uploadedPaths.push(targetPath);
                return { success: true };
            },
            onChange: () => {},
        });

        expect(() =>
            queue.enqueue(
                [
                    createMockFile('first.bin', 100),
                    createMockFile('second.bin', 100),
                    createMockFile('third.bin', 100),
                    createMockFile('fourth.bin', 100),
                ],
                'backups',
                1000
            )
        ).toThrow(McBrowserRequestError);

        expect(queue.snapshot()).toEqual([]);
        expect(uploadedPaths).toEqual([]);

        expect(() =>
            queue.enqueue(
                [createMockFile('big1.bin', 300), createMockFile('big2.bin', 250)],
                'backups',
                1000
            )
        ).toThrow(McBrowserRequestError);

        expect(queue.snapshot()).toEqual([]);
        expect(uploadedPaths).toEqual([]);

        queue.enqueue(
            [createMockFile('ok1.bin', 200), createMockFile('ok2.bin', 200)],
            'backups',
            1000
        );
        await flushMicrotasks();
        expect(uploadedPaths).toEqual(['backups/ok1.bin', 'backups/ok2.bin']);
    });

    it('marks oversized files and duplicate destinations as per-file errors without silent file loss', async () => {
        const uploadedPaths: string[] = [];
        const queue = new McBrowserUploadQueue({
            upload: async (targetPath) => {
                uploadedPaths.push(targetPath);
                return { success: true };
            },
            onChange: () => {},
        });

        queue.enqueue(
            [
                createMockFile('valid.jar', 50),
                createMockFile('oversized.jar', 200),
                createMockFile('valid.jar', 40),
            ],
            'mods',
            100
        );
        await flushMicrotasks();

        const snapshot = queue.snapshot();
        expect(snapshot).toHaveLength(3);
        expect(snapshot[0]).toMatchObject({
            id: 'upload-1',
            targetPath: 'mods/valid.jar',
            status: 'success',
        });
        expect(snapshot[1]).toMatchObject({
            id: 'upload-2',
            targetPath: 'mods/oversized.jar',
            status: 'error',
        });
        expect(snapshot[1].error).toContain('exceeds maximum upload limit');
        expect(snapshot[2]).toMatchObject({
            id: 'upload-3',
            targetPath: 'mods/valid.jar',
            status: 'error',
        });
        expect(snapshot[2].error).toContain('Duplicate upload destination');
        expect(uploadedPaths).toEqual(['mods/valid.jar']);

        queue.retryFailed();
        await flushMicrotasks();
        expect(uploadedPaths).toEqual(['mods/valid.jar']);
        expect(queue.snapshot()[1].status).toBe('error');
        expect(queue.snapshot()[2].status).toBe('error');
    });

    it('handles cancellation of pending and active uploads, keeping interrupted uploads uncertain unless confirmed successful', async () => {
        const activeDeferreds = new Map<string, Deferred<unknown>>();
        const activeSignals = new Map<string, AbortSignal>();

        const queue = new McBrowserUploadQueue({
            concurrency: 2,
            upload: (targetPath, _file, signal) => {
                const deferred = createDeferred();
                activeDeferreds.set(targetPath, deferred);
                activeSignals.set(targetPath, signal);
                return deferred.promise;
            },
            onChange: () => {},
        });

        queue.enqueue(
            [
                createMockFile('active-abort.jar', 100),
                createMockFile('active-confirm.jar', 100),
                createMockFile('pending-cancel.jar', 100),
            ],
            'mods',
            1024
        );
        await flushMicrotasks();

        queue.cancel('upload-3');
        expect(queue.snapshot()[2]).toMatchObject({
            id: 'upload-3',
            status: 'cancelled',
        });

        queue.cancel('upload-1');
        expect(activeSignals.get('mods/active-abort.jar')?.aborted).toBe(true);
        expect(queue.snapshot()[0]).toMatchObject({
            id: 'upload-1',
            status: 'uncertain',
        });

        queue.cancel('upload-2');
        expect(activeSignals.get('mods/active-confirm.jar')?.aborted).toBe(true);
        expect(queue.snapshot()[1]).toMatchObject({
            id: 'upload-2',
            status: 'uncertain',
        });

        activeDeferreds.get('mods/active-abort.jar')!.reject(new Error('AbortError'));
        activeDeferreds.get('mods/active-confirm.jar')!.resolve({ success: true });
        await flushMicrotasks();

        const afterSettle = queue.snapshot();
        expect(afterSettle[0]).toMatchObject({
            id: 'upload-1',
            status: 'uncertain',
        });
        expect(afterSettle[1]).toMatchObject({
            id: 'upload-2',
            status: 'success',
        });
        expect(afterSettle[2]).toMatchObject({
            id: 'upload-3',
            status: 'cancelled',
        });
    });

    it('retries only retryable error and cancelled items while never retrying uncertain items', async () => {
        let attemptCountByPath: Record<string, number> = {};
        const deferredByAttempt = new Map<string, Deferred<unknown>>();

        const queue = new McBrowserUploadQueue({
            concurrency: 3,
            upload: (targetPath) => {
                const count = (attemptCountByPath[targetPath] ?? 0) + 1;
                attemptCountByPath[targetPath] = count;
                const deferred = createDeferred();
                deferredByAttempt.set(`${targetPath}#${count}`, deferred);
                return deferred.promise;
            },
            onChange: () => {},
        });

        queue.enqueue(
            [
                createMockFile('transient-error.txt', 50),
                createMockFile('uncertain-item.txt', 50),
                createMockFile('cancelled-item.txt', 50),
            ],
            'configs',
            1024
        );

        queue.dispose();

        attemptCountByPath = {};
        deferredByAttempt.clear();

        const queue2 = new McBrowserUploadQueue({
            concurrency: 2,
            upload: (targetPath) => {
                const count = (attemptCountByPath[targetPath] ?? 0) + 1;
                attemptCountByPath[targetPath] = count;
                const deferred = createDeferred();
                deferredByAttempt.set(`${targetPath}#${count}`, deferred);
                return deferred.promise;
            },
            onChange: () => {},
        });

        queue2.enqueue(
            [
                createMockFile('transient-error.txt', 50),
                createMockFile('uncertain-item.txt', 50),
                createMockFile('cancelled-item.txt', 50),
            ],
            'configs',
            1024
        );
        await flushMicrotasks();

        queue2.cancel('upload-3');
        queue2.cancel('upload-2');

        deferredByAttempt
            .get('configs/transient-error.txt#1')!
            .reject(new McBrowserRequestError(500, 'IO_ERROR', 'Disk busy'));
        deferredByAttempt.get('configs/uncertain-item.txt#1')!.reject(new Error('Aborted'));
        await flushMicrotasks();

        expect(queue2.snapshot().map((item) => item.status)).toEqual([
            'error',
            'uncertain',
            'cancelled',
        ]);

        queue2.retryFailed();
        await flushMicrotasks();

        expect(attemptCountByPath['configs/transient-error.txt']).toBe(2);
        expect(attemptCountByPath['configs/cancelled-item.txt']).toBe(1);
        expect(attemptCountByPath['configs/uncertain-item.txt']).toBe(1);

        deferredByAttempt.get('configs/transient-error.txt#2')!.resolve({ success: true });
        deferredByAttempt.get('configs/cancelled-item.txt#1')!.resolve({ success: true });
        await flushMicrotasks();

        expect(queue2.snapshot().map((item) => item.status)).toEqual([
            'success',
            'uncertain',
            'success',
        ]);

        queue2.clearCompleted();
        expect(queue2.snapshot()).toEqual([]);
    });

    it('validates webkitRelativePath hierarchy, rejects invalid relative paths before normalization, and requires leaf match', async () => {
        const uploadedPaths: string[] = [];
        const ensuredDirs: string[] = [];
        const drained = createDeferred<void>();

        const queue = new McBrowserUploadQueue({
            ensureDirectory: async (dirPath) => {
                ensuredDirs.push(dirPath);
                return { success: true };
            },
            upload: async (targetPath) => {
                uploadedPaths.push(targetPath);
                return { success: true };
            },
            onChange: () => {},
            onIdle: () => drained.resolve(),
        });

        queue.enqueue(
            [
                createMockFile('config.yml', 30, 'pack/sub/config.yml'),
                createMockFile('abs.yml', 30, '/pack/abs.yml'),
                createMockFile('slash.yml', 30, 'pack\\slash.yml'),
                createMockFile('dot.yml', 30, 'pack/./dot.yml'),
                createMockFile('parent.yml', 30, 'pack/../parent.yml'),
                createMockFile('nul.yml', 30, 'pack/nul\0/nul.yml'),
                createMockFile('reserved.yml', 30, 'pack/.af-upload-tmp.123/reserved.yml'),
                createMockFile('mismatch.yml', 30, 'pack/other-name.yml'),
            ],
            'plugins',
            1024
        );
        await drained.promise;

        const statuses = queue.snapshot().map((item) => ({
            name: item.name,
            targetPath: item.targetPath,
            status: item.status,
        }));

        expect(statuses[0]).toEqual({
            name: 'pack/sub/config.yml',
            targetPath: 'plugins/pack/sub/config.yml',
            status: 'success',
        });
        for (let index = 1; index < statuses.length; index += 1) {
            expect(statuses[index].status).toBe('error');
        }

        expect(ensuredDirs).toEqual(['plugins/pack', 'plugins/pack/sub']);
        expect(uploadedPaths).toEqual(['plugins/pack/sub/config.yml']);
    });

    it('deduplicates concurrent ensureDirectory calls in shallow-to-deep order, marks pre-upload cancel as cancelled without file loss, and prevents single-file cancellation from poisoning shared directory creation', async () => {
        const dirCreationDeferreds = new Map<string, Deferred<unknown>>();
        const dirCreationCalls: string[] = [];
        const uploadedFiles: string[] = [];

        const queue = new McBrowserUploadQueue({
            concurrency: 3,
            ensureDirectory: (dirPath) => {
                dirCreationCalls.push(dirPath);
                const deferred = createDeferred();
                dirCreationDeferreds.set(
                    `${dirPath}#${dirCreationCalls.filter((item) => item === dirPath).length}`,
                    deferred
                );
                return deferred.promise;
            },
            upload: async (targetPath) => {
                uploadedFiles.push(targetPath);
                return { success: true };
            },
            onChange: () => {},
        });

        queue.enqueue(
            [
                createMockFile('one.json', 20, 'world/datapacks/packA/one.json'),
                createMockFile('two.json', 20, 'world/datapacks/packA/two.json'),
            ],
            'saves',
            1024
        );
        await flushMicrotasks();

        expect(dirCreationCalls).toEqual(['saves/world']);

        // Cancel upload-1 while it is still preparing directories BEFORE uploadFn starts
        queue.cancel('upload-1');
        expect(queue.snapshot()[0].status).toBe('cancelled');

        dirCreationDeferreds.get('saves/world#1')!.resolve({ success: true });
        await flushMicrotasks();

        expect(dirCreationCalls).toEqual(['saves/world', 'saves/world/datapacks']);
        dirCreationDeferreds.get('saves/world/datapacks#1')!.resolve({ success: true });
        await flushMicrotasks();

        expect(dirCreationCalls).toEqual([
            'saves/world',
            'saves/world/datapacks',
            'saves/world/datapacks/packA',
        ]);

        dirCreationDeferreds
            .get('saves/world/datapacks/packA#1')!
            .reject(new McBrowserRequestError(500, 'MKDIR_FAIL', 'Temporary mkdir failure'));
        await flushMicrotasks();

        expect(queue.snapshot()[0].status).toBe('cancelled');
        expect(queue.snapshot()[1].status).toBe('error');
        expect(uploadedFiles).toEqual([]);

        // Both pre-upload cancelled upload-1 and failed upload-2 retain their File reference and can be retried
        queue.retryFailed();
        await flushMicrotasks();

        expect(dirCreationCalls[3]).toBe('saves/world');
        dirCreationDeferreds.get('saves/world#2')!.resolve({ success: true });
        await flushMicrotasks();
        dirCreationDeferreds.get('saves/world/datapacks#2')!.resolve({ success: true });
        await flushMicrotasks();
        dirCreationDeferreds.get('saves/world/datapacks/packA#2')!.resolve({ success: true });
        await flushMicrotasks();

        expect(uploadedFiles).toEqual([
            'saves/world/datapacks/packA/one.json',
            'saves/world/datapacks/packA/two.json',
        ]);
        expect(queue.snapshot()[0].status).toBe('success');
        expect(queue.snapshot()[1].status).toBe('success');
    });

    it('guards McBrowserUploadUncertaintyError BEFORE generic McBrowserRequestError so uncertain commits are never retried', async () => {
        const attempts: string[] = [];
        const queue = new McBrowserUploadQueue({
            upload: async (path) => {
                attempts.push(path);
                throw new McBrowserUploadUncertaintyError(
                    'All bytes reached staging, but destination publication could not be confirmed.'
                );
            },
            onChange: () => {},
        });

        queue.enqueue([createMockFile('ambiguous.jar', 512)], 'mods', 2048);
        await flushMicrotasks();

        const item = queue.snapshot()[0];
        expect(item.status).toBe('uncertain');
        expect(item.error).toContain('destination publication could not be confirmed');

        queue.retryFailed();
        await flushMicrotasks();
        expect(attempts).toEqual(['mods/ambiguous.jar']);
    });

    it('treats an unacknowledged transport failure as uncertain and never retries it automatically', async () => {
        const attempts: string[] = [];
        const queue = new McBrowserUploadQueue({
            upload: async (path) => {
                attempts.push(path);
                throw new TypeError('Network disconnected after commit');
            },
            onChange: () => {},
        });
        queue.enqueue([createMockFile('commit.txt', 1)], '', 1024);
        await flushMicrotasks();
        expect(queue.snapshot()[0].status).toBe('uncertain');
        queue.retryFailed();
        await flushMicrotasks();
        expect(attempts).toEqual(['commit.txt']);
    });

    it('reports confirmed byte progress and speed updates and updates published targetPath', async () => {
        const uploadDeferred = createDeferred<{ success: true; path: string }>();
        let progressCallback:
            | ((progress: {
                  uploadedBytes: number;
                  totalBytes: number;
                  speedBytesPerSecond: number;
              }) => void)
            | undefined;

        const queue = new McBrowserUploadQueue({
            upload: (_path, _file, _signal, onProgress) => {
                progressCallback = onProgress;
                return uploadDeferred.promise;
            },
            onChange: () => {},
        });

        queue.enqueue([createMockFile('archive.zip', 1000)], 'backups', 4096);
        await flushMicrotasks();

        expect(progressCallback).toBeDefined();
        progressCallback!({
            uploadedBytes: 400,
            totalBytes: 1000,
            speedBytesPerSecond: 2048,
        });

        expect(queue.snapshot()[0]).toMatchObject({
            status: 'uploading',
            uploadedBytes: 400,
            speedBytesPerSecond: 2048,
        });

        uploadDeferred.resolve({ success: true, path: 'backups/archive (1).zip' });
        await flushMicrotasks();

        expect(queue.snapshot()[0]).toMatchObject({
            status: 'success',
            targetPath: 'backups/archive (1).zip',
            uploadedBytes: 1000,
            speedBytesPerSecond: 0,
        });
    });

    it('distinguishes pause/resume from explicit cancel with server session termination vs 409 already-completed commit', async () => {
        const attemptSignals: AbortSignal[] = [];
        const attemptDeferreds: Deferred<unknown>[] = [];
        const cancelSessionCalls: string[] = [];
        let cancelSessionBehavior: 'cancelled' | 'conflict' = 'cancelled';

        const queue = new McBrowserUploadQueue({
            concurrency: 2,
            upload: (path, _file, signal, onProgress) => {
                attemptSignals.push(signal);
                onProgress?.({
                    uploadedBytes: 256,
                    totalBytes: 512,
                    speedBytesPerSecond: 1024,
                });
                const deferred = createDeferred();
                attemptDeferreds.push(deferred);
                return deferred.promise;
            },
            cancelSession: async (path) => {
                cancelSessionCalls.push(path);
                if (cancelSessionBehavior === 'conflict') {
                    throw new McBrowserRequestError(
                        409,
                        'ALREADY_COMPLETED',
                        'Upload already completed and published; cannot roll back committed file.'
                    );
                }
                return { cancelled: true, sessionId: 'sess-1' };
            },
            onChange: () => {},
        });

        queue.enqueue(
            [createMockFile('resumable.bin', 512), createMockFile('committed.bin', 512)],
            'data',
            4096
        );
        await flushMicrotasks();

        // 1. Pause first item: aborts active PATCH without calling cancelSession, preserves file and progress
        queue.pause('upload-1');
        expect(attemptSignals[0].aborted).toBe(true);
        attemptDeferreds[0].reject(new DOMException('Aborted', 'AbortError'));
        await flushMicrotasks();

        expect(cancelSessionCalls).toEqual([]);
        expect(queue.snapshot()[0]).toMatchObject({
            id: 'upload-1',
            status: 'paused',
            uploadedBytes: 256,
        });

        // 2. Resume first item: re-enters upload pipeline with file intact
        queue.resume('upload-1');
        await flushMicrotasks();
        expect(attemptDeferreds).toHaveLength(3);
        expect(queue.snapshot()[0].status).toBe('uploading');

        // 3. Explicit cancel on upload-1 when server DELETE succeeds (204) -> 'cancelled' & retryable
        queue.cancel('upload-1');
        attemptDeferreds[2].reject(new DOMException('Aborted', 'AbortError'));
        await flushMicrotasks();

        expect(cancelSessionCalls).toEqual(['data/resumable.bin']);
        expect(queue.snapshot()[0]).toMatchObject({
            id: 'upload-1',
            status: 'cancelled',
            uploadedBytes: 0,
        });

        // 4. Explicit cancel on upload-2 when server returns 409 ALREADY_COMPLETED -> 'uncertain'
        cancelSessionBehavior = 'conflict';
        queue.cancel('upload-2');
        attemptDeferreds[1].reject(new DOMException('Aborted', 'AbortError'));
        await flushMicrotasks();

        expect(cancelSessionCalls).toEqual(['data/resumable.bin', 'data/committed.bin']);
        expect(queue.snapshot()[1]).toMatchObject({
            id: 'upload-2',
            status: 'uncertain',
        });
        expect(queue.snapshot()[1].error).toContain('cannot roll back committed file');
    });

    it('allows destination reselection after failed or cancelled uploads while still blocking active, successful, or uncertain destinations', async () => {
        const uploadedAttempts: string[] = [];
        let shouldFailFirst = true;

        const queue = new McBrowserUploadQueue({
            concurrency: 1,
            upload: async (targetPath) => {
                uploadedAttempts.push(targetPath);
                if (shouldFailFirst && targetPath === 'mods/retry-me.jar') {
                    shouldFailFirst = false;
                    throw new McBrowserRequestError(500, 'IO_ERROR', 'Temporary failure');
                }
                return { success: true };
            },
            onChange: () => {},
        });

        queue.enqueue(
            [createMockFile('retry-me.jar', 64), createMockFile('cancel-me.jar', 64)],
            'mods',
            1024
        );
        // Cancel pending second file before it starts
        queue.cancel('upload-2');
        await flushMicrotasks();

        expect(queue.snapshot().map((item) => ({ path: item.targetPath, status: item.status }))).toEqual([
            { path: 'mods/retry-me.jar', status: 'error' },
            { path: 'mods/cancel-me.jar', status: 'cancelled' },
        ]);

        // Re-selecting both failed and cancelled destinations in a new batch must succeed
        queue.enqueue(
            [createMockFile('retry-me.jar', 64), createMockFile('cancel-me.jar', 64)],
            'mods',
            1024
        );
        await flushMicrotasks();

        const snap = queue.snapshot();
        expect(snap[2]).toMatchObject({
            id: 'upload-3',
            targetPath: 'mods/retry-me.jar',
            status: 'success',
        });
        expect(snap[3]).toMatchObject({
            id: 'upload-4',
            targetPath: 'mods/cancel-me.jar',
            status: 'success',
        });

        // Calling retryFailed() afterwards does not re-trigger the superseded entries
        queue.retryFailed();
        await flushMicrotasks();
        expect(uploadedAttempts).toEqual([
            'mods/retry-me.jar',
            'mods/retry-me.jar',
            'mods/cancel-me.jar',
        ]);
    });

    it('recursively traverses webkitGetAsEntry directories across multiple readEntries batches, including empty directories, and creates empty folders in the queue', async () => {
        const fileInNested = createMockFile('server.properties', 42);
        const rootFile = createMockFile('readme.txt', 12);

        const emptyDirEntry = {
            isFile: false,
            isDirectory: true,
            name: 'empty-logs',
            createReader: () => ({
                readEntries: (cb: (entries: unknown[]) => void) => cb([]),
            }),
        };

        const fileEntry = {
            isFile: true,
            isDirectory: false,
            name: 'server.properties',
            file: (cb: (f: File) => void) => cb(fileInNested),
        };

        let subDirBatchCount = 0;
        const subDirEntry = {
            isFile: false,
            isDirectory: true,
            name: 'world',
            createReader: () => ({
                readEntries: (cb: (entries: unknown[]) => void) => {
                    subDirBatchCount += 1;
                    if (subDirBatchCount === 1) {
                        cb([fileEntry]);
                    } else if (subDirBatchCount === 2) {
                        cb([emptyDirEntry]);
                    } else {
                        cb([]);
                    }
                },
            }),
        };

        const rootFileEntry = {
            isFile: true,
            isDirectory: false,
            name: 'readme.txt',
            file: (cb: (f: File) => void) => cb(rootFile),
        };

        const fakeDataTransfer = {
            items: [
                {
                    kind: 'file',
                    webkitGetAsEntry: () => subDirEntry,
                },
                {
                    kind: 'file',
                    webkitGetAsEntry: () => rootFileEntry,
                },
            ],
            files: [rootFile],
        } as unknown as DataTransfer;

        const scanned = await scanTransferItems(fakeDataTransfer);
        expect(scanned.files).toHaveLength(2);
        expect(
            (scanned.files[0] as File & { webkitRelativePath?: string }).webkitRelativePath
        ).toBe('world/server.properties');
        expect(
            (scanned.files[1] as File & { webkitRelativePath?: string }).webkitRelativePath
        ).toBeFalsy();
        expect(scanned.emptyDirectories).toEqual(['world/empty-logs']);

        const ensuredDirs: string[] = [];
        const uploadedPaths: string[] = [];

        const queue = new McBrowserUploadQueue({
            ensureDirectory: async (dirPath) => {
                ensuredDirs.push(dirPath);
                return { success: true };
            },
            upload: async (targetPath) => {
                uploadedPaths.push(targetPath);
                return { success: true };
            },
            onChange: () => {},
        });

        queue.enqueue(scanned.files, 'imported', 1024, scanned.emptyDirectories);
        await flushMicrotasks(12);

        expect(ensuredDirs).toEqual(['imported/world', 'imported/world/empty-logs']);
        expect(uploadedPaths.sort()).toEqual([
            'imported/readme.txt',
            'imported/world/server.properties',
        ]);
        expect(queue.snapshot()).toEqual([
            expect.objectContaining({
                name: 'world/empty-logs',
                targetPath: 'imported/world/empty-logs',
                kind: 'directory',
                status: 'success',
            }),
            expect.objectContaining({
                name: 'world/server.properties',
                targetPath: 'imported/world/server.properties',
                kind: 'file',
                status: 'success',
            }),
            expect.objectContaining({
                name: 'readme.txt',
                targetPath: 'imported/readme.txt',
                kind: 'file',
                status: 'success',
            }),
        ]);
    });

    it('clears only settled results and retains cancelled requests until their promises settle', async () => {
        const request = createDeferred();
        const queue = new McBrowserUploadQueue({ upload: () => request.promise, onChange: () => {} });
        queue.enqueue([createMockFile('active.txt', 1)], '', 1024);
        await flushMicrotasks();
        queue.cancel();
        queue.clearCompleted();
        expect(queue.snapshot()).toHaveLength(1);
        request.reject(new DOMException('Aborted', 'AbortError'));
        await flushMicrotasks();
        queue.clearCompleted();
        expect(queue.snapshot()).toEqual([]);
    });

    it('returns immutable snapshots without leaking File references and stops callbacks after dispose', async () => {
        const uploadDeferred = createDeferred();
        const uploadedSignals: AbortSignal[] = [];
        let changeCount = 0;
        let idleCount = 0;

        const queue = new McBrowserUploadQueue({
            upload: (_path, _file, signal) => {
                uploadedSignals.push(signal);
                return uploadDeferred.promise;
            },
            onChange: () => {
                changeCount += 1;
            },
            onIdle: () => {
                idleCount += 1;
            },
        });

        const file = createMockFile('immutable.jar', 128);
        queue.enqueue([file], 'mods', 1024);
        await flushMicrotasks();

        const snap = queue.snapshot();
        expect(snap).toHaveLength(1);
        expect('file' in (snap[0] as unknown as Record<string, unknown>)).toBe(false);
        expect(Object.isFrozen(snap[0])).toBe(true);
        expect(() => {
            (snap[0] as { status: string }).status = 'success';
        }).toThrow();

        const changesBeforeDispose = changeCount;
        queue.dispose();
        expect(uploadedSignals[0].aborted).toBe(true);

        uploadDeferred.resolve({ success: true });
        await flushMicrotasks();

        expect(changeCount).toBe(changesBeforeDispose);
        expect(idleCount).toBe(0);
    });

    it('does not restart a pausing transport before the original request settles', async () => {
        const attempts: Deferred<unknown>[] = [];
        const queue = new McBrowserUploadQueue({
            concurrency: 3,
            upload: () => {
                const attempt = createDeferred();
                attempts.push(attempt);
                return attempt.promise;
            },
            onChange: () => {},
        });
        queue.enqueue([createMockFile('paused.bin', 512)], '', 4096);
        await flushMicrotasks();
        queue.pause('upload-1');
        queue.resume('upload-1');
        await flushMicrotasks();
        expect(queue.snapshot()[0].status).toBe('pausing');
        expect(attempts).toHaveLength(1);
        attempts[0].reject(new DOMException('Aborted', 'AbortError'));
        await flushMicrotasks();
        expect(attempts).toHaveLength(2);
        attempts[1].resolve({ success: true });
        await flushMicrotasks();
        expect(queue.snapshot()[0].status).toBe('success');
        queue.dispose();
    });

    it('settles cancellation during shared directory creation without awaiting the network', async () => {
        const directory = createDeferred();
        const ensureDirectory = jest.fn(() => directory.promise);
        const upload = jest.fn(async () => ({ success: true }));
        const queue = new McBrowserUploadQueue({
            ensureDirectory,
            upload,
            onChange: () => {},
        });
        queue.enqueue([createMockFile('note.txt', 5, 'folder/note.txt')], '', 4096);
        await flushMicrotasks();
        expect(ensureDirectory).toHaveBeenCalledTimes(1);
        queue.cancel('upload-1');
        await flushMicrotasks();
        expect(queue.snapshot()[0].status).toBe('cancelled');
        queue.retryFailed();
        await flushMicrotasks();
        expect(queue.snapshot()[0].status).toBe('uploading');
        expect(ensureDirectory).toHaveBeenCalledTimes(1);
        directory.resolve({ success: true });
        await flushMicrotasks();
        expect(upload).toHaveBeenCalledTimes(1);
        expect(queue.snapshot()[0].status).toBe('success');
        queue.dispose();
    });

    it('blocks retry, clearing and destination reselection until remote cancellation is confirmed', async () => {
        const transport = createDeferred();
        const cancellation = createDeferred<{ cancelled: boolean }>();
        const upload = jest.fn(() => transport.promise);
        const queue = new McBrowserUploadQueue({
            upload,
            cancelSession: () => cancellation.promise,
            concurrency: 3,
            onChange: () => {},
        });
        queue.enqueue([createMockFile('cancel.bin', 512)], '', 4096);
        await flushMicrotasks();
        queue.pause('upload-1');
        transport.reject(new DOMException('Aborted', 'AbortError'));
        await flushMicrotasks();
        queue.cancel('upload-1');
        queue.retryFailed();
        queue.clearCompleted();
        expect(queue.snapshot()[0].status).toBe('cancelling');
        queue.enqueue([createMockFile('cancel.bin', 512)], '', 4096);
        expect(queue.snapshot()[1].status).toBe('error');
        expect(upload).toHaveBeenCalledTimes(1);
        cancellation.resolve({ cancelled: true });
        await flushMicrotasks();
        expect(queue.snapshot()[0].status).toBe('cancelled');
        queue.dispose();
    });

});
