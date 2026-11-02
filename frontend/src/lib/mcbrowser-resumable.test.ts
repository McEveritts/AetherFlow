import { webcrypto } from 'crypto';
import { McBrowserRequestError } from '@/lib/mcbrowser';
import {
    DEFAULT_TUS_CHUNK_BYTES,
    FINGERPRINT_SAMPLE_BYTES,
    MAX_RESUMABLE_RETRIES,
    MAX_TUS_CHUNK_BYTES,
    MCBROWSER_UPLOADS_ENDPOINT,
    McBrowserResumableProgress,
    McBrowserUploadUncertaintyError,
    TUS_RESUMABLE_VERSION,
    cancelMcBrowserResumable,
    cancelMcBrowserResumableSession,
    computeMcBrowserFileFingerprint,
    findResumableUploadSession,
    headMcBrowserResumableUpload,
    isMcBrowserUploadUncertainError,
    listMcBrowserResumableUploads,
    parseTusMetadata,
    serializeTusMetadata,
    uploadMcBrowserResumable,
    validateTusUploadLocation,
} from '@/lib/mcbrowser-resumable';

interface FakeSessionRecord {
    id: string;
    path: string;
    publishedPath: string;
    length: number;
    offset: number;
    status: 'uploading' | 'completed';
    fingerprint?: string;
    conflict?: string;
    data: Uint8Array;
}

class FakeTusBackend {
    public sessions = new Map<string, FakeSessionRecord>();
    public requestLog: Array<{
        method: string;
        url: string;
        headers: Headers;
        credentials?: RequestCredentials;
        bodySize: number;
    }> = [];

    private nextSessionIndex = 1;
    public omitFingerprintInList = false;
    public omitFingerprintInHead = false;
    public customLocationOnPost: string | null = null;
    public patchHooks: Array<
        (ctx: {
            session: FakeSessionRecord;
            chunkBytes: Uint8Array;
            requestOffset: number;
            attemptIndex: number;
        }) => Promise<Response | null> | Response | null
    > = [];
    public headHooks: Array<
        (session: FakeSessionRecord) => Promise<Response | null> | Response | null
    > = [];
    public postHook:
        | ((req: {
              url: string;
              headers: Headers;
              metadata: Record<string, string>;
              length: number;
          }) => Promise<Response | null> | Response | null)
        | null = null;

    private patchAttemptCount = 0;

    public installFetchMock(): jest.SpiedFunction<typeof fetch> {
        return jest.spyOn(global, 'fetch').mockImplementation(async (input, init) => {
            const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
            const method = (init?.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
            const headers = new Headers(init?.headers || (input instanceof Request ? input.headers : undefined));

            let bodyBytes: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
            if (init?.body instanceof Blob) {
                const ab = await init.body.arrayBuffer();
                bodyBytes = new Uint8Array(ab);
            } else if (init?.body instanceof Uint8Array) {
                bodyBytes = new Uint8Array(init.body);
            } else if (typeof init?.body === 'string') {
                bodyBytes = new TextEncoder().encode(init.body);
            }

            this.requestLog.push({
                method,
                url: urlStr,
                headers,
                credentials: init?.credentials,
                bodySize: bodyBytes.byteLength,
            });

            const parsedUrl = new URL(urlStr, 'http://localhost');

            // 1. GET /api/v1/auth/mcbrowser/uploads
            if (method === 'GET' && parsedUrl.pathname === MCBROWSER_UPLOADS_ENDPOINT) {
                const filterPath = parsedUrl.searchParams.get('path');
                const filterLengthStr = parsedUrl.searchParams.get('length');
                const filterLength = filterLengthStr !== null ? Number(filterLengthStr) : null;
                const filterFp = parsedUrl.searchParams.get('fingerprint');

                const uploads = Array.from(this.sessions.values())
                    .filter((sess) => {
                        if (sess.status === 'completed') return false;
                        if (filterPath !== null && sess.path !== filterPath) return false;
                        if (filterLength !== null && sess.length !== filterLength) return false;
                        if (!this.omitFingerprintInList && filterFp !== null && sess.fingerprint && sess.fingerprint !== filterFp) {
                            return false;
                        }
                        return true;
                    })
                    .map((sess) => ({
                        id: sess.id,
                        path: sess.path,
                        length: sess.length,
                        offset: sess.offset,
                        status: sess.status,
                        ...(!this.omitFingerprintInList && sess.fingerprint
                            ? { fingerprint: sess.fingerprint }
                            : {}),
                    }));

                return new Response(JSON.stringify({ uploads }), {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' },
                });
            }

            // 2. POST /api/v1/auth/mcbrowser/uploads
            if (method === 'POST' && parsedUrl.pathname === MCBROWSER_UPLOADS_ENDPOINT) {
                const length = Number(headers.get('Upload-Length') ?? '0');
                const metadata = parseTusMetadata(headers.get('Upload-Metadata'));

                if (this.postHook) {
                    const customRes = await this.postHook({
                        url: urlStr,
                        headers,
                        metadata,
                        length,
                    });
                    if (customRes) {
                        return customRes;
                    }
                }

                const id = `sess_${this.nextSessionIndex}`;
                this.nextSessionIndex += 1;

                const status: 'uploading' | 'completed' = length === 0 ? 'completed' : 'uploading';
                const publishedPath =
                    metadata.conflict === 'keep-both'
                        ? metadata.path.replace(/(\.[^.]+)$/, ' (1)$1')
                        : metadata.path;

                const record: FakeSessionRecord = {
                    id,
                    path: metadata.path,
                    publishedPath,
                    length,
                    offset: 0,
                    status,
                    fingerprint: metadata.fingerprint,
                    conflict: metadata.conflict,
                    data: new Uint8Array(length),
                };
                this.sessions.set(id, record);

                const location = this.customLocationOnPost ?? `${MCBROWSER_UPLOADS_ENDPOINT}/${id}`;
                return new Response(null, {
                    status: 201,
                    headers: {
                        'Tus-Resumable': TUS_RESUMABLE_VERSION,
                        Location: location,
                        'Upload-Offset': '0',
                        'Upload-Status': status,
                        'Upload-Path': publishedPath,
                        'Upload-Metadata': serializeTusMetadata({ path: publishedPath, conflict: metadata.conflict }),
                    },
                });
            }

            // 3. Session-specific routes: HEAD / PATCH / DELETE /api/v1/auth/mcbrowser/uploads/{id}
            const match = /^\/api\/v1\/auth\/mcbrowser\/uploads\/([^/]+)$/.exec(parsedUrl.pathname);
            if (match) {
                const id = match[1];
                const session = this.sessions.get(id);
                if (!session) {
                    return new Response(
                        JSON.stringify({ code: 'NOT_FOUND', message: 'Upload session not found' }),
                        { status: 404, headers: { 'Content-Type': 'application/json' } }
                    );
                }

                if (method === 'HEAD') {
                    const nextHeadHook = this.headHooks.shift();
                    if (nextHeadHook) {
                        const hooked = await nextHeadHook(session);
                        if (hooked) {
                            return hooked;
                        }
                    }

                    const metadataEntries: Record<string, string | undefined> = {
                        path: session.publishedPath,
                        conflict: session.conflict ?? 'error',
                        ...(!this.omitFingerprintInHead && session.fingerprint
                            ? { fingerprint: session.fingerprint }
                            : {}),
                    };

                    return new Response(null, {
                        status: 200,
                        headers: {
                            'Tus-Resumable': TUS_RESUMABLE_VERSION,
                            'Upload-Offset': String(session.offset),
                            'Upload-Length': String(session.length),
                            'Upload-Status': session.status,
                            'Upload-Path': session.publishedPath,
                            'Upload-Metadata': serializeTusMetadata(metadataEntries),
                        },
                    });
                }

                if (method === 'PATCH') {
                    this.patchAttemptCount += 1;
                    const reqOffset = Number(headers.get('Upload-Offset') ?? '-1');

                    const nextPatchHook = this.patchHooks.shift();
                    if (nextPatchHook) {
                        const hooked = await nextPatchHook({
                            session,
                            chunkBytes: bodyBytes,
                            requestOffset: reqOffset,
                            attemptIndex: this.patchAttemptCount,
                        });
                        if (hooked) {
                            return hooked;
                        }
                    }

                    if (reqOffset !== session.offset) {
                        return new Response(
                            JSON.stringify({
                                code: 'OFFSET_MISMATCH',
                                message: `Expected offset ${session.offset}, got ${reqOffset}`,
                            }),
                            { status: 409, headers: { 'Content-Type': 'application/json' } }
                        );
                    }

                    session.data.set(bodyBytes, session.offset);
                    session.offset += bodyBytes.byteLength;
                    if (session.offset >= session.length) {
                        session.status = 'completed';
                    }

                    return new Response(null, {
                        status: 204,
                        headers: {
                            'Tus-Resumable': TUS_RESUMABLE_VERSION,
                            'Upload-Offset': String(session.offset),
                            'Upload-Status': session.status,
                            'Upload-Path': session.publishedPath,
                            'Upload-Metadata': serializeTusMetadata({ path: session.publishedPath, conflict: session.conflict }),
                        },
                    });
                }

                if (method === 'DELETE') {
                    if (session.status === 'completed') {
                        return new Response(
                            JSON.stringify({
                                code: 'ALREADY_COMPLETED',
                                message: 'Upload already completed and published; cannot delete.',
                            }),
                            { status: 409, headers: { 'Content-Type': 'application/json' } }
                        );
                    }
                    this.sessions.delete(id);
                    return new Response(null, {
                        status: 204,
                        headers: { 'Tus-Resumable': TUS_RESUMABLE_VERSION },
                    });
                }
            }

            return new Response(
                JSON.stringify({ code: 'UNHANDLED_ROUTE', message: `Unhandled ${method} ${urlStr}` }),
                { status: 500, headers: { 'Content-Type': 'application/json' } }
            );
        });
    }
}

function createPatternFile(
    name: string,
    sizeBytes: number,
    seedByte = 1,
    lastModified = 1762030000000
): { file: File; bytes: Uint8Array } {
    const bytes = new Uint8Array(sizeBytes);
    for (let i = 0; i < sizeBytes; i += 1) {
        bytes[i] = (seedByte + i * 31) & 0xff;
    }
    const file = new File([bytes], name, {
        type: 'application/octet-stream',
        lastModified,
    });
    if (typeof file.arrayBuffer !== 'function') {
        Object.defineProperty(file, 'arrayBuffer', {
            configurable: true,
            value: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
        });
    }
    const originalSlice = file.slice.bind(file);
    jest.spyOn(file, 'slice').mockImplementation((start?: number, end?: number, contentType?: string) => {
        const sliced = originalSlice(start, end, contentType);
        const s = Math.max(0, start ?? 0);
        const e = Math.min(sizeBytes, end ?? sizeBytes);
        const sub = bytes.subarray(s, e);
        if (typeof sliced.arrayBuffer !== 'function') {
            Object.defineProperty(sliced, 'arrayBuffer', {
                configurable: true,
                value: async () => sub.buffer.slice(sub.byteOffset, sub.byteOffset + sub.byteLength),
            });
        }
        return sliced;
    });
    return { file, bytes };
}

describe('mcbrowser-resumable TUS 1.0 client', () => {
    const originalCrypto = globalThis.crypto;

    beforeAll(() => {
        Object.defineProperty(globalThis, 'crypto', {
            value: webcrypto,
            configurable: true,
            writable: true,
        });
    });

    afterAll(() => {
        Object.defineProperty(globalThis, 'crypto', {
            value: originalCrypto,
            configurable: true,
            writable: true,
        });
    });

    beforeEach(() => {
        document.cookie = 'csrf_token=csrf-tus-token-999; path=/';
        window.localStorage.clear();
    });

    afterEach(() => {
        jest.restoreAllMocks();
        document.cookie = 'csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
    });

    it('does not report success when all bytes reached staging but publication remains unfinished', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();
        backend.patchHooks.push(({ session, chunkBytes }) => {
            session.offset += chunkBytes.length;
            session.status = 'uploading';
            return new Response(null, { status: 204, headers: {
                'Upload-Offset': String(session.offset), 'Upload-Status': 'uploading',
            } });
        });
        const { file } = createPatternFile('pending.txt', 1024);
        await expect(uploadMcBrowserResumable('pending.txt', file, { retryDelayMs: 0 }))
            .rejects.toBeInstanceOf(McBrowserUploadUncertaintyError);
        expect(backend.requestLog.filter((request) => request.method === 'HEAD')).toHaveLength(4);
    });

    it('does not mistake a full-offset recovered session for a published file', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();
        const { file } = createPatternFile('recovered.txt', 1024);
        const fingerprint = await computeMcBrowserFileFingerprint(file);
        backend.sessions.set('unfinished', { id: 'unfinished', path: 'recovered.txt', publishedPath: 'recovered.txt',
            length: file.size, offset: file.size, status: 'uploading', fingerprint, data: new Uint8Array(file.size) });
        await expect(uploadMcBrowserResumable('recovered.txt', file, { retryDelayMs: 0 }))
            .rejects.toBeInstanceOf(McBrowserUploadUncertaintyError);
        expect(backend.requestLog.filter((request) => request.method === 'PATCH')).toHaveLength(0);
    });

    it('rejects a PATCH acknowledgement jumping beyond the chunk actually sent', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();
        backend.patchHooks.push(() => new Response(null, { status: 204, headers: { 'Upload-Offset': '4096' } }));
        const { file } = createPatternFile('jump.txt', 4096);
        await expect(uploadMcBrowserResumable('jump.txt', file, { chunkSize: 1024, retryDelayMs: 0 }))
            .rejects.toMatchObject({ code: 'INVALID_TUS_OFFSET' });
    });

    it('marks persistent retryable HTTP failures uncertain after reconciling the last attempt', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();
        for (let attempt = 0; attempt <= MAX_RESUMABLE_RETRIES; attempt += 1) {
            backend.patchHooks.push(() => new Response(JSON.stringify({ code: 'UPSTREAM_TIMEOUT', message: 'Unknown final state' }), {
                status: 504, headers: { 'Content-Type': 'application/json' },
            }));
        }
        const { file } = createPatternFile('timeout.txt', 1024);
        await expect(uploadMcBrowserResumable('timeout.txt', file, { retryDelayMs: 0 }))
            .rejects.toBeInstanceOf(McBrowserUploadUncertaintyError);
        expect(backend.requestLog.filter((request) => request.method === 'HEAD')).toHaveLength(4);
    });

    it('exports expected TUS constants and helpers', () => {
        expect(TUS_RESUMABLE_VERSION).toBe('1.0.0');
        expect(DEFAULT_TUS_CHUNK_BYTES).toBe(4 * 1024 * 1024);
        expect(MAX_TUS_CHUNK_BYTES).toBe(4 * 1024 * 1024);
        expect(FINGERPRINT_SAMPLE_BYTES).toBe(64 * 1024);
        expect(MAX_RESUMABLE_RETRIES).toBe(3);
    });

    it('uploads a multi-chunk file (<= 4 MiB per PATCH), confirms byte progress via server offsets, sends CSRF & credentials, and never leaks tokens in URLs or localStorage', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();

        const totalSize = 9 * 1024 * 1024 + 512; // > 2 chunks of 4 MiB -> 3 PATCH calls
        const { file, bytes } = createPatternFile('world-backup.tar.gz', totalSize, 7);
        const progressEvents: McBrowserResumableProgress[] = [];

        const result = await uploadMcBrowserResumable('backups/world #1/world-backup.tar.gz', file, {
            onProgress: (p) => progressEvents.push(p),
        });

        expect(result).toEqual({
            success: true,
            path: 'backups/world #1/world-backup.tar.gz',
        });

        // Verify 3 PATCH requests with chunks <= 4 MiB
        const patchRequests = backend.requestLog.filter((r) => r.method === 'PATCH');
        expect(patchRequests).toHaveLength(3);
        expect(patchRequests[0].bodySize).toBe(4 * 1024 * 1024);
        expect(patchRequests[1].bodySize).toBe(4 * 1024 * 1024);
        expect(patchRequests[2].bodySize).toBe(1024 * 1024 + 512);

        for (const req of patchRequests) {
            expect(req.bodySize).toBeLessThanOrEqual(MAX_TUS_CHUNK_BYTES);
            expect(req.headers.get('Tus-Resumable')).toBe('1.0.0');
            expect(req.headers.get('Content-Type')).toBe('application/offset+octet-stream');
            expect(req.headers.get('X-CSRF-Token')).toBe('csrf-tus-token-999');
            expect(req.credentials).toBe('include');
            expect(req.url).not.toMatch(/token=|jwt=|access_token=|auth=/i);
        }

        // Verify POST creation headers and metadata
        const postReq = backend.requestLog.find((r) => r.method === 'POST');
        expect(postReq).toBeDefined();
        expect(postReq!.headers.get('Tus-Resumable')).toBe('1.0.0');
        expect(postReq!.headers.get('Upload-Length')).toBe(String(totalSize));
        expect(postReq!.headers.get('X-CSRF-Token')).toBe('csrf-tus-token-999');
        expect(postReq!.credentials).toBe('include');

        const sentMeta = parseTusMetadata(postReq!.headers.get('Upload-Metadata'));
        expect(sentMeta.path).toBe('backups/world #1/world-backup.tar.gz');
        expect(sentMeta.fingerprint).toMatch(/^v1:\d+:\d+:[0-9a-f]{64}$/);

        // Verify confirmed progress milestones match server offsets
        expect(progressEvents.map((p) => p.uploadedBytes)).toEqual([
            0,
            4 * 1024 * 1024,
            8 * 1024 * 1024,
            totalSize,
        ]);
        expect(progressEvents.every((p) => p.totalBytes === totalSize)).toBe(true);
        expect(progressEvents[progressEvents.length - 1].speedBytesPerSecond).toBeGreaterThanOrEqual(0);

        // Verify assembled bytes on fake backend match source file exactly
        const storedSession = backend.sessions.get('sess_1')!;
        expect(storedSession.status).toBe('completed');
        expect(storedSession.offset).toBe(totalSize);
        expect(Buffer.compare(Buffer.from(storedSession.data), Buffer.from(bytes))).toBe(0);

        // Never persist file bytes or tokens in localStorage
        expect(window.localStorage.length).toBe(0);
    });

    it('auto-publishes zero-byte files immediately on POST creation without sending PATCH requests', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();

        const { file } = createPatternFile('empty.txt', 0);
        const progressEvents: McBrowserResumableProgress[] = [];

        const result = await uploadMcBrowserResumable('notes/empty.txt', file, {
            onProgress: (p) => progressEvents.push(p),
        });

        expect(result).toEqual({
            success: true,
            path: 'notes/empty.txt',
        });
        expect(backend.requestLog.map((r) => r.method)).toEqual(['POST']);
        expect(progressEvents).toEqual([
            {
                uploadedBytes: 0,
                totalBytes: 0,
                speedBytesPerSecond: 0,
            },
        ]);
    });

    it('recovers and resumes an unfinished session after page reload/reselection when path, size, and SHA-256 fingerprint match', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();

        const { file, bytes } = createPatternFile('modpack.zip', 3000, 42, 1762031111000);
        const fp = await computeMcBrowserFileFingerprint(file);

        // Pre-populate unfinished session on backend at offset 1000
        const partialData = new Uint8Array(3000);
        partialData.set(bytes.subarray(0, 1000), 0);
        backend.sessions.set('sess_resume_1', {
            id: 'sess_resume_1',
            path: 'mods/modpack.zip',
            publishedPath: 'mods/modpack.zip',
            length: 3000,
            offset: 1000,
            status: 'uploading',
            fingerprint: fp,
            data: partialData,
        });

        const progressOffsets: number[] = [];
        const res = await uploadMcBrowserResumable('mods/modpack.zip', file, {
            chunkSize: 1000,
            onProgress: (p) => progressOffsets.push(p.uploadedBytes),
        });

        expect(res).toEqual({ success: true, path: 'mods/modpack.zip' });

        // Should have called GET (list), HEAD (verify), and 2 PATCH calls (1000..2000, 2000..3000) without POST
        expect(backend.requestLog.map((r) => r.method)).toEqual(['GET', 'HEAD', 'PATCH', 'PATCH']);
        expect(progressOffsets).toEqual([1000, 2000, 3000]);

        const completed = backend.sessions.get('sess_resume_1')!;
        expect(completed.status).toBe('completed');
        expect(Buffer.compare(Buffer.from(completed.data), Buffer.from(bytes))).toBe(0);
    });

    it('does NOT mix different same-name same-size files on reload and fail-safely creates a new session if fingerprint mismatches or is absent on backend', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();

        const { file: oldFile, bytes: oldBytes } = createPatternFile(
            'config.bin',
            2048,
            11,
            1762000000000
        );
        const { file: newFile, bytes: newBytes } = createPatternFile(
            'config.bin',
            2048,
            99,
            1762000000000 // Even with identical timestamp and size, content differs!
        );

        const oldFp = await computeMcBrowserFileFingerprint(oldFile);
        const newFp = await computeMcBrowserFileFingerprint(newFile);
        expect(oldFp).not.toBe(newFp);

        // Backend has unfinished session for oldFile
        const staleData = new Uint8Array(2048);
        staleData.set(oldBytes.subarray(0, 1024), 0);
        backend.sessions.set('sess_old', {
            id: 'sess_old',
            path: 'configs/config.bin',
            publishedPath: 'configs/config.bin',
            length: 2048,
            offset: 1024,
            status: 'uploading',
            fingerprint: oldFp,
            data: staleData,
        });

        // Case A: Backend returns session in list without fingerprint filter, client checks fingerprint and rejects mismatch
        backend.omitFingerprintInList = true;
        const resMismatch = await uploadMcBrowserResumable('configs/config.bin', newFile, {
            chunkSize: 1024,
        });
        expect(resMismatch).toEqual({ success: true, path: 'configs/config.bin' });

        // Must have created a brand-new session sess_1 and uploaded from offset 0
        const newSession = backend.sessions.get('sess_1')!;
        expect(newSession).toBeDefined();
        expect(newSession.status).toBe('completed');
        expect(Buffer.compare(Buffer.from(newSession.data), Buffer.from(newBytes))).toBe(0);
        // Old session was untouched
        expect(backend.sessions.get('sess_old')!.offset).toBe(1024);

        // Case B: Backend omits fingerprint in both GET list and HEAD metadata -> fail-safe create new session
        backend.omitFingerprintInHead = true;
        await uploadMcBrowserResumable('configs/config.bin', oldFile, {
            chunkSize: 1024,
        });
        expect(backend.sessions.has('sess_2')).toBe(true);
        expect(backend.sessions.get('sess_old')!.offset).toBe(1024);
    });

    it('reconciles via HEAD when a network error occurs after server commits a chunk (network-after-commit), completing without re-sending committed bytes', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();

        const { file, bytes } = createPatternFile('plugin.jar', 2000, 5);

        // Simulate first PATCH (0..1000) succeeding on the server, then throwing a network error before response reaches client
        backend.patchHooks.push(({ session, chunkBytes }) => {
            session.data.set(chunkBytes, session.offset);
            session.offset += chunkBytes.byteLength;
            throw new TypeError('Network connection lost after server write');
        });

        // Also simulate second PATCH failing once with 409 Conflict after another concurrent commit
        backend.patchHooks.push(({ session, chunkBytes }) => {
            session.data.set(chunkBytes, session.offset);
            session.offset += chunkBytes.byteLength;
            session.status = 'completed';
            return new Response(
                JSON.stringify({ code: 'CONFLICT', message: 'Offset changed concurrently' }),
                { status: 409, headers: { 'Content-Type': 'application/json' } }
            );
        });

        const progressOffsets: number[] = [];
        const result = await uploadMcBrowserResumable('plugins/plugin.jar', file, {
            chunkSize: 1000,
            retryDelayMs: 1,
            onProgress: (p) => progressOffsets.push(p.uploadedBytes),
        });

        expect(result).toEqual({ success: true, path: 'plugins/plugin.jar' });
        expect(progressOffsets).toEqual([0, 1000, 2000]);

        const finalSession = backend.sessions.get('sess_1')!;
        expect(finalSession.status).toBe('completed');
        expect(Buffer.compare(Buffer.from(finalSession.data), Buffer.from(bytes))).toBe(0);
    });

    it('bounds retries to at most 3 attempts with exponential backoff and surfaces distinguishable McBrowserUploadUncertaintyError when commit state cannot be reconciled', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();

        const { file } = createPatternFile('unstable.bin', 1000, 13);

        // Every PATCH throws a network failure and every reconciling HEAD also fails with 503
        for (let i = 0; i < 10; i += 1) {
            backend.patchHooks.push(() => {
                throw new TypeError('Socket hang up during PATCH');
            });
            backend.headHooks.push(() => {
                return new Response(
                    JSON.stringify({ code: 'UNAVAILABLE', message: 'Gateway timeout' }),
                    { status: 503, headers: { 'Content-Type': 'application/json' } }
                );
            });
        }

        let caughtError: unknown = null;
        try {
            await uploadMcBrowserResumable('mods/unstable.bin', file, {
                chunkSize: 1000,
                retryDelayMs: 1,
            });
        } catch (err) {
            caughtError = err;
        }

        expect(caughtError).toBeInstanceOf(McBrowserUploadUncertaintyError);
        expect(caughtError).toBeInstanceOf(McBrowserRequestError);
        expect(isMcBrowserUploadUncertainError(caughtError)).toBe(true);
        expect((caughtError as McBrowserUploadUncertaintyError).code).toBe('UPLOAD_UNCERTAIN_COMMIT');

        // 1 initial PATCH + 3 retry cycles (each doing HEAD; since HEAD fails, it loops up to 3 retries)
        const headCalls = backend.requestLog.filter((r) => r.method === 'HEAD');
        expect(headCalls).toHaveLength(MAX_RESUMABLE_RETRIES);
    });

    it('fails fast on HTTP 4xx quota/limit errors (413, 403, 507) without retrying', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();

        const { file } = createPatternFile('quota-exceeded.bin', 2000, 3);

        backend.patchHooks.push(() => {
            return new Response(
                JSON.stringify({
                    code: 'QUOTA_EXCEEDED',
                    message: 'User storage quota exceeded.',
                }),
                { status: 413, headers: { 'Content-Type': 'application/json' } }
            );
        });

        await expect(
            uploadMcBrowserResumable('backups/quota-exceeded.bin', file, {
                chunkSize: 1000,
                retryDelayMs: 1,
            })
        ).rejects.toMatchObject({
            name: 'McBrowserRequestError',
            status: 413,
            code: 'QUOTA_EXCEEDED',
            message: 'User storage quota exceeded.',
        });

        // Must NOT have issued any retry PATCH or reconciling HEAD
        expect(backend.requestLog.map((r) => r.method)).toEqual([' GET'.trim(), 'POST', 'PATCH']);
    });

    it('treats AbortSignal as pause (does not DELETE server session) so subsequent reselection resumes from committed offset, while cancelMcBrowserResumable explicitly sends DELETE', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();

        const { file } = createPatternFile('pausable.tar', 3000, 21);
        const abortController = new AbortController();

        // Abort right after the first 1000-byte chunk commits
        let firstChunkDone = false;
        const progressPromise = uploadMcBrowserResumable('backups/pausable.tar', file, {
            chunkSize: 1000,
            signal: abortController.signal,
            onProgress: (p) => {
                if (p.uploadedBytes === 1000 && !firstChunkDone) {
                    firstChunkDone = true;
                    abortController.abort();
                }
            },
        });

        await expect(progressPromise).rejects.toThrow(/aborted/i);

        // Session must still exist on the server at offset 1000 (no DELETE sent on abort)
        expect(backend.requestLog.some((r) => r.method === 'DELETE')).toBe(false);
        expect(backend.sessions.get('sess_1')?.offset).toBe(1000);

        // Explicit cancellation helper finds and DELETEs the unfinished session (204)
        const cancelResult = await cancelMcBrowserResumable('backups/pausable.tar', file);
        expect(cancelResult).toEqual({
            cancelled: true,
            sessionId: 'sess_1',
        });
        expect(backend.sessions.has('sess_1')).toBe(false);

        // Calling DELETE on an already-completed session surfaces 409 without false rollback promise
        backend.sessions.set('sess_done', {
            id: 'sess_done',
            path: 'backups/done.tar',
            publishedPath: 'backups/done.tar',
            length: 500,
            offset: 500,
            status: 'completed',
            data: new Uint8Array(500),
        });

        await expect(cancelMcBrowserResumableSession('sess_done')).rejects.toMatchObject({
            name: 'McBrowserRequestError',
            status: 409,
            code: 'ALREADY_COMPLETED',
        });
    });

    it('rejects malicious or cross-origin Location headers before sending any authenticated follow-up requests', async () => {
        const maliciousLocations = [
            'https://evil.example.com/api/v1/auth/mcbrowser/uploads/sess_1',
            '//evil.example.com/api/v1/auth/mcbrowser/uploads/sess_1',
            'http://localhost:9999/api/v1/auth/mcbrowser/uploads/sess_1',
            '/api/v1/auth/mcbrowser/uploads/../../admin/users',
            '/api/v1/auth/mcbrowser/uploads/sess_1?token=steal',
            '/api/v1/auth/mcbrowser/uploads/sess_1#frag',
            '/api/v1/public/other/endpoint',
            'javascript:alert(1)',
        ];

        for (const badLocation of maliciousLocations) {
            expect(() => validateTusUploadLocation(badLocation)).toThrow(McBrowserRequestError);
        }

        const backend = new FakeTusBackend();
        backend.customLocationOnPost = 'https://attacker.invalid/api/v1/auth/mcbrowser/uploads/sess_1';
        backend.installFetchMock();

        const { file } = createPatternFile('secret.txt', 128);
        await expect(uploadMcBrowserResumable('secret.txt', file)).rejects.toMatchObject({
            name: 'McBrowserRequestError',
            status: 502,
            code: 'INVALID_UPLOAD_LOCATION',
        });

        // Ensure no PATCH or HEAD was ever sent to the malicious Location
        expect(backend.requestLog.map((r) => r.method)).toEqual(['GET', 'POST']);
    });

    it('fails closed when Web Crypto SHA-256 is unavailable instead of falling back to a weak fingerprint', async () => {
        const savedCrypto = globalThis.crypto;
        Object.defineProperty(globalThis, 'crypto', {
            value: undefined,
            configurable: true,
            writable: true,
        });

        try {
            const { file } = createPatternFile('no-crypto.bin', 64);
            await expect(computeMcBrowserFileFingerprint(file)).rejects.toMatchObject({
                name: 'McBrowserRequestError',
                status: 500,
                code: 'CRYPTO_UNAVAILABLE',
            });
            await expect(uploadMcBrowserResumable('mods/no-crypto.bin', file)).rejects.toMatchObject({
                name: 'McBrowserRequestError',
                status: 500,
                code: 'CRYPTO_UNAVAILABLE',
            });
        } finally {
            Object.defineProperty(globalThis, 'crypto', {
                value: savedCrypto,
                configurable: true,
                writable: true,
            });
        }
    });

    it('does not resume a session created under a different conflict policy', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();
        const { file } = createPatternFile('existing.bin', 512);
        const fingerprint = await computeMcBrowserFileFingerprint(file);
        backend.sessions.set('no_clobber', {
            id: 'no_clobber',
            path: 'existing.bin',
            publishedPath: 'existing.bin',
            length: file.size,
            offset: 128,
            status: 'uploading',
            fingerprint,
            conflict: 'error',
            data: new Uint8Array(file.size),
        });
        const session = await findResumableUploadSession('existing.bin', file, { fingerprint, conflict: 'overwrite' });
        expect(session).toBeNull();
        const matching = await findResumableUploadSession('existing.bin', file, { fingerprint, conflict: 'error' });
        expect(matching?.id).toBe('no_clobber');
    });

    it('preserves filename spaces from metadata when HTTP trims the direct path header', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();
        const targetPath = ' spaced name.bin ';
        const { file } = createPatternFile('spaced.bin', 512);
        const fingerprint = await computeMcBrowserFileFingerprint(file);
        backend.sessions.set('spaced', {
            id: 'spaced', path: targetPath, publishedPath: targetPath,
            length: file.size, offset: 128, status: 'uploading', fingerprint,
            data: new Uint8Array(file.size),
        });
        const head = await headMcBrowserResumableUpload(`${MCBROWSER_UPLOADS_ENDPOINT}/spaced`);
        expect(head.path).toBe(targetPath);
        expect(head.publishedPath).toBe(targetPath);
        const result = await uploadMcBrowserResumable(targetPath, file);
        expect(result.path).toBe(targetPath);
    });

    it('rejects unrecognized server conflict policies instead of coercing them', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();
        backend.sessions.set('invalid_policy', {
            id: 'invalid_policy', path: 'file.bin', publishedPath: 'file.bin',
            length: 512, offset: 0, status: 'uploading', conflict: 'replace-everything',
            data: new Uint8Array(512),
        });
        await expect(headMcBrowserResumableUpload(`${MCBROWSER_UPLOADS_ENDPOINT}/invalid_policy`))
            .rejects.toMatchObject({ status: 502, code: 'INVALID_TUS_CONFLICT_POLICY' });
    });

    it('forwards conflict policy in Upload-Metadata and honors server-resolved path (e.g. keep-both)', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();

        const { file } = createPatternFile('dupe.jar', 512);
        const res = await uploadMcBrowserResumable('mods/dupe.jar', file, {
            conflict: 'keep-both',
        });

        expect(res).toEqual({
            success: true,
            path: 'mods/dupe (1).jar',
        });
    });

    it('discovers matching session via findResumableUploadSession and lists sessions via listMcBrowserResumableUploads', async () => {
        const backend = new FakeTusBackend();
        backend.installFetchMock();

        const { file } = createPatternFile('world.zip', 4096, 77);
        const fp = await computeMcBrowserFileFingerprint(file);

        backend.sessions.set('sess_abc', {
            id: 'sess_abc',
            path: 'worlds/world.zip',
            publishedPath: 'worlds/world.zip',
            length: 4096,
            offset: 2048,
            status: 'uploading',
            fingerprint: fp,
            data: new Uint8Array(4096),
        });

        const listed = await listMcBrowserResumableUploads({
            path: 'worlds/world.zip',
            length: 4096,
            fingerprint: fp,
        });
        expect(listed).toEqual([
            {
                id: 'sess_abc',
                path: 'worlds/world.zip',
                length: 4096,
                offset: 2048,
                status: 'uploading',
                fingerprint: fp,
            },
        ]);

        const found = await findResumableUploadSession('worlds/world.zip', file);
        expect(found).toMatchObject({
            id: 'sess_abc',
            location: '/api/v1/auth/mcbrowser/uploads/sess_abc',
            offset: 2048,
            length: 4096,
            status: 'uploading',
            fingerprint: fp,
        });

        const headDirect = await headMcBrowserResumableUpload('sess_abc');
        expect(headDirect.offset).toBe(2048);
    });
});
