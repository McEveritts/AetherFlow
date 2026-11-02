import { TextEncoder, TextDecoder } from 'util';
import { MCBROWSER_BASE, McBrowserRequestError } from '@/lib/mcbrowser';
import {
    MAX_ARCHIVE_BLOB_FALLBACK_BYTES,
    classifyBatchError,
    copyMcBrowserEntry,
    createMcBrowserFile,
    createMcBrowserShare,
    deleteMcBrowserRecursive,
    downloadMcBrowserArchive,
    fetchMcBrowserContent,
    fetchMcBrowserFileInfo,
    fetchMcBrowserPolicy,
    fetchMcBrowserPreferences,
    fetchMcBrowserUsage,
    listMcBrowserShares,
    resolveBatchDestinationPath,
    revokeMcBrowserShare,
    saveMcBrowserContent,
    searchMcBrowserEntries,
    updateMcBrowserPreferences,
} from '@/lib/mcbrowser-workspace';

function createReadableStreamFromChunks(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
    let idx = 0;
    return {
        getReader() {
            return {
                async read() {
                    if (idx >= chunks.length) {
                        return { done: true, value: undefined };
                    }
                    const value = chunks[idx++];
                    return { done: false, value };
                },
                async cancel() {},
                releaseLock() {},
                closed: Promise.resolve(undefined),
            };
        },
        cancel: async () => {},
    } as unknown as ReadableStream<Uint8Array>;
}

describe('mcbrowser-workspace API contracts', () => {
    it('omits checksums for directory metadata while preserving alias request paths', async () => {
        const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ entry: { name: 'dir alias', path: 'dir alias', kind: 'directory', size: 0, modified: null }, checksums: {}, num_files: 2, num_dirs: 1 }),
        } as Response);
        const info = await fetchMcBrowserFileInfo('dir alias', null);
        expect(info.num_files).toBe(2);
        expect(String(fetchMock.mock.calls[0][0])).toContain('/info?path=dir%20alias');
        expect(String(fetchMock.mock.calls[0][0])).not.toContain('checksum=');
    });

    beforeAll(() => {
        Object.assign(globalThis, { TextEncoder, TextDecoder });
        if (typeof globalThis.Headers === 'undefined') {
            class MockHeaders {
                private map = new Map<string, string>();
                constructor(init?: HeadersInit) {
                    if (init instanceof MockHeaders) {
                        init.forEach((v, k) => this.set(k, v));
                    } else if (Array.isArray(init)) {
                        for (const [k, v] of init) this.set(k, v);
                    } else if (init && typeof init === 'object') {
                        for (const [k, v] of Object.entries(init)) this.set(k, v);
                    }
                }
                set(key: string, value: string) {
                    this.map.set(key.toLowerCase(), String(value));
                }
                get(key: string): string | null {
                    return this.map.get(key.toLowerCase()) ?? null;
                }
                has(key: string): boolean {
                    return this.map.has(key.toLowerCase());
                }
                forEach(cb: (value: string, key: string) => void) {
                    this.map.forEach((v, k) => cb(v, k));
                }
            }
            Object.defineProperty(globalThis, 'Headers', {
                writable: true,
                configurable: true,
                value: MockHeaders,
            });
        }
        if (typeof globalThis.Request === 'undefined') {
            class MockRequest {
                public url: string;
                public method: string;
                public headers: Headers;
                constructor(input: string | URL, init?: RequestInit) {
                    this.url = String(input);
                    this.method = init?.method ?? 'GET';
                    this.headers = new Headers(init?.headers);
                }
            }
            Object.defineProperty(globalThis, 'Request', {
                writable: true,
                configurable: true,
                value: MockRequest,
            });
        }
    });

    beforeEach(() => {
        document.cookie = 'csrf_token=csrf-workspace-999; path=/';
        if (typeof global.fetch !== 'function') {
            Object.defineProperty(global, 'fetch', {
                writable: true,
                configurable: true,
                value: async () => {
                    throw new Error('Unmocked fetch call');
                },
            });
        }
    });

    afterEach(() => {
        jest.restoreAllMocks();
        document.cookie = 'csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
    });

    it('calls GET /search with encoded path, query, and type parameters', async () => {
        const payload = {
            entries: [
                {
                    name: 'server.properties',
                    path: 'configs/sub/server.properties',
                    kind: 'file' as const,
                    size: 512,
                    modified: '2026-11-01T10:00:00Z',
                },
            ],
            truncated: true,
        };
        const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
            ok: true,
            status: 200,
            json: async () => payload,
        } as Response);

        const res = await searchMcBrowserEntries({
            path: 'configs/sub',
            q: 'server #1',
            type: 'file',
        });

        expect(res).toEqual(payload);
        const [calledUrl, calledInit] = fetchMock.mock.calls[0];
        expect(String(calledUrl)).toBe(
            `${MCBROWSER_BASE}/search?path=configs%2Fsub&q=server%20%231&type=file`
        );
        expect(calledInit?.method).toBe('GET');
        expect(calledInit?.credentials).toBe('include');
    });

    it('calls POST /copy and POST /delete-recursive with normalized paths and CSRF token', async () => {
        const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
            ok: true,
            status: 200,
            json: async () => ({ success: true }),
        } as Response);

        await copyMcBrowserEntry('configs/a.txt', 'backups/a.txt');
        expect(fetchMock).toHaveBeenLastCalledWith(
            `${MCBROWSER_BASE}/copy`,
            expect.objectContaining({
                method: 'POST',
                body: JSON.stringify({ from: 'configs/a.txt', to: 'backups/a.txt' }),
            })
        );

        await deleteMcBrowserRecursive('backups/old-folder/');
        expect(fetchMock).toHaveBeenLastCalledWith(
            `${MCBROWSER_BASE}/delete-recursive`,
            expect.objectContaining({
                method: 'POST',
                body: JSON.stringify({ path: 'backups/old-folder' }),
            })
        );
    });

    it('supports optional conflict policy (error | overwrite | keep-both and override | rename aliases), AbortSignal, and returns allocated destination on POST /copy', async () => {
        const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async (_url, init) => {
            const parsed = JSON.parse(String(init?.body ?? '{}'));
            const allocatedTo =
                parsed.conflict === 'keep-both' ? 'backups/a(1).txt' : parsed.to;
            return {
                ok: true,
                status: 200,
                json: async () => ({
                    success: true,
                    path: allocatedTo,
                    from: parsed.from,
                    to: allocatedTo,
                }),
            } as Response;
        });

        const controller = new AbortController();
        const keepBoth = await copyMcBrowserEntry(
            'configs/a.txt',
            'backups/a.txt',
            'keep-both',
            controller.signal
        );
        expect(keepBoth).toEqual({
            success: true,
            path: 'backups/a(1).txt',
            from: 'configs/a.txt',
            to: 'backups/a(1).txt',
        });
        expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
            from: 'configs/a.txt',
            to: 'backups/a.txt',
            conflict: 'keep-both',
        });
        expect(fetchMock.mock.calls[0][1]?.signal).toBe(controller.signal);

        await copyMcBrowserEntry('configs/a.txt', 'backups/a.txt', 'override');
        expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual({
            from: 'configs/a.txt',
            to: 'backups/a.txt',
            conflict: 'overwrite',
        });

        await copyMcBrowserEntry('configs/a.txt', 'backups/a.txt', {
            conflict: 'rename',
            signal: controller.signal,
        });
        expect(JSON.parse(String(fetchMock.mock.calls[2][1]?.body))).toEqual({
            from: 'configs/a.txt',
            to: 'backups/a.txt',
            conflict: 'keep-both',
        });
        expect(fetchMock.mock.calls[2][1]?.signal).toBe(controller.signal);

        await copyMcBrowserEntry('configs/a.txt', 'backups/a.txt', 'error');
        expect(JSON.parse(String(fetchMock.mock.calls[3][1]?.body))).toEqual({
            from: 'configs/a.txt',
            to: 'backups/a.txt',
            conflict: 'error',
        });

        await copyMcBrowserEntry('configs/a.txt', 'backups/a.txt', controller.signal);
        expect(JSON.parse(String(fetchMock.mock.calls[4][1]?.body))).toEqual({
            from: 'configs/a.txt',
            to: 'backups/a.txt',
        });
        expect(fetchMock.mock.calls[4][1]?.signal).toBe(controller.signal);
    });

    it('calls GET /content, PUT /content with optimistic etag, and POST /file', async () => {
        const fetchMock = jest
            .spyOn(global, 'fetch')
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => ({
                    path: 'configs/motd.txt',
                    content: 'hello',
                    etag: 'etag-v1',
                }),
            } as Response)
            .mockResolvedValueOnce({
                ok: true,
                status: 200,
                json: async () => ({
                    success: true,
                    etag: 'etag-v2',
                }),
            } as Response)
            .mockResolvedValueOnce({
                ok: true,
                status: 201,
                json: async () => ({ success: true }),
            } as Response);

        const loaded = await fetchMcBrowserContent('configs/motd.txt');
        expect(loaded).toEqual({
            path: 'configs/motd.txt',
            content: 'hello',
            etag: 'etag-v1',
        });
        expect(fetchMock.mock.calls[0][0]).toBe(
            `${MCBROWSER_BASE}/content?path=configs%2Fmotd.txt`
        );

        const saved = await saveMcBrowserContent('configs/motd.txt', 'updated', 'etag-v1');
        expect(saved).toEqual({ success: true, etag: 'etag-v2' });
        expect(fetchMock.mock.calls[1][0]).toBe(
            `${MCBROWSER_BASE}/content?path=configs%2Fmotd.txt`
        );
        expect(fetchMock.mock.calls[1][1]?.method).toBe('PUT');
        expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual({
            content: 'updated',
            etag: 'etag-v1',
        });

        await createMcBrowserFile('configs/new.yml', 'port: 25565');
        expect(fetchMock.mock.calls[2][0]).toBe(`${MCBROWSER_BASE}/file`);
        expect(JSON.parse(String(fetchMock.mock.calls[2][1]?.body))).toEqual({
            path: 'configs/new.yml',
            content: 'port: 25565',
        });
    });

    it('calls GET /info with checksum algorithm and manages shares, policy, preferences, and usage', async () => {
        const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async (input, init) => {
            const url = String(input);
            if (url.includes('/info?')) {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        entry: {
                            name: 'ops.json',
                            path: 'ops.json',
                            kind: 'file',
                            size: 16,
                            modified: '2026-11-01T00:00:00Z',
                        },
                        checksums: { sha512: 'deadbeef512' },
                    }),
                } as Response;
            }
            if (url.endsWith('/shares') && init?.method === 'GET') {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({ shares: [] }),
                } as Response;
            }
            if (url.endsWith('/shares') && init?.method === 'POST') {
                return {
                    ok: true,
                    status: 201,
                    json: async () => ({
                        share: {
                            id: 'sh-1',
                            path: 'ops.json',
                            expires_at: '2026-12-01T00:00:00Z',
                            allow_download: true,
                            created_at: '2026-11-01T00:00:00Z',
                            url: 'https://example.test/s/sh-1',
                        },
                    }),
                } as Response;
            }
            if (url.includes('/shares/sh-1') && init?.method === 'DELETE') {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({ success: true }),
                } as Response;
            }
            if (url.endsWith('/policy')) {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        permissions: {
                            read: true,
                            create: true,
                            rename: false,
                            modify: true,
                            delete: false,
                            share: true,
                            download: true,
                        },
                        rules: [{ id: 'r1' }],
                        scope: 'My files',
                    }),
                } as Response;
            }
            if (url.endsWith('/preferences')) {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        view: 'grid',
                        sort: 'size',
                        direction: 'desc',
                        show_hidden: true,
                        single_click: true,
                        locale: 'en-US',
                    }),
                } as Response;
            }
            if (url.endsWith('/usage')) {
                return {
                    ok: true,
                    status: 200,
                    json: async () => ({
                        used_bytes: 1024,
                        quota_bytes: 4096,
                        status: 'ok',
                    }),
                } as Response;
            }
            throw new Error(`Unexpected URL: ${url}`);
        });

        const info = await fetchMcBrowserFileInfo('ops.json', 'sha512');
        expect(info.checksums.sha512).toBe('deadbeef512');

        const shares = await listMcBrowserShares();
        expect(shares.shares).toEqual([]);

        const created = await createMcBrowserShare({
            path: 'ops.json',
            password: 'secret',
            expires_at: '2026-12-01T00:00:00Z',
            allow_download: true,
        });
        expect(created.share.id).toBe('sh-1');

        await revokeMcBrowserShare('sh-1');

        const policy = await fetchMcBrowserPolicy();
        expect(policy.permissions.delete).toBe(false);

        const prefs = await fetchMcBrowserPreferences();
        expect(prefs.view).toBe('grid');
        expect(prefs.natural_sort).toBe(true);
        expect(prefs.redirect_after_copy_move).toBe(false);
        expect(prefs.date_format).toBe(false);
        expect(prefs.editor_theme).toBe('chrome');

        const updatedPrefs = await updateMcBrowserPreferences({
            ...prefs,
            view: 'mosaic gallery',
            natural_sort: false,
            redirect_after_copy_move: true,
            date_format: true,
            editor_theme: 'monokai',
        });
        expect(updatedPrefs.show_hidden).toBe(true);

        const usage = await fetchMcBrowserUsage();
        expect(usage.used_bytes).toBe(1024);
        expect(fetchMock).toHaveBeenCalled();
    });

    it('uses a short-lived ticket and native navigation without reading archive bytes', async () => {
        const ticketUrl = `${MCBROWSER_BASE}/archive/test-ticket`;
        const navigation = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
            expect(this.getAttribute('href')).toBe(ticketUrl);
            expect(this.download).toBe('bundle.zip');
        });
        const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
            ok: true,
            status: 201,
            json: async () => ({ url: ticketUrl, filename: 'bundle.zip' }),
        } as Response);
        await expect(downloadMcBrowserArchive(['folder/a.txt'])).resolves.toEqual({
            filename: 'bundle.zip', bytesWritten: 0, method: 'browser-navigation',
        });
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(String(fetchMock.mock.calls[0][0])).toBe(`${MCBROWSER_BASE}/archive-ticket`);
        expect(navigation).toHaveBeenCalledTimes(1);
    });

    it('rejects foreign-origin archive ticket destinations before browser navigation', async () => {
        const navigation = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
        jest.spyOn(global, 'fetch').mockResolvedValue({
            ok: true, status: 201,
            json: async () => ({ url: 'https://untrusted.invalid/archive', filename: 'bundle.zip' }),
        } as Response);
        await expect(downloadMcBrowserArchive(['folder/a.txt'])).rejects.toMatchObject({ code: 'INVALID_DOWNLOAD_URL' });
        expect(navigation).not.toHaveBeenCalled();
    });

    it('streams POST /archive directly to File System Access writable when available', async () => {
        const writtenChunks: Uint8Array[] = [];
        let closed = false;
        const mockPicker = jest.fn(async () => ({
            createWritable: async () => ({
                write: async (chunk: Uint8Array) => {
                    writtenChunks.push(chunk);
                },
                close: async () => {
                    closed = true;
                },
            }),
        }));

        const chunk1 = new Uint8Array([1, 2, 3]);
        const chunk2 = new Uint8Array([4, 5, 6, 7]);
        jest.spyOn(global, 'fetch').mockResolvedValue({
            ok: true,
            status: 200,
            headers: new Headers({
                'Content-Disposition': 'attachment; filename="bundle.tar.gz"',
            }),
            body: createReadableStreamFromChunks([chunk1, chunk2]),
        } as unknown as Response);

        const res = await downloadMcBrowserArchive(['configs/a.txt', 'mods/b.jar'], 'tar.gz', {
            saveFilePicker: mockPicker,
        });

        expect(res).toEqual({
            filename: 'bundle.tar.gz',
            bytesWritten: 7,
            method: 'filesystem-access',
        });
        expect(closed).toBe(true);
        expect(writtenChunks).toHaveLength(2);
    });

    it('rejects archive download when bounded blob fallback cap (128 MiB) is exceeded', async () => {
        const chunk = new Uint8Array(64);
        jest.spyOn(global, 'fetch').mockResolvedValue({
            ok: true,
            status: 200,
            headers: new Headers({
                'Content-Disposition': 'attachment; filename="too-big.zip"',
            }),
            body: createReadableStreamFromChunks([chunk, chunk]),
        } as unknown as Response);

        await expect(
            downloadMcBrowserArchive(['configs/a.txt'], 'zip', {
                maxBlobBytes: 100, // 100-byte test cap
            })
        ).rejects.toMatchObject({
            name: 'McBrowserRequestError',
            status: 413,
            code: 'ARCHIVE_TOO_LARGE_FOR_BLOB_FALLBACK',
        });
        expect(MAX_ARCHIVE_BLOB_FALLBACK_BYTES).toBe(128 * 1024 * 1024);
    });

    it('validates batch destination resolution, preserves directory whitespace, and classifies conflicts vs forbidden errors', () => {
        expect(resolveBatchDestinationPath('configs/a.txt', 'backups/2026')).toBe(
            'backups/2026/a.txt'
        );
        expect(resolveBatchDestinationPath('configs/a.txt', '  spaced folder  ')).toBe(
            '  spaced folder  /a.txt'
        );
        expect(resolveBatchDestinationPath('configs/a.txt', 'backups/ trailing ')).toBe(
            'backups/ trailing /a.txt'
        );
        expect(() => resolveBatchDestinationPath('configs/a.txt', 'configs')).toThrow(
            McBrowserRequestError
        );
        expect(resolveBatchDestinationPath('configs/a.txt', 'configs', 'keep-both')).toBe('configs/a.txt');
        expect(() => resolveBatchDestinationPath('configs/a.txt', 'configs', 'overwrite')).toThrow();
        expect(() => resolveBatchDestinationPath('configs', 'configs/sub', 'keep-both')).toThrow();
        expect(() => resolveBatchDestinationPath('configs', 'configs/sub')).toThrow(
            McBrowserRequestError
        );

        expect(
            classifyBatchError(new McBrowserRequestError(409, 'CONFLICT', 'Target exists'))
        ).toEqual({
            status: 'conflict',
            code: 'CONFLICT',
            message: 'Target exists',
        });
        expect(
            classifyBatchError(new McBrowserRequestError(403, 'FORBIDDEN', 'Denied by policy'))
        ).toEqual({
            status: 'forbidden',
            code: 'FORBIDDEN',
            message: 'Denied by policy',
        });
    });
});
