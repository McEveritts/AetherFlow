import {
    MCBROWSER_BASE,
    DEFAULT_MAX_UPLOAD_BYTES,
    McBrowserRequestError,
    getMcBrowserEntryTargetKind,
    normalizeRelativePath,
    joinRelativePath,
    validateEntryName,
    buildBreadcrumbs,
    extractMcBrowserError,
    listMcBrowserEntries,
    createMcBrowserDirectory,
    ensureMcBrowserDirectory,
    renameMcBrowserEntry,
    deleteMcBrowserEntry,
    uploadMcBrowserFile,
    downloadMcBrowserFile,
    fetchMcBrowserPreview,
    parseFilenameFromContentDisposition,
} from '@/lib/mcbrowser';

describe('mcbrowser API contract', () => {
    it('only treats explicitly resolved internal file and directory links as openable', () => {
        const link = { name: 'alias', path: 'alias', kind: 'symlink' as const, size: 0, modified: null };
        expect(getMcBrowserEntryTargetKind(link)).toBe('symlink');
        expect(getMcBrowserEntryTargetKind({ ...link, target_kind: 'file' })).toBe('file');
        expect(getMcBrowserEntryTargetKind({ ...link, target_kind: 'directory' })).toBe('directory');
        expect(getMcBrowserEntryTargetKind({ ...link, kind: 'other', target_kind: 'file' })).toBe('other');
    });
    beforeAll(() => {
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

    describe('listMcBrowserEntries (/api/v1/auth/mcbrowser/entries)', () => {
        it.each([
            ['spaces', 'mods/my folder/sub dir', 'mods%2Fmy%20folder%2Fsub%20dir'],
            ['hash #', 'configs/server#1/ops#backup.json', 'configs%2Fserver%231%2Fops%23backup.json'],
            ['plus +', 'plugins/world+edit+beta/config.yml', 'plugins%2Fworld%2Bedit%2Bbeta%2Fconfig.yml'],
            [
                'Unicode',
                'worlds/새로운世界/データ/level.dat',
                'worlds%2F%EC%83%88%EB%A1%9C%EC%9A%B4%E4%B8%96%E7%95%8C%2F%E3%83%87%E3%83%BC%E3%82%BF%2Flevel.dat',
            ],
        ])(
            'properly encodes relative path query with %s via apiFetch without leaking tokens in URL',
            async (_label, relPath, expectedEncoded) => {
                const payload = {
                    path: relPath,
                    max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
                    entries: [
                        {
                            name: 'server.properties',
                            path: `${relPath}/server.properties`,
                            kind: 'file' as const,
                            size: 1024,
                            modified: '2026-11-01T12:00:00Z',
                        },
                    ],
                };
                const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
                    ok: true,
                    status: 200,
                    json: async () => payload,
                } as Response);

                const result = await listMcBrowserEntries(relPath);
                expect(result).toEqual(payload);

                expect(fetchMock).toHaveBeenCalledTimes(1);
                const [calledUrl, calledInit] = fetchMock.mock.calls[0];
                const urlStr = String(calledUrl);

                expect(urlStr).toBe(`${MCBROWSER_BASE}/entries?path=${expectedEncoded}`);
                expect(urlStr).not.toMatch(/token=|jwt=|access_token=|auth=/i);
                expect(calledInit).toEqual(
                    expect.objectContaining({
                        method: 'GET',
                        credentials: 'include',
                        headers: expect.any(Headers),
                    })
                );

                const headers = calledInit?.headers as Headers;
                expect(headers.get('X-API-Version')).toBe('v1');
                expect(headers.get('Accept')).toBe('application/vnd.aetherflow.v1+json');
                expect(headers.get('X-Requested-With')).toBe('XMLHttpRequest');
                expect(headers.get('Cache-Control')).toBe('no-store');
            }
        );

        it('preserves whitespace in names and rejects traversal', async () => {
            const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
                ok: true,
                status: 200,
                json: async () => ({ path: 'logs/latest #1+2.log', entries: [], max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES }),
            } as Response);

            await listMcBrowserEntries('logs/ latest #1+2.log /');
            const [calledUrl] = fetchMock.mock.calls[0];
            expect(String(calledUrl)).toBe(
                '/api/v1/auth/mcbrowser/entries?path=logs%2F%20latest%20%231%2B2.log%20'
            );

            await expect(listMcBrowserEntries('logs/../secrets')).rejects.toMatchObject({
                name: 'McBrowserRequestError',
                status: 400,
                code: 'INVALID_PATH',
            });
        });
    });

    describe('createMcBrowserDirectory (/api/v1/auth/mcbrowser/directory)', () => {
        it('sends POST JSON { path } with credentials and CSRF token delegated to shared apiFetch helper', async () => {
            document.cookie = 'csrf_token=csrf-mkdir-123; path=/';
            const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
                ok: true,
                status: 201,
                json: async () => ({ success: true }),
            } as Response);

            const res = await createMcBrowserDirectory('worlds/survival #1+beta/');
            expect(res).toEqual({ success: true });

            expect(fetchMock).toHaveBeenCalledTimes(1);
            const [calledUrl, calledInit] = fetchMock.mock.calls[0];
            expect(String(calledUrl)).toBe('/api/v1/auth/mcbrowser/directory');
            expect(String(calledUrl)).not.toMatch(/token=|jwt=/i);
            expect(calledInit?.method?.toUpperCase()).toBe('POST');
            expect(calledInit?.credentials).toBe('include');

            const headers = new Headers(calledInit?.headers);
            expect(headers.get('X-CSRF-Token')).toBe('csrf-mkdir-123');
            expect(headers.get('Content-Type')).toBe('application/json');
            expect(JSON.parse(String(calledInit?.body))).toEqual({
                path: 'worlds/survival #1+beta',
            });
        });

        it('rejects empty root path for directory creation before network call', async () => {
            const fetchMock = jest.spyOn(global, 'fetch');
            await expect(createMcBrowserDirectory('')).rejects.toMatchObject({
                status: 400,
                code: 'INVALID_PATH',
            });
            expect(fetchMock).not.toHaveBeenCalled();
        });
    });

    it('prepares nested upload directories with explicit parent creation, CSRF, and cancellation', async () => {
        document.cookie = 'csrf_token=csrf-folder-upload; path=/';
        const controller = new AbortController();
        const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({ ok: true, status: 201, json: async () => ({ success: true }) } as Response);
        await ensureMcBrowserDirectory('albums/live', controller.signal);
        const [url, options] = fetchMock.mock.calls[0];
        expect(url).toBe('/api/v1/auth/mcbrowser/directory');
        expect(options?.method).toBe('POST');
        expect(options?.signal).toBe(controller.signal);
        expect(new Headers(options?.headers).get('X-CSRF-Token')).toBe('csrf-folder-upload');
        expect(JSON.parse(String(options?.body))).toEqual({ path: 'albums/live', parents: true });
    });

    it('rejects overlong UTF-8 names, deep paths, and combined upload paths before transport', () => {
        expect(validateEntryName('😀'.repeat(64))).not.toBeNull();
        expect(() => normalizeRelativePath(Array(65).fill('folder').join('/'))).toThrow(McBrowserRequestError);
        expect(() => normalizeRelativePath(Array(20).fill('a'.repeat(240)).join('/'))).toThrow(McBrowserRequestError);
        expect(() => joinRelativePath(Array(64).fill('folder').join('/'), 'file.txt')).toThrow(McBrowserRequestError);
    });

    describe('renameMcBrowserEntry (/api/v1/auth/mcbrowser/rename)', () => {
        it('sends POST JSON { from, to } with normalized relative paths and CSRF token', async () => {
            document.cookie = 'csrf_token=csrf-rename-456; path=/';
            const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
                ok: true,
                status: 200,
                json: async () => ({ success: true }),
            } as Response);

            const res = await renameMcBrowserEntry('mods/old+name.jar', 'mods/new #name 1.jar');
            expect(res).toEqual({ success: true });

            expect(fetchMock).toHaveBeenCalledTimes(1);
            const [calledUrl, calledInit] = fetchMock.mock.calls[0];
            expect(String(calledUrl)).toBe('/api/v1/auth/mcbrowser/rename');
            expect(String(calledUrl)).not.toMatch(/token=|jwt=/i);
            expect(calledInit?.method?.toUpperCase()).toBe('POST');
            expect(calledInit?.credentials).toBe('include');

            const headers = new Headers(calledInit?.headers);
            expect(headers.get('X-CSRF-Token')).toBe('csrf-rename-456');
            expect(headers.get('Content-Type')).toBe('application/json');
            expect(JSON.parse(String(calledInit?.body))).toEqual({
                from: 'mods/old+name.jar',
                to: 'mods/new #name 1.jar',
            });
        });

        it('supports optional conflict policy (error | overwrite | keep-both and override | rename aliases), AbortSignal, and returns allocated destination metadata', async () => {
            document.cookie = 'csrf_token=csrf-rename-conflict; path=/';
            const fetchMock = jest.spyOn(global, 'fetch').mockImplementation(async (_url, init) => {
                const parsed = JSON.parse(String(init?.body ?? '{}'));
                const allocatedTo =
                    parsed.conflict === 'keep-both' ? 'mods/target(1).jar' : parsed.to;
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
            const keepBothRes = await renameMcBrowserEntry(
                'mods/source.jar',
                'mods/target.jar',
                'keep-both',
                controller.signal
            );
            expect(keepBothRes).toEqual({
                success: true,
                path: 'mods/target(1).jar',
                from: 'mods/source.jar',
                to: 'mods/target(1).jar',
            });
            expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
                from: 'mods/source.jar',
                to: 'mods/target.jar',
                conflict: 'keep-both',
            });
            expect(fetchMock.mock.calls[0][1]?.signal).toBe(controller.signal);

            await renameMcBrowserEntry('mods/source.jar', 'mods/target.jar', 'override');
            expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual({
                from: 'mods/source.jar',
                to: 'mods/target.jar',
                conflict: 'overwrite',
            });

            await renameMcBrowserEntry('mods/source.jar', 'mods/target.jar', {
                conflict: 'rename',
                signal: controller.signal,
            });
            expect(JSON.parse(String(fetchMock.mock.calls[2][1]?.body))).toEqual({
                from: 'mods/source.jar',
                to: 'mods/target.jar',
                conflict: 'keep-both',
            });
            expect(fetchMock.mock.calls[2][1]?.signal).toBe(controller.signal);

            await renameMcBrowserEntry('mods/source.jar', 'mods/target.jar', 'error');
            expect(JSON.parse(String(fetchMock.mock.calls[3][1]?.body))).toEqual({
                from: 'mods/source.jar',
                to: 'mods/target.jar',
                conflict: 'error',
            });

            await renameMcBrowserEntry('mods/source.jar', 'mods/target.jar', controller.signal);
            expect(JSON.parse(String(fetchMock.mock.calls[4][1]?.body))).toEqual({
                from: 'mods/source.jar',
                to: 'mods/target.jar',
            });
            expect(fetchMock.mock.calls[4][1]?.signal).toBe(controller.signal);
        });
    });

    describe('deleteMcBrowserEntry (/api/v1/auth/mcbrowser/entry)', () => {
        it('sends DELETE request with URL-encoded relative path query and CSRF token', async () => {
            document.cookie = 'csrf_token=csrf-delete-789; path=/';
            const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
                ok: true,
                status: 200,
                json: async () => ({ success: true }),
            } as Response);

            const targetPath = 'backups/world #1+old/ワールド.tar.gz';
            const res = await deleteMcBrowserEntry(targetPath);
            expect(res).toEqual({ success: true });

            expect(fetchMock).toHaveBeenCalledTimes(1);
            const [calledUrl, calledInit] = fetchMock.mock.calls[0];
            const urlStr = String(calledUrl);
            expect(urlStr).toBe(
                `/api/v1/auth/mcbrowser/entry?path=${encodeURIComponent(targetPath)}`
            );
            expect(urlStr).not.toMatch(/token=|jwt=/i);
            expect(calledInit?.method?.toUpperCase()).toBe('DELETE');
            expect(calledInit?.credentials).toBe('include');

            const headers = new Headers(calledInit?.headers);
            expect(headers.get('X-CSRF-Token')).toBe('csrf-delete-789');
        });
    });

    describe('uploadMcBrowserFile (/api/v1/auth/mcbrowser/upload)', () => {
        it('uploads raw File body with encoded relative path query, no multipart FormData assumptions, and CSRF token', async () => {
            document.cookie = 'csrf_token=csrf-upload-321; path=/';
            const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
                ok: true,
                status: 201,
                json: async () => ({ success: true }),
            } as Response);

            const fileContent = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x01, 0x02]);
            const file = new File([fileContent], 'fabric-api+1.21 #2.jar', {
                type: 'application/java-archive',
            });
            const uploadPath = 'mods/fabric-api+1.21 #2.jar';

            const res = await uploadMcBrowserFile(uploadPath, file);
            expect(res).toEqual({ success: true });

            expect(fetchMock).toHaveBeenCalledTimes(1);
            const [calledUrl, calledInit] = fetchMock.mock.calls[0];
            const urlStr = String(calledUrl);

            expect(urlStr).toBe(
                `/api/v1/auth/mcbrowser/upload?path=${encodeURIComponent(uploadPath)}`
            );
            expect(urlStr).not.toMatch(/token=|jwt=/i);
            expect(['PUT', 'POST']).toContain(calledInit?.method?.toUpperCase());
            expect(calledInit?.credentials).toBe('include');
            expect(typeof FormData !== 'undefined' ? calledInit?.body instanceof FormData : false).toBe(false);
            expect(calledInit?.body).toBe(file);

            const headers = new Headers(calledInit?.headers);
            expect(headers.get('X-CSRF-Token')).toBe('csrf-upload-321');
            expect(headers.get('Content-Type')).toBe('application/java-archive');
            expect(headers.get('Content-Type') ?? '').not.toContain('multipart/form-data');
        });

        it('rejects files exceeding maxUploadBytes before sending request', async () => {
            const fetchMock = jest.spyOn(global, 'fetch');
            const bigBlob = new Blob([new Uint8Array(128)], { type: 'application/octet-stream' });

            await expect(uploadMcBrowserFile('mods/huge.jar', bigBlob, 64)).rejects.toMatchObject({
                status: 413,
                code: 'FILE_TOO_LARGE',
            });
            expect(fetchMock).not.toHaveBeenCalled();
        });
    });

    describe('downloadMcBrowserFile (/api/v1/auth/mcbrowser/download)', () => {
        it('checks download headers then streams using native browser navigation without buffering', async () => {
            jest.useFakeTimers();
            const createObjectURLMock = jest.fn(() => 'blob:http://localhost/mock-download-id');
            const revokeObjectURLMock = jest.fn();
            Object.defineProperty(window.URL, 'createObjectURL', {
                writable: true,
                value: createObjectURLMock,
            });
            Object.defineProperty(window.URL, 'revokeObjectURL', {
                writable: true,
                value: revokeObjectURLMock,
            });

            const clickSpy = jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

            const fakeBlob = new Blob(['motd=AetherFlow'], { type: 'text/plain' });
            const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
                ok: true,
                status: 200,
                headers: new Headers({
                    'Content-Disposition': "attachment; filename*=UTF-8''server%20%231%2Bmain.properties",
                }),
                blob: async () => fakeBlob,
            } as unknown as Response);

            const relPath = 'configs/server #1+main/テスト.properties';
            await downloadMcBrowserFile(relPath);

            expect(fetchMock).toHaveBeenCalledTimes(1);
            const [calledUrl, calledInit] = fetchMock.mock.calls[0];
            const urlStr = String(calledUrl);

            expect(urlStr).toBe(
                `/api/v1/auth/mcbrowser/download?path=${encodeURIComponent(relPath)}`
            );
            expect(urlStr).not.toMatch(/token=|jwt=|access_token=|session=/i);
            expect(calledInit?.method?.toUpperCase()).toBe('HEAD');
            expect(calledInit?.credentials).toBe('include');

            expect(createObjectURLMock).not.toHaveBeenCalled();
            expect(clickSpy).toHaveBeenCalledTimes(1);

            jest.advanceTimersByTime(300);
            expect(revokeObjectURLMock).not.toHaveBeenCalled();
            jest.useRealTimers();
        });

        it('surfaces structured backend { code, message } error when download response fails', async () => {
            jest.spyOn(global, 'fetch').mockResolvedValue({
                ok: false,
                status: 404,
                statusText: 'Not Found',
                json: async () => ({
                    code: 'NOT_FOUND',
                    message: 'Requested file does not exist',
                }),
            } as Response);

            await expect(downloadMcBrowserFile('logs/missing #file.log')).rejects.toMatchObject({
                name: 'McBrowserRequestError',
                code: 'NOT_FOUND',
                message: 'Requested file does not exist',
                status: 404,
            });
        });
    });

    describe('fetchMcBrowserPreview (/api/v1/auth/mcbrowser/preview)', () => {
        it('fetches preview JSON with encoded relative path query via apiFetch', async () => {
            const previewPayload = {
                path: 'config/server #1+main/server.properties',
                content: 'motd=AetherFlow Minecraft Server\nonline-mode=true\n',
                truncated: false,
            };
            const fetchMock = jest.spyOn(global, 'fetch').mockResolvedValue({
                ok: true,
                status: 200,
                json: async () => previewPayload,
            } as Response);

            const relPath = 'config/server #1+main/server.properties';
            const result = await fetchMcBrowserPreview(relPath);

            expect(result).toEqual(previewPayload);
            expect(fetchMock).toHaveBeenCalledTimes(1);
            const [calledUrl, calledInit] = fetchMock.mock.calls[0];
            const urlStr = String(calledUrl);

            expect(urlStr).toBe(
                `/api/v1/auth/mcbrowser/preview?path=${encodeURIComponent(relPath)}`
            );
            expect(urlStr).not.toMatch(/token=|jwt=/i);
            expect(calledInit?.credentials).toBe('include');
        });
    });

    describe('error handling ({ code, message }) and utility helpers', () => {
        it.each([
            ['listMcBrowserEntries', () => listMcBrowserEntries('forbidden/path'), 403, 'FORBIDDEN', 'Path escapes sandbox root'],
            ['createMcBrowserDirectory', () => createMcBrowserDirectory('existing/dir'), 409, 'CONFLICT', 'Directory already exists'],
            ['renameMcBrowserEntry', () => renameMcBrowserEntry('a.txt', 'b.txt'), 400, 'VALIDATION_ERROR', 'Renaming symlinks is not permitted'],
            ['deleteMcBrowserEntry', () => deleteMcBrowserEntry('missing.txt'), 404, 'NOT_FOUND', 'Target entry not found'],
            [
                'uploadMcBrowserFile',
                () => uploadMcBrowserFile('mods/dup.jar', new File(['data'], 'dup.jar')),
                409,
                'CONFLICT',
                'Destination file already exists',
            ],
            ['fetchMcBrowserPreview', () => fetchMcBrowserPreview('binary.dat'), 400, 'BAD_REQUEST', 'File cannot be previewed as text'],
        ])('surfaces backend { code, message } error for %s (%s %s)', async (_op, invoke, status, code, message) => {
            jest.spyOn(global, 'fetch').mockResolvedValue({
                ok: false,
                status,
                statusText: 'Error',
                json: async () => ({ code, message }),
            } as Response);

            await expect(invoke()).rejects.toMatchObject({
                name: 'McBrowserRequestError',
                code,
                message,
                status,
            });
        });

        it('formats structured errors via extractMcBrowserError and parses Content-Disposition filenames', () => {
            const err = new McBrowserRequestError(409, 'CONFLICT', 'Destination already exists');
            expect(extractMcBrowserError(err)).toBe('Destination already exists (CONFLICT)');

            expect(
                parseFilenameFromContentDisposition("attachment; filename*=UTF-8''world%20%231.tar.gz")
            ).toBe('world #1.tar.gz');
            expect(parseFilenameFromContentDisposition('attachment; filename="ops.json"')).toBe('ops.json');
            expect(normalizeRelativePath('mods/fabric//sodium/')).toBe('mods/fabric/sodium');
            expect(normalizeRelativePath(' configs / file.txt ')).toBe(' configs / file.txt ');
            expect(joinRelativePath(' configs ', ' file.txt ')).toBe(' configs / file.txt ');
            for (const invalid of ['/absolute', 'folder\\file', 'folder/./file', 'folder/../file', '.af-upload-tmp.secret', 'nul\0byte']) {
                expect(() => normalizeRelativePath(invalid)).toThrow(McBrowserRequestError);
            }
            expect(validateEntryName('.af-upload-tmp.secret')).not.toBeNull();
            expect(joinRelativePath('mods/fabric', 'lithium #1.jar')).toBe('mods/fabric/lithium #1.jar');
            expect(validateEntryName('bad/name')).not.toBeNull();
            expect(buildBreadcrumbs('worlds/survival/region')).toEqual([
                { label: 'My files', path: '' },
                { label: 'worlds', path: 'worlds' },
                { label: 'survival', path: 'worlds/survival' },
                { label: 'region', path: 'worlds/survival/region' },
            ]);
        });
    });
});
