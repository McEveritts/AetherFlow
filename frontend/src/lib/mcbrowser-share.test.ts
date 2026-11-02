import {
    PUBLIC_SHARE_API_BASE,
    PublicShareError,
    validatePublicShareToken,
    normalizeShareSubPath,
    assertNoSecretQueryParams,
    sanitizePublicShareMetadata,
    isShareExpiredAt,
    buildShareBreadcrumbs,
    getParentSharePath,
    fetchPublicShareMetadata,
    unlockPublicShare,
    listPublicShareEntries,
    buildPublicShareDownloadUrl,
    downloadPublicShareFile,
    parseShareContentDispositionFilename,
    formatShareBytes,
} from '@/lib/mcbrowser-share';

const VALID_TOKEN = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcd';

describe('mcbrowser-share library', () => {
    beforeEach(() => {
        jest.restoreAllMocks();
        window.localStorage.clear();
    });

    describe('validatePublicShareToken', () => {
        it('accepts valid base64url tokens and trims surrounding whitespace', () => {
            expect(validatePublicShareToken(`  ${VALID_TOKEN}  `)).toBe(VALID_TOKEN);
        });

        it.each([
            ['empty', ''],
            ['too short (<16)', 'shorttoken12345'],
            ['too long (>256)', 'a'.repeat(257)],
            ['contains slash', 'AbCdEfGhIjKlMnOp/QrStUvWxYz'],
            ['contains query char', 'AbCdEfGhIjKlMnOp?password=1'],
            ['contains control char', 'AbCdEfGhIjKlMnOp\nQrStUvWxYz'],
        ])('rejects invalid token (%s)', (_label, badToken) => {
            expect(() => validatePublicShareToken(badToken)).toThrow(PublicShareError);
        });
    });

    describe('normalizeShareSubPath', () => {
        it('normalizes valid relative sub-paths and empty root path', () => {
            expect(normalizeShareSubPath('')).toBe('');
            expect(normalizeShareSubPath(null)).toBe('');
            expect(normalizeShareSubPath('docs//guides/readme.txt')).toBe('docs/guides/readme.txt');
        });

        it.each([
            ['leading slash', '/etc/passwd'],
            ['dot-dot traversal', 'docs/../secret.txt'],
            ['single dot segment', './secret.txt'],
            ['backslash', 'docs\\secret.txt'],
            ['nul byte', 'docs/bad\0file.txt'],
            ['temp upload prefix', 'docs/.af-upload-tmp.123'],
        ])('rejects unsafe path (%s)', (_label, unsafePath) => {
            expect(() => normalizeShareSubPath(unsafePath)).toThrow(PublicShareError);
        });
    });

    describe('assertNoSecretQueryParams', () => {
        it('allows safe query parameters like path', () => {
            expect(() =>
                assertNoSecretQueryParams(
                    `${PUBLIC_SHARE_API_BASE}/${VALID_TOKEN}/entries?path=sub%2Ffile.txt`
                )
            ).not.toThrow();
        });

        it.each(['password', 'access_token', 'share_token', 'PASSWORD'])(
            'rejects %s in query string',
            (param) => {
                expect(() =>
                    assertNoSecretQueryParams(
                        `${PUBLIC_SHARE_API_BASE}/${VALID_TOKEN}/entries?path=a&${param}=secret`
                    )
                ).toThrow(PublicShareError);
            }
        );
    });

    describe('sanitizePublicShareMetadata & isShareExpiredAt', () => {
        it('keeps only minimal public metadata fields and strips internal fields', () => {
            const raw = {
                id: 'internal-uuid',
                owner_user_id: 42,
                username: 'admin',
                target_path: 'private/vault/report.pdf',
                token_hash: 'deadbeef',
                password_hash: '$2b$10$secret',
                name: '  report.pdf  ',
                is_directory: false,
                password_required: true,
                allow_download: false,
                expires_at: '2030-01-01T00:00:00Z',
            };

            const sanitized = sanitizePublicShareMetadata(raw);
            expect(sanitized).toEqual({
                name: 'report.pdf',
                is_directory: false,
                password_required: true,
                allow_download: false,
                expires_at: '2030-01-01T00:00:00Z',
            });
            expect(Object.keys(sanitized).sort()).toEqual([
                'allow_download',
                'expires_at',
                'is_directory',
                'name',
                'password_required',
            ]);
        });

        it('evaluates expiry accurately and fails closed on malformed timestamps', () => {
            const now = Date.parse('2026-11-01T12:00:00Z');
            expect(isShareExpiredAt(null, now)).toBe(false);
            expect(isShareExpiredAt('2026-11-01T13:00:00Z', now)).toBe(false);
            expect(isShareExpiredAt('2026-11-01T11:59:59Z', now)).toBe(true);
            expect(isShareExpiredAt('not-a-valid-date', now)).toBe(true);
        });
    });

    describe('breadcrumbs and parent path helpers', () => {
        it('builds breadcrumbs strictly rooted at the shared folder name', () => {
            expect(buildShareBreadcrumbs('Project Vault', 'docs/specs')).toEqual([
                { label: 'Project Vault', path: '' },
                { label: 'docs', path: 'docs' },
                { label: 'specs', path: 'docs/specs' },
            ]);
            expect(getParentSharePath('docs/specs')).toBe('docs');
            expect(getParentSharePath('docs')).toBe('');
            expect(getParentSharePath('')).toBe('');
        });
    });

    describe('plain fetch transport & session isolation on 401', () => {
        it('uses plain fetch with credentials: include and never triggers af:session-expired on 401', async () => {
            const sessionExpiredSpy = jest.fn();
            window.addEventListener('af:session-expired', sessionExpiredSpy);

            const fetchMock = jest.fn().mockResolvedValue(
                new Response(
                    JSON.stringify({
                        code: 'SHARE_PASSWORD_INVALID',
                        message: 'Invalid share password',
                    }),
                    { status: 401, headers: { 'Content-Type': 'application/json' } }
                )
            );
            global.fetch = fetchMock as unknown as typeof fetch;

            await expect(unlockPublicShare(VALID_TOKEN, 'wrong-password')).rejects.toMatchObject({
                status: 401,
                code: 'SHARE_PASSWORD_INVALID',
                isPasswordInvalid: true,
                isUnauthorized: true,
            });

            expect(fetchMock).toHaveBeenCalledTimes(1);
            const [calledUrl, calledInit] = fetchMock.mock.calls[0];
            expect(calledUrl).toBe(`${PUBLIC_SHARE_API_BASE}/${VALID_TOKEN}/unlock`);
            expect(calledInit.credentials).toBe('include');
            expect(calledInit.method).toBe('POST');
            expect(calledInit.body).toBe(JSON.stringify({ password: 'wrong-password' }));

            // Must NEVER call /api/v1/auth/refresh or broadcast logout sync
            expect(window.localStorage.getItem('af_logout_sync')).toBeNull();
            expect(sessionExpiredSpy).not.toHaveBeenCalled();

            window.removeEventListener('af:session-expired', sessionExpiredSpy);
        });

        it('fetches metadata, unlocks, lists scoped entries (filtering non-regular entries), and downloads', async () => {
            const fetchMock = jest
                .fn()
                // 1. Metadata
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            name: 'shared-folder',
                            is_directory: true,
                            password_required: true,
                            allow_download: true,
                            expires_at: null,
                            owner_user_id: 99,
                        }),
                        { status: 200, headers: { 'Content-Type': 'application/json' } }
                    )
                )
                // 2. Unlock
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            success: true,
                            access_token: 'scoped-unlock-token-123',
                            expires_in: 3600,
                        }),
                        { status: 200, headers: { 'Content-Type': 'application/json' } }
                    )
                )
                // 3. Entries
                .mockResolvedValueOnce(
                    new Response(
                        JSON.stringify({
                            path: 'sub',
                            entries: [
                                {
                                    name: 'notes.txt',
                                    path: 'sub/notes.txt',
                                    kind: 'file',
                                    size: 1536,
                                    modified: '2026-11-01T10:00:00Z',
                                },
                                {
                                    name: 'bad-symlink',
                                    path: 'sub/bad-symlink',
                                    kind: 'symlink',
                                    size: 0,
                                    modified: null,
                                },
                            ],
                        }),
                        { status: 200, headers: { 'Content-Type': 'application/json' } }
                    )
                )
                // 4. Download
                .mockResolvedValueOnce(
                    new Response('file-payload-bytes', {
                        status: 200,
                        headers: {
                            'Content-Type': 'application/octet-stream',
                            'Content-Disposition': "attachment; filename*=UTF-8''notes.txt",
                        },
                    })
                );

            global.fetch = fetchMock as unknown as typeof fetch;

            const createObjectUrlMock = jest.fn(() => 'blob:mock-share-dl');
            const revokeObjectUrlMock = jest.fn();
            Object.defineProperty(window.URL, 'createObjectURL', {
                writable: true,
                value: createObjectUrlMock,
            });
            Object.defineProperty(window.URL, 'revokeObjectURL', {
                writable: true,
                value: revokeObjectUrlMock,
            });
            const anchorClickSpy = jest
                .spyOn(HTMLAnchorElement.prototype, 'click')
                .mockImplementation(() => {});

            const meta = await fetchPublicShareMetadata(VALID_TOKEN);
            expect(meta).toEqual({
                name: 'shared-folder',
                is_directory: true,
                password_required: true,
                allow_download: true,
                expires_at: null,
            });

            const unlockRes = await unlockPublicShare(VALID_TOKEN, 'correct-horse-battery-staple');
            expect(unlockRes.access_token).toBe('scoped-unlock-token-123');

            const entriesRes = await listPublicShareEntries(VALID_TOKEN, 'sub', {
                accessToken: unlockRes.access_token,
            });
            expect(entriesRes.path).toBe('sub');
            expect(entriesRes.entries).toEqual([
                {
                    name: 'notes.txt',
                    path: 'sub/notes.txt',
                    kind: 'file',
                    size: 1536,
                    modified: '2026-11-01T10:00:00Z',
                },
            ]);

            const entriesHeaders = fetchMock.mock.calls[2][1].headers as Headers;
            expect(entriesHeaders.get('X-McBrowser-Share-Token')).toBe('scoped-unlock-token-123');
            expect(fetchMock.mock.calls[2][1].credentials).toBe('include');

            const dlRes = await downloadPublicShareFile(VALID_TOKEN, 'sub/notes.txt', {
                accessToken: unlockRes.access_token,
            });
            expect(dlRes.filename).toBe('notes.txt');
            expect(fetchMock.mock.calls[3][0]).toBe(
                buildPublicShareDownloadUrl(VALID_TOKEN, 'sub/notes.txt')
            );
            expect(fetchMock.mock.calls[3][1].credentials).toBe('include');
            expect(fetchMock.mock.calls[3][1].method).toBe('HEAD');
            expect((fetchMock.mock.calls[3][1].headers as Headers).has('X-McBrowser-Share-Token')).toBe(false);
            expect(createObjectUrlMock).not.toHaveBeenCalled();
            expect(revokeObjectUrlMock).not.toHaveBeenCalled();
            expect(anchorClickSpy).toHaveBeenCalledTimes(1);
        });
    });

    describe('utilities', () => {
        it('parses Content-Disposition filenames and strips path separators', () => {
            expect(
                parseShareContentDispositionFilename("attachment; filename*=UTF-8''my%20report.pdf")
            ).toBe('my report.pdf');
            expect(
                parseShareContentDispositionFilename('attachment; filename="../../evil.sh"')
            ).toBe('evil.sh');
        });

        it('formats byte sizes cleanly', () => {
            expect(formatShareBytes(0)).toBe('0 B');
            expect(formatShareBytes(512)).toBe('512 B');
            expect(formatShareBytes(2048)).toBe('2 KiB');
        });
    });
});
