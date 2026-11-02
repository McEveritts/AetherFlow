import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import PublicSharePage from '@/app/share/page';
import { PUBLIC_SHARE_API_BASE } from '@/lib/mcbrowser-share';

let mockTokenParam: string | null = null;

jest.mock('next/navigation', () => ({
    useSearchParams: () => ({
        get: (key: string) => (key === 'token' ? mockTokenParam : null),
    }),
}));

const VALID_TOKEN = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcd';

function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
}

describe('PublicSharePage (/share?token=...)', () => {
    beforeEach(() => {
        jest.restoreAllMocks();
        mockTokenParam = VALID_TOKEN;
        window.localStorage.clear();

        Object.defineProperty(window.URL, 'createObjectURL', {
            writable: true,
            value: jest.fn(() => 'blob:mock-public-share-url'),
        });
        Object.defineProperty(window.URL, 'revokeObjectURL', {
            writable: true,
            value: jest.fn(),
        });
        jest.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    });

    it('renders an accessible alert state when token is missing or invalid without making network requests', () => {
        mockTokenParam = 'too-short';
        const fetchMock = jest.fn();
        global.fetch = fetchMock as unknown as typeof fetch;

        render(<PublicSharePage />);

        const alert = screen.getByRole('alert');
        expect(within(alert).getByText('Invalid or Missing Share Link')).toBeInTheDocument();
        expect(fetchMock).not.toHaveBeenCalled();
    });

    it('renders expired/revoked state when metadata returns 404 or expires_at is in the past', async () => {
        const fetchMock = jest
            .fn()
            .mockResolvedValueOnce(
                jsonResponse(
                    { code: 'NOT_FOUND', message: 'Share not found or has expired' },
                    404
                )
            )
            .mockResolvedValueOnce(
                jsonResponse({
                    name: 'expired-archive.zip',
                    is_directory: false,
                    password_required: false,
                    allow_download: true,
                    expires_at: '2020-01-01T00:00:00Z',
                })
            );
        global.fetch = fetchMock as unknown as typeof fetch;

        render(<PublicSharePage />);

        expect(await screen.findByText('Share Unavailable or Expired')).toBeInTheDocument();
        expect(screen.getByText('Share not found or has expired')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Check Again/i }));

        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledTimes(2);
        });
        expect(
            await screen.findByText('This shared link has expired and is no longer available.')
        ).toBeInTheDocument();
    });

    it('handles password-protected share unlock flow, wrong password 401 without logout, and 429 throttle', async () => {
        const sessionExpiredListener = jest.fn();
        window.addEventListener('af:session-expired', sessionExpiredListener);

        const fetchMock = jest
            .fn()
            // 1. Metadata -> password_required: true
            .mockResolvedValueOnce(
                jsonResponse({
                    name: 'vault-folder',
                    is_directory: true,
                    password_required: true,
                    allow_download: true,
                    expires_at: null,
                })
            )
            // 2. Unlock attempt 1 -> 401 wrong password
            .mockResolvedValueOnce(
                jsonResponse(
                    { code: 'SHARE_PASSWORD_INVALID', message: 'Invalid share password' },
                    401
                )
            )
            // 3. Unlock attempt 2 -> 429 rate limited
            .mockResolvedValueOnce(
                jsonResponse(
                    {
                        code: 'TOO_MANY_REQUESTS',
                        message: 'Too many failed password attempts. Please try again later.',
                    },
                    429
                )
            )
            // 4. Unlock attempt 3 -> 200 OK
            .mockResolvedValueOnce(
                jsonResponse({
                    success: true,
                    access_token: 'scoped-token-xyz',
                    expires_in: 3600,
                })
            )
            // 5. Entries after unlock -> 200 OK
            .mockResolvedValueOnce(
                jsonResponse({
                    path: '',
                    entries: [
                        {
                            name: 'secret.txt',
                            path: 'secret.txt',
                            kind: 'file',
                            size: 1024,
                            modified: '2026-11-01T12:00:00Z',
                        },
                    ],
                })
            );
        global.fetch = fetchMock as unknown as typeof fetch;

        render(<PublicSharePage />);

        expect(
            await screen.findByRole('heading', { name: 'vault-folder' })
        ).toBeInTheDocument();
        expect(screen.getByText('Password Protected')).toBeInTheDocument();

        const passwordInput = screen.getByLabelText('Share Password');
        const unlockBtn = screen.getByRole('button', { name: /Unlock Share/i });

        // Submit wrong password
        fireEvent.change(passwordInput, { target: { value: 'wrong-pass' } });
        fireEvent.click(unlockBtn);

        expect(await screen.findByRole('alert')).toHaveTextContent('Invalid share password');
        expect(window.localStorage.getItem('af_logout_sync')).toBeNull();
        expect(sessionExpiredListener).not.toHaveBeenCalled();

        // Submit throttled attempt
        fireEvent.change(passwordInput, { target: { value: 'another-pass' } });
        fireEvent.click(unlockBtn);

        await waitFor(() => {
            expect(screen.getByRole('alert')).toHaveTextContent(
                'Too many failed password attempts. Please try again later.'
            );
        });

        // Submit correct password
        fireEvent.change(passwordInput, { target: { value: 'correct-horse-battery-staple' } });
        fireEvent.click(unlockBtn);

        expect(await screen.findByText('secret.txt')).toBeInTheDocument();
        expect(screen.getByText('Unlocked')).toBeInTheDocument();

        // Verify credentials: 'include' was passed on every call
        for (const call of fetchMock.mock.calls) {
            expect(call[1]?.credentials).toBe('include');
        }

        window.removeEventListener('af:session-expired', sessionExpiredListener);
    });

    it('browses scoped directories, filters entries, downloads files, and handles mid-session revocation', async () => {
        const fetchMock = jest
            .fn()
            // 1. Metadata
            .mockResolvedValueOnce(
                jsonResponse({
                    name: 'project-docs',
                    is_directory: true,
                    password_required: false,
                    allow_download: true,
                    expires_at: null,
                })
            )
            // 2. Root entries
            .mockResolvedValueOnce(
                jsonResponse({
                    path: '',
                    entries: [
                        {
                            name: 'guides',
                            path: 'guides',
                            kind: 'directory',
                            size: 0,
                            modified: '2026-11-01T09:00:00Z',
                        },
                        {
                            name: 'readme.md',
                            path: 'readme.md',
                            kind: 'file',
                            size: 2048,
                            modified: '2026-11-01T10:00:00Z',
                        },
                    ],
                })
            )
            // 3. Subdirectory entries (guides)
            .mockResolvedValueOnce(
                jsonResponse({
                    path: 'guides',
                    entries: [
                        {
                            name: 'install.txt',
                            path: 'guides/install.txt',
                            kind: 'file',
                            size: 512,
                            modified: '2026-11-01T11:00:00Z',
                        },
                    ],
                })
            )
            // 4. Download guides/install.txt
            .mockResolvedValueOnce(
                new Response('install-steps', {
                    status: 200,
                    headers: {
                        'Content-Type': 'application/octet-stream',
                        'Content-Disposition': 'attachment; filename="install.txt"',
                    },
                })
            )
            // 5. Navigate back to root -> simulate share revoked (404)
            .mockResolvedValueOnce(
                jsonResponse(
                    { code: 'NOT_FOUND', message: 'Share not found or has expired' },
                    404
                )
            );
        global.fetch = fetchMock as unknown as typeof fetch;

        render(<PublicSharePage />);

        expect(await screen.findByText('readme.md')).toBeInTheDocument();
        expect(screen.getByText('2 KiB')).toBeInTheDocument();

        // Filter entries in root folder
        const filterInput = screen.getByLabelText('Filter current folder');
        fireEvent.change(filterInput, { target: { value: 'guides' } });
        expect(screen.queryByText('readme.md')).not.toBeInTheDocument();
        expect(screen.getByText('guides')).toBeInTheDocument();

        // Open subdirectory 'guides'
        fireEvent.click(screen.getByRole('button', { name: 'Open folder guides' }));

        expect(await screen.findByText('install.txt')).toBeInTheDocument();
        expect(fetchMock).toHaveBeenCalledWith(
            `${PUBLIC_SHARE_API_BASE}/${VALID_TOKEN}/entries?path=guides`,
            expect.objectContaining({ credentials: 'include', method: 'GET' })
        );

        // Breadcrumbs show root 'project-docs' and 'guides'
        const breadcrumbNav = screen.getByRole('navigation', {
            name: 'Shared folder breadcrumbs',
        });
        expect(within(breadcrumbNav).getByRole('button', { name: 'project-docs' })).toBeEnabled();
        expect(within(breadcrumbNav).getByRole('button', { name: 'guides' })).toHaveAttribute(
            'aria-current',
            'page'
        );

        // Download file in subdirectory
        fireEvent.click(screen.getByRole('button', { name: 'Download install.txt' }));
        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledWith(
                `${PUBLIC_SHARE_API_BASE}/${VALID_TOKEN}/download?path=guides%2Finstall.txt`,
                expect.objectContaining({ credentials: 'include', method: 'HEAD' })
            );
        });

        // Navigate up after owner revokes the share -> transitions to expired/revoked alert
        fireEvent.click(screen.getByRole('button', { name: 'Up one folder level' }));
        expect(await screen.findByText('Share Unavailable or Expired')).toBeInTheDocument();
    });

    it('enforces view-only mode when allow_download is false and never injects untrusted HTML', async () => {
        const maliciousName = '<img src=x onerror=alert(1)><script>window.__xss=1</script>.txt';
        const fetchMock = jest
            .fn()
            .mockResolvedValueOnce(
                jsonResponse({
                    name: maliciousName,
                    is_directory: false,
                    password_required: false,
                    allow_download: false,
                    expires_at: null,
                })
            )
            .mockResolvedValueOnce(
                jsonResponse({
                    path: '',
                    entries: [
                        {
                            name: maliciousName,
                            path: maliciousName,
                            kind: 'file',
                            size: 4096,
                            modified: '2026-11-01T12:00:00Z',
                        },
                    ],
                })
            );
        global.fetch = fetchMock as unknown as typeof fetch;

        const { container } = render(<PublicSharePage />);

        expect(
            await screen.findByText('View-only (downloads disabled)')
        ).toBeInTheDocument();
        expect(screen.getAllByText(maliciousName).length).toBeGreaterThanOrEqual(1);
        expect(screen.getByRole('button', { name: /Downloads Disabled/i })).toBeDisabled();

        // Ensure no <script> or <img> tag was injected into the DOM
        expect(container.querySelector('script')).toBeNull();
        expect(container.querySelector('img')).toBeNull();
    });
});
