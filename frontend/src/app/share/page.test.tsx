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
        expect(within(alert).getByText(/ask the share owner for a new link/)).toBeInTheDocument();
        expect(within(alert).getByRole('link', { name: 'Open AetherFlow' })).toHaveAttribute('href', '/');
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

        const checkAgainButton = screen.getByRole('button', { name: /Check Again/i });
        expect(checkAgainButton).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');
        fireEvent.click(checkAgainButton);

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

        expect(unlockBtn).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');
        expect(passwordInput).toHaveClass('min-h-[44px]');
        expect(screen.getByRole('button', { name: 'Show password' })).toHaveClass(
            'min-h-[44px]',
            'min-w-[44px]',
            'obs-touch-target-standard'
        );

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
        const projectDocsButton = within(breadcrumbNav).getByRole('button', { name: 'project-docs' });
        const guidesButton = within(breadcrumbNav).getByRole('button', { name: 'guides' });
        expect(projectDocsButton).toBeEnabled();
        expect(projectDocsButton).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');
        expect(guidesButton).toHaveAttribute(
            'aria-current',
            'page'
        );
        expect(guidesButton).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');

        // Download file in subdirectory
        const downloadInstallButton = screen.getByRole('button', { name: 'Download install.txt' });
        expect(downloadInstallButton).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');
        fireEvent.click(downloadInstallButton);
        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledWith(
                `${PUBLIC_SHARE_API_BASE}/${VALID_TOKEN}/download?path=guides%2Finstall.txt`,
                expect.objectContaining({ credentials: 'include', method: 'HEAD' })
            );
        });

        // Navigate up after owner revokes the share -> transitions to expired/revoked alert
        const upButton = screen.getByRole('button', { name: 'Up one folder level' });
        expect(upButton).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');
        fireEvent.click(upButton);
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

    it('renders embedded continuous hairline bands and verified touch targets without floating card islands', async () => {
        const fetchMock = jest
            .fn()
            .mockResolvedValueOnce(
                jsonResponse({
                    name: 'workspace-bundle',
                    is_directory: true,
                    password_required: false,
                    allow_download: true,
                    expires_at: null,
                })
            )
            .mockResolvedValueOnce(
                jsonResponse({
                    path: '',
                    entries: [
                        {
                            name: 'docs',
                            path: 'docs',
                            kind: 'directory',
                            size: 0,
                            modified: '2026-11-01T09:00:00Z',
                        },
                        {
                            name: 'spec.pdf',
                            path: 'spec.pdf',
                            kind: 'file',
                            size: 8192,
                            modified: '2026-11-01T10:00:00Z',
                        },
                    ],
                })
            );
        global.fetch = fetchMock as unknown as typeof fetch;

        render(<PublicSharePage />);

        expect(await screen.findByRole('heading', { name: 'workspace-bundle' })).toBeInTheDocument();
        const mainElement = screen.getByLabelText('Public shared content');
        expect(mainElement).toHaveClass('bg-transparent');
        expect(mainElement).not.toHaveClass('bg-slate-950');

        const tableElement = screen.getByLabelText('Shared directory contents');
        const tableWrapper = tableElement.parentElement;
        expect(tableWrapper).not.toBeNull();
        expect(tableWrapper).toHaveClass(
            'border-y',
            'border-white/[0.07]',
            'bg-transparent',
            'overflow-x-auto',
            'min-w-0',
            'max-w-full'
        );
        expect(tableWrapper).not.toHaveClass('rounded-xl', 'bg-slate-950/60');

        const openDocsButton = screen.getByRole('button', { name: 'Browse docs' });
        expect(openDocsButton).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');

        const downloadPdfButton = screen.getByRole('button', { name: 'Download spec.pdf' });
        expect(downloadPdfButton).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');
    });

    it('renders single-file share as transparent hairline band with standard interaction height', async () => {
        const fetchMock = jest
            .fn()
            .mockResolvedValueOnce(
                jsonResponse({
                    name: 'archive.tar.gz',
                    is_directory: false,
                    password_required: false,
                    allow_download: true,
                    expires_at: null,
                })
            )
            .mockResolvedValueOnce(
                jsonResponse({
                    path: '',
                    entries: [
                        {
                            name: 'archive.tar.gz',
                            path: 'archive.tar.gz',
                            kind: 'file',
                            size: 1048576,
                            modified: '2026-11-01T12:00:00Z',
                        },
                    ],
                })
            );
        global.fetch = fetchMock as unknown as typeof fetch;

        render(<PublicSharePage />);

        const downloadFileButton = await screen.findByRole('button', {
            name: 'Download archive.tar.gz',
        });
        expect(downloadFileButton).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');

        const singleFileBand = downloadFileButton.closest('div')?.parentElement;
        expect(singleFileBand).toHaveClass('border-y', 'border-white/[0.07]', 'bg-transparent');
        expect(singleFileBand).not.toHaveClass('rounded-xl', 'bg-slate-950/70');
    });

    it('keeps directory actions in view and wraps complete names with responsive metadata', async () => {
        const longFilename = 'canvas-final-6M98BF-long-configuration-manifest-backup-v2.yaml';
        const fetchMock = jest
            .fn()
            .mockResolvedValueOnce(
                jsonResponse({
                    name: 'shared-folder',
                    is_directory: true,
                    password_required: false,
                    allow_download: true,
                    expires_at: null,
                })
            )
            .mockResolvedValueOnce(
                jsonResponse({
                    path: '',
                    entries: [
                        {
                            name: longFilename,
                            path: longFilename,
                            kind: 'file',
                            size: 1048576,
                            modified: '2026-11-01T12:00:00Z',
                        },
                    ],
                })
            );
        global.fetch = fetchMock as unknown as typeof fetch;

        render(<PublicSharePage />);

        const tableElement = await screen.findByRole('table', {
            name: 'Shared directory contents',
        });
        expect(tableElement).toHaveClass('w-full', 'block', 'md:table', 'md:table-fixed');

        const theadElement = tableElement.querySelector('thead');
        expect(theadElement).not.toBeNull();
        expect(theadElement).toHaveClass('hidden', 'md:table-header-group');

        const nameHeader = screen.getByRole('columnheader', { name: 'Name' });
        expect(nameHeader).toBeInTheDocument();
        expect(screen.getByRole('columnheader', { name: 'Action' })).toHaveClass('md:w-40');
        expect(screen.getByRole('columnheader', { name: 'Type' })).toHaveClass('hidden', 'md:table-cell');
        expect(screen.getByRole('columnheader', { name: 'Modified' })).toHaveClass('hidden', 'lg:table-cell');

        const fileSpan = screen.getByTitle(longFilename);
        expect(fileSpan).toHaveClass('min-w-0', 'break-words', '[overflow-wrap:anywhere]');
        expect(fileSpan).toHaveTextContent(longFilename);

        const rowElement = fileSpan.closest('tr');
        expect(rowElement).not.toBeNull();
        expect(rowElement).toHaveClass('block', 'md:table-row');

        const nameCell = fileSpan.closest('td');
        expect(nameCell).not.toBeNull();
        expect(nameCell).toHaveClass('block', 'md:table-cell', 'min-w-0');

        expect(screen.getByText('File · 1 MiB')).toHaveClass('text-slate-300');
        const modifiedElements = within(nameCell!).getAllByText(/Modified/i);
        expect(modifiedElements.length).toBeGreaterThanOrEqual(1);
        expect(modifiedElements[0]).toHaveClass('text-slate-400');

        const downloadButton = screen.getByRole('button', {
            name: `Download ${longFilename}`,
        });
        expect(downloadButton).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');
        expect(downloadButton).toHaveClass('border-white/10', 'bg-white/[0.04]', 'text-indigo-200');
        expect(downloadButton).not.toHaveClass('bg-indigo-600');

        const actionCell = downloadButton.closest('td');
        expect(actionCell).not.toBeNull();
        expect(actionCell).toHaveClass('block', 'md:table-cell');
    });

    it('verifies responsive folder row semantics and authorized per-row directory actions', async () => {
        const fetchMock = jest
            .fn()
            .mockResolvedValueOnce(
                jsonResponse({
                    name: 'nested-share',
                    is_directory: true,
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
                            name: 'nested-folder',
                            path: 'nested-folder',
                            kind: 'directory',
                            size: 0,
                            modified: '2026-11-01T08:00:00Z',
                        },
                        {
                            name: 'locked-doc.pdf',
                            path: 'locked-doc.pdf',
                            kind: 'file',
                            size: 2048,
                            modified: '2026-11-01T08:30:00Z',
                        },
                    ],
                })
            );
        global.fetch = fetchMock as unknown as typeof fetch;

        render(<PublicSharePage />);

        expect(await screen.findByRole('heading', { name: 'nested-share' })).toBeInTheDocument();

        const folderButton = screen.getByRole('button', { name: 'Open folder nested-folder' });
        expect(folderButton).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');

        const folderCell = folderButton.closest('td');
        expect(folderCell).not.toBeNull();
        expect(within(folderCell!).getByText('Folder')).toHaveClass('text-slate-300');

        const openAction = screen.getByRole('button', { name: 'Browse nested-folder' });
        expect(openAction).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');
        expect(openAction.closest('td')).toHaveClass('block', 'md:table-cell');

        expect(screen.getByText('File · 2 KiB')).toHaveClass('text-slate-300');

        const viewOnlyBadge = screen.getByText('View only');
        expect(viewOnlyBadge).toBeInTheDocument();
        expect(viewOnlyBadge.closest('td')).toHaveClass('block', 'md:table-cell');
    });
});
