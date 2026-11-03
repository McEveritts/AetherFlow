import React from 'react';
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import McBrowserTab from '@/components/tabs/McBrowserTab';
import McBrowserSettingsTab from '@/components/tabs/McBrowserSettingsTab';
import { NAVIGATION } from '@/components/layout/Sidebar';
import { useSystemStore } from '@/store/useSystemStore';
import {
    McBrowserEntry,
    McBrowserEntriesResponse,
    McBrowserPreviewResponse,
    McBrowserRequestError,
    DEFAULT_MAX_UPLOAD_BYTES,
    listMcBrowserEntries,
    createMcBrowserDirectory,
    ensureMcBrowserDirectory,
    renameMcBrowserEntry,
    deleteMcBrowserEntry,
    fetchMcBrowserPreview,
    downloadMcBrowserFile,
} from '@/lib/mcbrowser';
import {
    McBrowserResumableProgress,
    McBrowserResumableResult,
    McBrowserUploadUncertaintyError,
    cancelMcBrowserResumable,
    uploadMcBrowserResumable,
} from '@/lib/mcbrowser-resumable';
import {
    fetchMcBrowserPolicy,
    fetchMcBrowserPreferences,
    fetchMcBrowserUsage,
} from '@/lib/mcbrowser-workspace';

const mockAddToast = jest.fn();
jest.mock('@/components/mcbrowser/McBrowserEventsAdmin', () => ({
    __esModule: true,
    default: () => <section aria-label="Mounted event administration" />,
}));
jest.mock('@/components/mcbrowser/McBrowserPolicyAdmin', () => ({
    __esModule: true,
    default: ({ initialTargetUserId, onPolicySaved }: { initialTargetUserId: number; onPolicySaved: (targetUserId: number) => void }) => (
        <section aria-label="File policy administration">
            <button onClick={() => onPolicySaved(initialTargetUserId)}>Save own file policy</button>
        </section>
    ),
}));
jest.mock('@/components/mcbrowser/McBrowserMediaPreview', () => ({
    __esModule: true,
    default: ({ entry, onClose }: { entry: McBrowserEntry; onClose: () => void }) => (
        <div role="dialog" aria-label={`Media preview ${entry.name}`}>
            <button onClick={onClose}>Close media preview</button>
        </div>
    ),
}));
let mockAuthState: {
    isAuthenticated: boolean;
    isLoading: boolean;
    user: { id: number; username: string; role?: string } | null;
} = {
    isAuthenticated: true,
    isLoading: false,
    user: { id: 1, username: 'admin' },
};

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
    }),
}));

jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => mockAuthState,
}));

jest.mock('@/lib/mcbrowser', () => {
    const actual = jest.requireActual('@/lib/mcbrowser');
    return {
        ...actual,
        listMcBrowserEntries: jest.fn(),
        createMcBrowserDirectory: jest.fn(),
        ensureMcBrowserDirectory: jest.fn(),
        renameMcBrowserEntry: jest.fn(),
        deleteMcBrowserEntry: jest.fn(),
        uploadMcBrowserFile: jest.fn(),
        fetchMcBrowserPreview: jest.fn(),
        downloadMcBrowserFile: jest.fn(),
    };
});

jest.mock('@/lib/mcbrowser-resumable', () => {
    const actual = jest.requireActual('@/lib/mcbrowser-resumable');
    return {
        ...actual,
        uploadMcBrowserResumable: jest.fn(),
        cancelMcBrowserResumable: jest.fn(),
    };
});

jest.mock('@/lib/mcbrowser-workspace', () => {
    const actual = jest.requireActual('@/lib/mcbrowser-workspace');
    return {
        ...actual,
        fetchMcBrowserPolicy: jest.fn(),
        fetchMcBrowserPreferences: jest.fn(),
        fetchMcBrowserUsage: jest.fn(),
    };
});

const mockedListEntries = listMcBrowserEntries as jest.MockedFunction<typeof listMcBrowserEntries>;
const mockedCreateDir = createMcBrowserDirectory as jest.MockedFunction<typeof createMcBrowserDirectory>;
const mockedRenameEntry = renameMcBrowserEntry as jest.MockedFunction<typeof renameMcBrowserEntry>;
const mockedDeleteEntry = deleteMcBrowserEntry as jest.MockedFunction<typeof deleteMcBrowserEntry>;
const mockedEnsureDir = ensureMcBrowserDirectory as jest.MockedFunction<typeof ensureMcBrowserDirectory>;
const mockedUploadResumable = uploadMcBrowserResumable as jest.MockedFunction<typeof uploadMcBrowserResumable>;
const mockedCancelResumable = cancelMcBrowserResumable as jest.MockedFunction<typeof cancelMcBrowserResumable>;
const mockedFetchPreview = fetchMcBrowserPreview as jest.MockedFunction<typeof fetchMcBrowserPreview>;
const mockedDownloadFile = downloadMcBrowserFile as jest.MockedFunction<typeof downloadMcBrowserFile>;
const mockedFetchPolicy = fetchMcBrowserPolicy as jest.MockedFunction<typeof fetchMcBrowserPolicy>;
const mockedFetchPrefs = fetchMcBrowserPreferences as jest.MockedFunction<typeof fetchMcBrowserPreferences>;
const mockedFetchUsage = fetchMcBrowserUsage as jest.MockedFunction<typeof fetchMcBrowserUsage>;

function createDeferred<T>() {
    let resolve!: (value: T | PromiseLike<T>) => void;
    let reject!: (reason?: unknown) => void;
    const promise = new Promise<T>((res, rej) => {
        resolve = res;
        reject = rej;
    });
    return { promise, resolve, reject };
}

const SAMPLE_ENTRIES: McBrowserEntry[] = [
    {
        name: 'configs',
        path: 'configs',
        kind: 'directory',
        size: 0,
        modified: '2026-10-15T10:00:00Z',
    },
    {
        name: 'alpha-notes.txt',
        path: 'alpha-notes.txt',
        kind: 'file',
        size: 1024,
        modified: '2026-10-20T14:30:00Z',
    },
    {
        name: 'zeta-archive.log',
        path: 'zeta-archive.log',
        kind: 'file',
        size: 51200,
        modified: '2026-10-18T08:15:00Z',
    },
    {
        name: 'broken-link',
        path: 'broken-link',
        kind: 'symlink',
        size: 24,
        modified: '2026-10-19T12:00:00Z',
    },
];

describe('McBrowserTab Component & Workspace Integration', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockAuthState = {
            isAuthenticated: true,
            isLoading: false,
            user: { id: 1, username: 'admin' },
        };
        mockedUploadResumable.mockReset();
        mockedCancelResumable.mockReset();
        mockedEnsureDir.mockReset();
        mockedEnsureDir.mockResolvedValue({ success: true });
        mockedListEntries.mockResolvedValue({
            path: '',
            entries: SAMPLE_ENTRIES,
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });
        mockedFetchPolicy.mockResolvedValue({
            permissions: {
                read: true,
                create: true,
                rename: true,
                modify: true,
                delete: true,
                share: true,
                download: true,
            },
            rules: [],
            scope: 'My files',
        });
        mockedFetchPrefs.mockResolvedValue({
            view: 'list',
            sort: 'name',
            direction: 'asc',
            show_hidden: false,
            single_click: false,
            locale: 'en-US',
        });
        mockedFetchUsage.mockResolvedValue({
            used_bytes: 52224,
            quota_bytes: 1073741824,
            status: 'ok',
        });
    });

    it('renders accessible loading state while initial directory entries are in flight', async () => {
        const deferred = createDeferred<McBrowserEntriesResponse>();
        mockedListEntries.mockReturnValueOnce(deferred.promise);

        render(<McBrowserTab />);

        const loadingStatus = screen.getByRole('status');
        expect(loadingStatus).toHaveAttribute('aria-live', 'polite');
        expect(within(loadingStatus).getByText(/Loading My files\.\.\./i)).toBeInTheDocument();

        expect(screen.getByRole('button', { name: /New Folder/i })).toBeDisabled();
        expect(screen.getByRole('button', { name: /Upload Files/i })).toBeDisabled();

        await act(async () => {
            deferred.resolve({
                path: '',
                entries: [],
                max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            });
        });

        await waitFor(() => {
            expect(screen.queryByRole('status')).not.toBeInTheDocument();
        });
        expect(screen.getByText(/This folder is empty/i)).toBeInTheDocument();
    });

    it('opens the mounted rename confirmation from the workspace F2 shortcut', async () => {
        render(<McBrowserTab />);
        const workspace = await screen.findByRole('region', { name: 'Advanced file actions and workspace explorer' });
        await waitFor(() => expect(within(workspace).getByRole('button', { name: 'New File' })).toBeEnabled());
        fireEvent.click(within(workspace).getByRole('checkbox', { name: 'Select alpha-notes.txt' }));
        fireEvent.keyDown(workspace, { key: 'F2' });
        expect(screen.getByRole('dialog', { name: 'Rename File' })).toBeInTheDocument();
        expect(mockedRenameEntry).not.toHaveBeenCalled();
    });

    it('renders empty state and handles error state with retry recovery', async () => {
        mockedListEntries.mockRejectedValueOnce(
            new McBrowserRequestError(500, 'IO_ERROR', 'Storage volume temporarily unavailable')
        );

        render(<McBrowserTab />);

        const alertRegion = await screen.findByRole('alert');
        expect(within(alertRegion).getByText(/Unable to load directory/i)).toBeInTheDocument();
        expect(
            within(alertRegion).getByText(/Storage volume temporarily unavailable \(IO_ERROR\)/i)
        ).toBeInTheDocument();

        mockedListEntries.mockResolvedValueOnce({
            path: '',
            entries: [],
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });

        fireEvent.click(within(alertRegion).getByRole('button', { name: /Retry/i }));

        await waitFor(() => {
            expect(screen.getByText(/This folder is empty/i)).toBeInTheDocument();
        });
        expect(mockedListEntries).toHaveBeenCalledTimes(2);
    });

    it('navigates into nested folders and returns via breadcrumb and parent button', async () => {
        render(<McBrowserTab />);

        const primaryTable = await screen.findByRole('table', { name: /Directory entries/i });
        expect(within(primaryTable).getByRole('button', { name: 'configs' })).toBeInTheDocument();

        const nestedEntries: McBrowserEntry[] = [
            {
                name: 'nginx.conf',
                path: 'configs/nginx.conf',
                kind: 'file',
                size: 2048,
                modified: '2026-10-21T09:00:00Z',
            },
            {
                name: 'tls',
                path: 'configs/tls',
                kind: 'directory',
                size: 0,
                modified: '2026-10-21T09:05:00Z',
            },
        ];
        mockedListEntries.mockResolvedValueOnce({
            path: 'configs',
            entries: nestedEntries,
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });

        fireEvent.click(within(primaryTable).getByRole('button', { name: 'configs' }));

        await waitFor(() => {
            const updatedTable = screen.getByRole('table', { name: /Directory entries/i });
            expect(within(updatedTable).getByRole('button', { name: 'nginx.conf' })).toBeInTheDocument();
        });
        expect(mockedListEntries).toHaveBeenLastCalledWith('configs', expect.any(AbortSignal));

        const breadcrumbNav = screen.getByRole('navigation', { name: /Breadcrumb/i });
        expect(within(breadcrumbNav).getByRole('button', { name: 'My files' })).toBeInTheDocument();
        expect(within(breadcrumbNav).getByRole('button', { name: 'configs' })).toHaveAttribute(
            'aria-current',
            'page'
        );
        mockedListEntries.mockResolvedValueOnce({
            path: 'configs/tls',
            entries: [],
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });
        fireEvent.click(
            within(screen.getByRole('table', { name: /Directory entries/i })).getByRole('button', {
                name: 'tls',
            })
        );

        await screen.findByText(/This folder is empty/i);
        expect(within(breadcrumbNav).getByRole('button', { name: 'tls' })).toHaveAttribute(
            'aria-current',
            'page'
        );
        mockedListEntries.mockResolvedValueOnce({
            path: 'configs',
            entries: nestedEntries,
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });
        fireEvent.click(screen.getByRole('button', { name: /Navigate to parent folder/i }));

        await waitFor(() => {
            expect(
                within(screen.getByRole('table', { name: /Directory entries/i })).getByRole(
                    'button',
                    { name: 'nginx.conf' }
                )
            ).toBeInTheDocument();
        });
        expect(mockedListEntries).toHaveBeenLastCalledWith('configs', expect.any(AbortSignal));
        mockedListEntries.mockResolvedValueOnce({
            path: '',
            entries: SAMPLE_ENTRIES,
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });
        fireEvent.click(within(breadcrumbNav).getByRole('button', { name: 'My files' }));

        await waitFor(() => {
            expect(
                within(screen.getByRole('table', { name: /Directory entries/i })).getByRole(
                    'button',
                    { name: 'alpha-notes.txt' }
                )
            ).toBeInTheDocument();
        });
        expect(mockedListEntries).toHaveBeenLastCalledWith('', expect.any(AbortSignal));
    });

    it('filters entries by filename and sorts by name, size, and modified date while keeping folders grouped first', async () => {
        render(<McBrowserTab />);

        const getPrimaryTable = () => screen.getByRole('table', { name: /Directory entries/i });
        await screen.findByRole('table', { name: /Directory entries/i });

        const getRenderedRowNames = () => {
            const rows = within(getPrimaryTable()).getAllByRole('row').slice(1); // skip header row
            return rows.map((r) => {
                const btn = within(r).queryByRole('button', {
                    name: /^(configs|alpha-notes\.txt|zeta-archive\.log)$/,
                });
                if (btn) return btn.textContent;
                if (r.textContent?.includes('broken-link')) return 'broken-link';
                return r.textContent;
            });
        };
        expect(getRenderedRowNames()).toEqual([
            'configs',
            'alpha-notes.txt',
            'broken-link',
            'zeta-archive.log',
        ]);
        fireEvent.click(screen.getByRole('button', { name: /^Sort by name$/i }));
        expect(getRenderedRowNames()).toEqual([
            'configs',
            'zeta-archive.log',
            'broken-link',
            'alpha-notes.txt',
        ]);
        fireEvent.click(screen.getByRole('button', { name: /^Sort by size$/i }));
        expect(getRenderedRowNames()).toEqual([
            'configs',
            'broken-link',
            'alpha-notes.txt',
            'zeta-archive.log',
        ]);
        fireEvent.click(screen.getByRole('button', { name: /^Sort by size$/i }));
        expect(getRenderedRowNames()).toEqual([
            'configs',
            'zeta-archive.log',
            'alpha-notes.txt',
            'broken-link',
        ]);
        const filterInput = screen.getByRole('searchbox', { name: /Filter files by name/i });
        fireEvent.change(filterInput, { target: { value: 'zeta' } });

        expect(within(getPrimaryTable()).getByRole('button', { name: 'zeta-archive.log' })).toBeInTheDocument();
        expect(within(getPrimaryTable()).queryByRole('button', { name: 'alpha-notes.txt' })).not.toBeInTheDocument();
        fireEvent.change(filterInput, { target: { value: 'nonexistent-file' } });
        expect(screen.getByText(/No matching entries for/i)).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /Clear filename filter/i }));
        expect(within(getPrimaryTable()).getByRole('button', { name: 'alpha-notes.txt' })).toBeInTheDocument();
    });

    it('validates folder names in the mkdir dialog and submits the joined relative path', async () => {
        mockedListEntries.mockResolvedValueOnce({
            path: 'configs',
            entries: [],
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });

        render(<McBrowserTab />);
        await screen.findByText(/This folder is empty/i);

        fireEvent.click(screen.getByRole('button', { name: /New Folder/i }));

        const dialog = screen.getByRole('dialog', { name: /Create New Folder/i });
        const input = within(dialog).getByLabelText(/Folder Name/i);
        const submitBtn = within(dialog).getByRole('button', { name: /^Create Folder$/i });
        fireEvent.click(submitBtn);
        expect(within(dialog).getByRole('alert')).toHaveTextContent(/Name cannot be empty/i);
        expect(mockedCreateDir).not.toHaveBeenCalled();
        fireEvent.change(input, { target: { value: '../escape' } });
        fireEvent.click(submitBtn);
        expect(within(dialog).getByRole('alert')).toHaveTextContent(
            /Name cannot contain slashes or path separators/i
        );
        expect(mockedCreateDir).not.toHaveBeenCalled();
        mockedCreateDir.mockResolvedValueOnce({ success: true });
        mockedListEntries.mockResolvedValueOnce({
            path: 'configs',
            entries: [
                {
                    name: 'backups',
                    path: 'configs/backups',
                    kind: 'directory',
                    size: 0,
                    modified: '2026-10-22T00:00:00Z',
                },
            ],
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });

        fireEvent.change(input, { target: { value: 'backups' } });
        fireEvent.click(submitBtn);

        await waitFor(() => {
            expect(mockedCreateDir).toHaveBeenCalledWith('configs/backups');
        });
        expect(mockAddToast).toHaveBeenCalledWith('Created folder "backups"', 'success');
        expect(screen.queryByRole('dialog', { name: /Create New Folder/i })).not.toBeInTheDocument();
    });

    it('submits rename dialog with normalized from/to relative paths and validates input', async () => {
        const nestedEntry: McBrowserEntry = {
            name: 'draft.txt',
            path: 'configs/draft.txt',
            kind: 'file',
            size: 128,
            modified: '2026-10-20T10:00:00Z',
        };
        mockedListEntries.mockResolvedValueOnce({
            path: 'configs',
            entries: [nestedEntry],
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });

        render(<McBrowserTab />);
        await screen.findByRole('table', { name: /Directory entries/i });

        fireEvent.click(screen.getByRole('button', { name: /Rename draft\.txt/i }));

        const dialog = screen.getByRole('dialog', { name: /Rename File/i });
        const input = within(dialog).getByLabelText(/New Name for/i);
        const submitBtn = within(dialog).getByRole('button', { name: /Confirm Rename/i });
        fireEvent.click(submitBtn);
        expect(within(dialog).getByRole('alert')).toHaveTextContent(
            /New name must be different from the current name/i
        );
        expect(mockedRenameEntry).not.toHaveBeenCalled();
        fireEvent.change(input, { target: { value: 'sub/final.txt' } });
        fireEvent.click(submitBtn);
        expect(within(dialog).getByRole('alert')).toHaveTextContent(
            /Name cannot contain slashes or path separators/i
        );
        expect(mockedRenameEntry).not.toHaveBeenCalled();
        mockedRenameEntry.mockResolvedValueOnce({ success: true });
        mockedListEntries.mockResolvedValueOnce({
            path: 'configs',
            entries: [{ ...nestedEntry, name: 'final.txt', path: 'configs/final.txt' }],
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });

        fireEvent.change(input, { target: { value: 'final.txt' } });
        fireEvent.click(submitBtn);

        await waitFor(() => {
            expect(mockedRenameEntry).toHaveBeenCalledWith('configs/draft.txt', 'configs/final.txt');
        });
        expect(mockAddToast).toHaveBeenCalledWith('Renamed "draft.txt" to "final.txt"', 'success');
        expect(screen.queryByRole('dialog', { name: /Rename File/i })).not.toBeInTheDocument();
    });

    it('requires explicit confirmation before deleting and does not optimistically remove entries on failure', async () => {
        render(<McBrowserTab />);
        const primaryTable = await screen.findByRole('table', { name: /Directory entries/i });

        fireEvent.click(screen.getByRole('button', { name: /Delete alpha-notes\.txt/i }));

        const dialog = screen.getByRole('dialog', { name: /Delete File/i });
        expect(within(dialog).getByText(/Are you sure you want to permanently delete/i)).toBeInTheDocument();
        expect(mockedDeleteEntry).not.toHaveBeenCalled();
        mockedDeleteEntry.mockRejectedValueOnce(
            new McBrowserRequestError(409, 'DIRECTORY_NOT_EMPTY', 'Cannot delete locked resource')
        );

        fireEvent.click(within(dialog).getByRole('button', { name: /Confirm Delete/i }));

        await waitFor(() => {
            expect(mockedDeleteEntry).toHaveBeenCalledWith('alpha-notes.txt');
        });
        expect(within(dialog).getByRole('alert')).toHaveTextContent(
            /Cannot delete locked resource \(DIRECTORY_NOT_EMPTY\)/i
        );
        expect(within(primaryTable).getByRole('button', { name: 'alpha-notes.txt' })).toBeInTheDocument();
        fireEvent.click(within(dialog).getByRole('button', { name: /Cancel/i }));
        expect(within(primaryTable).getByRole('button', { name: 'alpha-notes.txt' })).toBeInTheDocument();
    });

    it('allows safe leaf-link mutations without opening an unresolved link target', async () => {
        render(<McBrowserTab />);
        await screen.findByText('broken-link');

        expect(screen.getByRole('button', { name: 'broken-link' })).toBeDisabled();
        expect(screen.queryByRole('button', { name: /Preview broken-link/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /Download broken-link/i })).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Rename broken-link/i })).toBeEnabled();
        expect(screen.getByRole('button', { name: /Delete broken-link/i })).toBeEnabled();
        const symlinkRow = screen.getByText('broken-link').closest('tr');
        expect(symlinkRow).not.toBeNull();
        fireEvent.click(symlinkRow!);

        const selectionBar = screen.getByRole('region', { name: /Selected item actions/i });
        expect(
            within(selectionBar).getByText(
                /rename and delete affect the link only/i
            )
        ).toBeInTheDocument();
        expect(within(selectionBar).getByRole('button', { name: /Rename/i })).toBeEnabled();
        expect(within(selectionBar).getByRole('button', { name: /Delete/i })).toBeEnabled();
        expect(within(selectionBar).queryByRole('button', { name: /Preview/i })).not.toBeInTheDocument();
        expect(within(selectionBar).queryByRole('button', { name: /Download/i })).not.toBeInTheDocument();
    });

    it('opens confined directory and file aliases using their original alias paths', async () => {
        mockedListEntries.mockResolvedValue({
            path: '', max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            entries: [
                { name: 'folder-link', path: 'folder-link', kind: 'symlink', target_kind: 'directory', size: 0, modified: null },
                { name: 'file-link.txt', path: 'file-link.txt', kind: 'symlink', target_kind: 'file', size: 5, modified: null },
            ],
        });
        mockedFetchPreview.mockResolvedValue({ path: 'file-link.txt', content: 'hello', truncated: false });
        render(<McBrowserTab />);
        await screen.findByRole('button', { name: 'folder-link' });
        const directoryRow = screen.getByRole('button', { name: 'folder-link' }).closest('tr')!;
        expect(within(directoryRow).getAllByRole('cell')[2]).toHaveTextContent('—');
        expect(screen.getByText('1 folder · 1 file')).toBeInTheDocument();
        const rows = within(screen.getByRole('table', { name: /Directory entries/i })).getAllByRole('row');
        expect(rows[1]).toHaveTextContent('folder-link');
        await waitFor(() => expect(screen.getByRole('button', { name: 'Preview file-link.txt' })).toBeEnabled());
        fireEvent.click(screen.getByRole('button', { name: 'Preview file-link.txt' }));
        await waitFor(() => expect(mockedFetchPreview).toHaveBeenCalledWith('file-link.txt', expect.any(AbortSignal)));
        fireEvent.click(screen.getByRole('button', { name: /Close preview/i }));
        fireEvent.click(screen.getByRole('button', { name: 'folder-link' }));
        await waitFor(() => expect(mockedListEntries).toHaveBeenCalledWith('folder-link', expect.any(AbortSignal)));
    });

    it('renders UTF-8 text preview safely as literal text without executing HTML and shows truncation notice', async () => {
        const maliciousText = '<img src=x onerror="window.__xssExecuted = true" /><script>alert(1)</script>';
        const previewPayload: McBrowserPreviewResponse = {
            path: 'alpha-notes.txt',
            content: maliciousText,
            truncated: true,
        };
        mockedFetchPreview.mockResolvedValueOnce(previewPayload);

        render(<McBrowserTab />);
        await screen.findByRole('table', { name: /Directory entries/i });

        fireEvent.click(screen.getByRole('button', { name: /Preview alpha-notes\.txt/i }));

        const dialog = await screen.findByRole('dialog', { name: /Preview: alpha-notes\.txt/i });
        expect(mockedFetchPreview).toHaveBeenCalledWith('alpha-notes.txt', expect.any(AbortSignal));
        await waitFor(() => {
            expect(within(dialog).getByRole('status')).toHaveTextContent(
                /Preview truncated to the first 256 KiB of UTF-8 text/i
            );
        });
        expect(within(dialog).getByText(maliciousText)).toBeInTheDocument();
        expect(dialog.querySelector('img')).toBeNull();
        expect(dialog.querySelector('script')).toBeNull();
        mockedDownloadFile.mockResolvedValueOnce();
        fireEvent.click(within(dialog).getByRole('button', { name: /Download/i }));
        await waitFor(() => {
            expect(mockedDownloadFile).toHaveBeenCalledWith('alpha-notes.txt', 'alpha-notes.txt');
        });
    });

    it('pipelines resumable uploads with a five-request bound, confirmed progress, ETA, and per-file errors', async () => {
        render(<McBrowserTab />);
        await screen.findByRole('table', { name: /Directory entries/i });

        const firstUpload = createDeferred<McBrowserResumableResult>();
        const secondUpload = createDeferred<McBrowserResumableResult>();
        const thirdUpload = createDeferred<McBrowserResumableResult>();
        let firstProgressCb: ((p: McBrowserResumableProgress) => void) | undefined;

        mockedUploadResumable
            .mockImplementationOnce((_path, _file, options) => {
                firstProgressCb = options?.onProgress;
                return firstUpload.promise;
            })
            .mockReturnValueOnce(secondUpload.promise)
            .mockReturnValueOnce(thirdUpload.promise)
            .mockResolvedValue({ success: true, path: 'fourth.txt' });

        const oversized = new File(['x'], 'huge.bin');
        Object.defineProperty(oversized, 'size', { value: DEFAULT_MAX_UPLOAD_BYTES + 1 });
        const firstFile = new File(['a'.repeat(512)], 'first.txt');

        fireEvent.change(screen.getByLabelText('Upload files'), {
            target: {
                files: [
                    firstFile,
                    new File(['b'], 'second.txt'),
                    new File(['c'], 'third.txt'),
                    new File(['d'], 'fourth.txt'),
                    oversized,
                ],
            },
        });

        await waitFor(() => expect(mockedUploadResumable).toHaveBeenCalledTimes(4));
        const progress = screen.getByRole('region', { name: 'Upload progress' });
        expect(within(progress).getByText(/up to 5 requests in flight/i)).toBeInTheDocument();
        expect(within(progress).getByText(/exceeds maximum upload limit/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Add Files' })).toBeEnabled();
        expect(screen.getByRole('button', { name: 'Upload Folder' })).toBeEnabled();

        // Emit confirmed progress on first file
        await act(async () => {
            firstProgressCb?.({
                uploadedBytes: 256,
                totalBytes: 512,
                speedBytesPerSecond: 1024,
            });
        });
        expect(within(progress).getByText(/256 B \/ 512 B/i)).toBeInTheDocument();
        expect(within(progress).getByLabelText('Upload transfer estimate')).toHaveTextContent('ETA 00:00:01');
        expect(within(progress).getByRole('progressbar', { name: 'Confirmed upload bytes' })).toHaveAttribute('aria-valuenow', '257');

        await act(async () => {
            secondUpload.reject(
                new McBrowserRequestError(409, 'FILE_EXISTS', 'File already exists')
            );
        });
        await waitFor(() => expect(mockedUploadResumable).toHaveBeenCalledTimes(4));
        expect(mockedUploadResumable.mock.calls[3][0]).toBe('fourth.txt');

        await act(async () => {
            firstUpload.resolve({ success: true, path: 'first.txt' });
            thirdUpload.resolve({ success: true, path: 'third.txt' });
        });
        await waitFor(() =>
            expect(mockAddToast).toHaveBeenCalledWith(
                'Upload queue finished: 3 uploaded; 0 skipped; 2 failed; 0 need destination checks.',
                'info'
            )
        );
        expect(within(progress).getByText(/File already exists/)).toBeInTheDocument();
    });

    it('appends files to an active batch, retries only confirmed failures, and allows destination reselection after failure or cancellation', async () => {
        render(<McBrowserTab />);
        await screen.findByRole('table', { name: /Directory entries/i });

        const blocked = createDeferred<McBrowserResumableResult>();
        mockedUploadResumable
            .mockReturnValueOnce(blocked.promise)
            .mockRejectedValueOnce(new McBrowserRequestError(500, 'DISK_BUSY', 'Try again'))
            .mockResolvedValue({ success: true, path: 'second.txt' });

        fireEvent.change(screen.getByLabelText('Upload files'), {
            target: { files: [new File(['a'], 'first.txt')] },
        });
        await waitFor(() => expect(mockedUploadResumable).toHaveBeenCalledTimes(1));

        fireEvent.change(screen.getByLabelText('Upload files'), {
            target: { files: [new File(['b'], 'second.txt')] },
        });
        await screen.findByText(/Try again/);

        // Re-selecting failed destination 'second.txt' via file input is permitted (not blocked as duplicate)
        fireEvent.change(screen.getByLabelText('Upload files'), {
            target: { files: [new File(['b-reselected'], 'second.txt')] },
        });
        await waitFor(() => expect(mockedUploadResumable).toHaveBeenCalledTimes(3));
        expect(mockedUploadResumable.mock.calls[2][0]).toBe('second.txt');

        await act(async () => {
            blocked.resolve({ success: true, path: 'first.txt' });
        });
        await waitFor(() =>
            expect(screen.getByText(/2 files confirmed uploaded/)).toBeInTheDocument()
        );
    });

    it('preserves folder paths from folder picker and prepares parent directories before uploading', async () => {
        render(<McBrowserTab />);
        await screen.findByRole('table', { name: /Directory entries/i });
        mockedUploadResumable.mockResolvedValue({
            success: true,
            path: 'backup/config/settings.json',
        });
        const file = new File(['{}'], 'settings.json');
        Object.defineProperty(file, 'webkitRelativePath', { value: 'backup/config/settings.json' });
        fireEvent.change(screen.getByLabelText('Upload folder'), { target: { files: [file] } });
        await waitFor(() => expect(mockedUploadResumable).toHaveBeenCalledTimes(1));
        expect(mockedEnsureDir.mock.calls.map(([path]) => path)).toEqual(['backup', 'backup/config']);
        expect(mockedEnsureDir).toHaveBeenCalledWith('backup/config', expect.any(AbortSignal));
        expect(mockedUploadResumable).toHaveBeenCalledWith(
            'backup/config/settings.json',
            file,
            expect.objectContaining({
                signal: expect.any(AbortSignal),
                onProgress: expect.any(Function),
            })
        );
    });

    it('recursively traverses drag-and-drop webkitGetAsEntry items including empty directories and nested files', async () => {
        render(<McBrowserTab />);
        await screen.findByRole('table', { name: /Directory entries/i });
        mockedUploadResumable.mockResolvedValue({
            success: true,
            path: 'datapack/pack.mcmeta',
        });

        const packFile = new File(['{"pack":{}}'], 'pack.mcmeta');
        const emptySubdirEntry = {
            isFile: false,
            isDirectory: true,
            name: 'empty-functions',
            createReader: () => ({
                readEntries: (cb: (entries: unknown[]) => void) => cb([]),
            }),
        };
        const fileEntry = {
            isFile: true,
            isDirectory: false,
            name: 'pack.mcmeta',
            file: (cb: (f: File) => void) => cb(packFile),
        };
        let readCount = 0;
        const rootDirEntry = {
            isFile: false,
            isDirectory: true,
            name: 'datapack',
            createReader: () => ({
                readEntries: (cb: (entries: unknown[]) => void) => {
                    readCount += 1;
                    if (readCount === 1) {
                        cb([emptySubdirEntry, fileEntry]);
                    } else {
                        cb([]);
                    }
                },
            }),
        };

        const dropZone = screen.getByRole('heading', { name: 'McBrowser' }).closest('div.space-y-6')!;
        await act(async () => {
            fireEvent.drop(dropZone, {
                dataTransfer: {
                    items: [
                        {
                            kind: 'file',
                            webkitGetAsEntry: () => rootDirEntry,
                        },
                    ],
                    files: [],
                },
            });
        });

        await waitFor(() => expect(mockedUploadResumable).toHaveBeenCalledTimes(1));
        expect(mockedEnsureDir.mock.calls.map(([path]) => path)).toEqual([
            'datapack',
            'datapack/empty-functions',
        ]);
        expect(mockedUploadResumable).toHaveBeenCalledWith(
            'datapack/pack.mcmeta',
            expect.objectContaining({ name: 'pack.mcmeta' }),
            expect.any(Object)
        );
        const progress = screen.getByRole('region', { name: 'Upload progress' });
        expect(within(progress).getByText('datapack/empty-functions')).toBeInTheDocument();
        expect(within(progress).getByText('Folder created')).toBeInTheDocument();
    });

    it('keeps uploads running when the workspace is hidden but aborts them on unmount', async () => {
        const view = render(<McBrowserTab />);
        await screen.findByRole('table', { name: /Directory entries/i });
        const blocked = createDeferred<McBrowserResumableResult>();
        mockedUploadResumable.mockReturnValueOnce(blocked.promise);
        fireEvent.change(screen.getByLabelText('Upload files'), {
            target: { files: [new File(['a'], 'background.txt')] },
        });
        await waitFor(() => expect(mockedUploadResumable).toHaveBeenCalledTimes(1));
        const signal = mockedUploadResumable.mock.calls[0][2]?.signal;
        if (!signal) throw new Error('Upload must receive an abort signal');
        view.rerender(<McBrowserTab isActive={false} />);
        expect(signal.aborted).toBe(false);
        view.rerender(<McBrowserTab isActive />);
        expect(mockedUploadResumable).toHaveBeenCalledTimes(1);
        view.unmount();
        expect(signal.aborted).toBe(true);
        await act(async () => {
            blocked.resolve({ success: true, path: 'background.txt' });
        });
    });

    it('distinguishes pause/resume, explicit cancel with DELETE 204, pre-upload cancel, and uncertain commit state', async () => {
        render(<McBrowserTab />);
        await screen.findByRole('table', { name: /Directory entries/i });

        const firstDeferred = createDeferred<McBrowserResumableResult>();
        const secondDeferred = createDeferred<McBrowserResumableResult>();
        const thirdDeferred = createDeferred<McBrowserResumableResult>();
        const fourthDeferred = createDeferred<McBrowserResumableResult>();
        const fifthDeferred = createDeferred<McBrowserResumableResult>();
        const resumedDeferred = createDeferred<McBrowserResumableResult>();

        mockedUploadResumable
            .mockReturnValueOnce(firstDeferred.promise)
            .mockReturnValueOnce(secondDeferred.promise)
            .mockReturnValueOnce(thirdDeferred.promise)
            .mockReturnValueOnce(fourthDeferred.promise)
            .mockReturnValueOnce(fifthDeferred.promise)
            .mockReturnValueOnce(resumedDeferred.promise);

        fireEvent.change(screen.getByLabelText('Upload files'), {
            target: {
                files: ['one.txt', 'two.txt', 'three.txt', 'four.txt', 'five.txt', 'six.txt'].map(
                    (name) => new File(['x'], name)
                ),
            },
        });
        await waitFor(() => expect(mockedUploadResumable).toHaveBeenCalledTimes(5));

        fireEvent.click(screen.getByRole('button', { name: 'Cancel upload six.txt' }));
        expect(screen.getByText('Cancelled')).toBeInTheDocument();

        // 2. Pause active item one.txt -> aborts active request without calling cancelMcBrowserResumable, marks 'Paused'
        fireEvent.click(screen.getByRole('button', { name: 'Pause upload one.txt' }));
        expect(mockedUploadResumable.mock.calls[0][2]?.signal?.aborted).toBe(true);
        await act(async () => {
            firstDeferred.reject(new DOMException('Aborted', 'AbortError'));
        });
        expect(mockedCancelResumable).not.toHaveBeenCalled();
        expect(screen.getByText('Paused')).toBeInTheDocument();

        // 3. Resume paused item one.txt -> re-enters uploading state
        fireEvent.click(screen.getByRole('button', { name: 'Resume upload one.txt' }));
        await waitFor(() => expect(mockedUploadResumable).toHaveBeenCalledTimes(6));

        // 4. Explicit cancel on two.txt when server DELETE returns 204 ({ cancelled: true }) -> 'Cancelled before sending'
        mockedCancelResumable.mockResolvedValueOnce({ cancelled: true, sessionId: 'sess-2' });
        fireEvent.click(screen.getByRole('button', { name: 'Cancel upload two.txt' }));
        await act(async () => {
            secondDeferred.reject(new DOMException('Aborted', 'AbortError'));
        });

        // 5. Explicit cancel on three.txt when server returns 409 ALREADY_COMPLETED -> 'Check destination' (uncertain)
        mockedCancelResumable.mockRejectedValueOnce(
            new McBrowserRequestError(409, 'ALREADY_COMPLETED', 'Already published')
        );
        fireEvent.click(screen.getByRole('button', { name: 'Cancel upload three.txt' }));
        await act(async () => {
            thirdDeferred.reject(new DOMException('Aborted', 'AbortError'));
        });

        // 6. Transport uncertainty on resumed one.txt -> 'Check destination'
        await act(async () => {
            resumedDeferred.reject(
                new McBrowserUploadUncertaintyError('Ambiguous final chunk commit')
            );
            fourthDeferred.resolve({ success: true, path: 'four.txt' });
            fifthDeferred.resolve({ success: true, path: 'five.txt' });
        });

        await waitFor(() => {
            expect(screen.getAllByText('Check destination')).toHaveLength(2);
        });
        expect(screen.getAllByText('Cancelled')).toHaveLength(2);
        expect(screen.getByRole('alert')).toHaveTextContent('may have completed');
    });

    it('moves file policy and audit administration to McBrowserSettingsTab and navigates via McBrowser Settings button', async () => {
        mockAuthState.user = { id: 1, username: 'admin', role: 'admin' };
        useSystemStore.setState({ activeTab: 'fileshare', activeSettingsTab: 'preferences' });
        const view = render(<McBrowserTab isActive />);
        await screen.findByRole('table', { name: /Directory entries/i });
        expect(screen.queryByRole('region', { name: 'File policy administration' })).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'McBrowser Settings' }));
        expect(useSystemStore.getState().activeTab).toBe('settings');
        expect(useSystemStore.getState().activeSettingsTab).toBe('mcbrowser');
        view.unmount();

        const settingsView = render(<McBrowserSettingsTab />);
        expect(screen.getByRole('region', { name: 'File policy administration' })).toBeInTheDocument();
        expect(screen.queryByRole('region', { name: 'Mounted event administration' })).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Audit Events & Internal Queue' }));
        expect(screen.getByRole('region', { name: 'Mounted event administration' })).toBeInTheDocument();

        mockAuthState.user = { id: 2, username: 'member', role: 'user' };
        settingsView.rerender(<McBrowserSettingsTab />);
        expect(screen.queryByRole('region', { name: 'File policy administration' })).not.toBeInTheDocument();
        expect(screen.queryByRole('region', { name: 'Mounted event administration' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Audit Events & Internal Queue' })).not.toBeInTheDocument();
    });

    it('mounts McBrowserWorkspace only after activation and isolates state across user sessions', async () => {
        const view = render(<McBrowserTab isActive={false} />);
        expect(mockedListEntries).not.toHaveBeenCalled();
        expect(mockedFetchPolicy).not.toHaveBeenCalled();
        expect(
            screen.queryByRole('region', {
                name: /Advanced file actions and workspace explorer/i,
            })
        ).not.toBeInTheDocument();

        view.rerender(<McBrowserTab isActive />);
        await screen.findByRole('table', { name: /Directory entries/i });
        expect(mockedListEntries).toHaveBeenCalledTimes(1);
        expect(mockedFetchPolicy).toHaveBeenCalledTimes(1);
        expect(
            screen.getByRole('region', {
                name: /Advanced file actions and workspace explorer/i,
            })
        ).toBeInTheDocument();

        // Start an upload in user 1's session
        const user1Upload = createDeferred<McBrowserResumableResult>();
        mockedUploadResumable.mockReturnValueOnce(user1Upload.promise);
        fireEvent.change(screen.getByLabelText('Upload files'), {
            target: { files: [new File(['secret'], 'user1-secret.txt')] },
        });
        await waitFor(() => expect(mockedUploadResumable).toHaveBeenCalledTimes(1));
        const user1Signal = mockedUploadResumable.mock.calls[0][2]?.signal;
        if (!user1Signal) throw new Error('Upload must receive an abort signal');
        expect(screen.getByText('user1-secret.txt')).toBeInTheDocument();

        // Switch session identity to user 2: aborts user 1's upload, clears queue, remounts workspace, and reloads root
        mockAuthState = {
            isAuthenticated: true,
            isLoading: false,
            user: { id: 2, username: 'bob' },
        };
        mockedListEntries.mockResolvedValueOnce({
            path: '',
            entries: [],
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });
        view.rerender(<McBrowserTab isActive />);

        expect(user1Signal.aborted).toBe(true);
        await waitFor(() => {
            expect(screen.queryByText('user1-secret.txt')).not.toBeInTheDocument();
        });
        expect(mockedFetchPolicy).toHaveBeenCalledTimes(2);
    });

    it('ignores stale directory listing responses when navigating to a newer path before the earlier request resolves', async () => {
        render(<McBrowserTab />);
        const primaryTable = await screen.findByRole('table', { name: /Directory entries/i });

        const slowConfigsDeferred = createDeferred<McBrowserEntriesResponse>();

        mockedListEntries.mockReturnValueOnce(slowConfigsDeferred.promise);
        fireEvent.click(within(primaryTable).getByRole('button', { name: 'configs' }));
        expect(mockedListEntries).toHaveBeenLastCalledWith('configs', expect.any(AbortSignal));
        await act(async () => {
            slowConfigsDeferred.resolve({
                path: 'configs',
                entries: [
                    {
                        name: 'nested-dir',
                        path: 'configs/nested-dir',
                        kind: 'directory',
                        size: 0,
                        modified: '2026-10-20T10:00:00Z',
                    },
                ],
                max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            });
        });

        await waitFor(() => {
            expect(
                within(screen.getByRole('table', { name: /Directory entries/i })).getByRole(
                    'button',
                    { name: 'nested-dir' }
                )
            ).toBeInTheDocument();
        });
        const staleRefreshDeferred = createDeferred<McBrowserEntriesResponse>();
        const freshNestedDeferred = createDeferred<McBrowserEntriesResponse>();

        mockedListEntries
            .mockReturnValueOnce(staleRefreshDeferred.promise)
            .mockReturnValueOnce(freshNestedDeferred.promise);

        fireEvent.click(screen.getByRole('button', { name: /Refresh directory/i }));
        expect(mockedListEntries).toHaveBeenLastCalledWith('configs', expect.any(AbortSignal));
        fireEvent.click(
            within(screen.getByRole('table', { name: /Directory entries/i })).getByRole('button', {
                name: 'nested-dir',
            })
        );
        expect(mockedListEntries).toHaveBeenLastCalledWith(
            'configs/nested-dir',
            expect.any(AbortSignal)
        );
        await act(async () => {
            freshNestedDeferred.resolve({
                path: 'configs/nested-dir',
                entries: [
                    {
                        name: 'fresh-target.txt',
                        path: 'configs/nested-dir/fresh-target.txt',
                        kind: 'file',
                        size: 42,
                        modified: '2026-10-22T12:00:00Z',
                    },
                ],
                max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            });
        });

        await waitFor(() => {
            expect(
                within(screen.getByRole('table', { name: /Directory entries/i })).getByRole(
                    'button',
                    { name: 'fresh-target.txt' }
                )
            ).toBeInTheDocument();
        });
        await act(async () => {
            staleRefreshDeferred.resolve({
                path: 'configs',
                entries: [
                    {
                        name: 'stale-ghost.txt',
                        path: 'configs/stale-ghost.txt',
                        kind: 'file',
                        size: 99,
                        modified: '2026-10-20T00:00:00Z',
                    },
                ],
                max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            });
        });

        expect(
            within(screen.getByRole('table', { name: /Directory entries/i })).getByRole('button', {
                name: 'fresh-target.txt',
            })
        ).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'stale-ghost.txt' })).not.toBeInTheDocument();
        const breadcrumbNav = screen.getByRole('navigation', { name: /Breadcrumb/i });
        expect(within(breadcrumbNav).getByRole('button', { name: 'nested-dir' })).toHaveAttribute(
            'aria-current',
            'page'
        );
    });

    it('registers McBrowser in Sidebar NAVIGATION and switches activeTab in useSystemStore', () => {
        const mcBrowserNav = NAVIGATION.find((item) => item.id === 'mcbrowser');
        expect(mcBrowserNav).toBeDefined();
        expect(mcBrowserNav?.label).toBe('McBrowser');

        act(() => {
            useSystemStore.getState().setActiveTab('mcbrowser');
        });
        expect(useSystemStore.getState().activeTab).toBe('mcbrowser');
    });

    it('disables primary mutations and downloads when policy denies them', async () => {
        mockedFetchPolicy.mockResolvedValue({
            permissions: {
                read: true,
                create: false,
                rename: false,
                modify: false,
                delete: false,
                share: false,
                download: false,
            },
            rules: [],
            scope: '',
        });
        render(<McBrowserTab />);
        await within(await screen.findByRole('table', { name: 'Directory entries' })).findByRole('button', { name: 'alpha-notes.txt' });
        expect(screen.getByRole('button', { name: 'New Folder' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Upload Files' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Upload Folder' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Rename alpha-notes.txt' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Delete alpha-notes.txt' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Download alpha-notes.txt' })).toBeDisabled();
        fireEvent.drop(screen.getByRole('region', { name: 'McBrowser workspace' }), {
            dataTransfer: { files: [new File(['blocked'], 'blocked.txt')], items: [] },
        });
        expect(mockedUploadResumable).not.toHaveBeenCalled();
    });

    it('fails closed for primary actions when policy cannot be loaded', async () => {
        mockedFetchPolicy.mockRejectedValue(new Error('Policy unavailable'));
        render(<McBrowserTab />);
        await within(await screen.findByRole('table', { name: 'Directory entries' })).findByRole('button', { name: 'alpha-notes.txt' });
        expect(screen.getByRole('button', { name: 'New Folder' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Preview alpha-notes.txt' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'Download alpha-notes.txt' })).toBeDisabled();
    });

    it.each(
        (['file', 'symlink'] as const).flatMap((kind) =>
            ['photo.png', 'movie.mp4', 'audio.mp3', 'document.pdf', 'table.csv', 'book.epub'].map((name) => ({ kind, name }))
        )
    )('routes supported $kind $name to rich preview rather than the UTF-8 reader', async ({ kind, name }) => {
        const mediaEntry: McBrowserEntry = {
            name,
            path: name,
            kind,
            ...(kind === 'symlink' ? { target_kind: 'file' as const } : {}),
            size: 1024,
            modified: null,
        };
        mockedListEntries.mockResolvedValue({
            path: '',
            entries: [mediaEntry],
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        });
        render(<McBrowserTab />);
        const previewButton = await screen.findByRole('button', { name: `Preview ${name}` });
        await waitFor(() => expect(previewButton).toBeEnabled());
        fireEvent.click(previewButton);
        expect(screen.getByRole('dialog', { name: `Media preview ${name}` })).toBeInTheDocument();
        expect(mockedFetchPreview).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Close media preview' }));
        expect(screen.queryByRole('dialog', { name: `Media preview ${name}` })).not.toBeInTheDocument();
    });
});
