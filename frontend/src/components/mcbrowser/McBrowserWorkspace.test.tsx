import { TextEncoder, TextDecoder } from 'util';
import React from 'react';
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';

Object.assign(globalThis, { TextEncoder, TextDecoder });
import McBrowserWorkspace from '@/components/mcbrowser/McBrowserWorkspace';
import { dispatchMcBrowserAction } from '@/lib/mcbrowser-actions';
import {
    McBrowserEntry,
    McBrowserRequestError,
    renameMcBrowserEntry,
    deleteMcBrowserEntry,
} from '@/lib/mcbrowser';
import {
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
    revokeMcBrowserShare,
    saveMcBrowserContent,
    searchMcBrowserEntries,
    updateMcBrowserPreferences,
} from '@/lib/mcbrowser-workspace';

const mockAddToast = jest.fn();

jest.mock('@/lib/mcbrowser-actions', () => ({
    ...jest.requireActual('@/lib/mcbrowser-actions'),
    dispatchMcBrowserAction: jest.fn(),
}));

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
    }),
}));

jest.mock('@/lib/mcbrowser', () => {
    const actual = jest.requireActual('@/lib/mcbrowser');
    return {
        ...actual,
        renameMcBrowserEntry: jest.fn(),
        deleteMcBrowserEntry: jest.fn(),
    };
});

jest.mock('@/lib/mcbrowser-workspace', () => {
    const actual = jest.requireActual('@/lib/mcbrowser-workspace');
    return {
        ...actual,
        searchMcBrowserEntries: jest.fn(),
        copyMcBrowserEntry: jest.fn(),
        deleteMcBrowserRecursive: jest.fn(),
        fetchMcBrowserContent: jest.fn(),
        saveMcBrowserContent: jest.fn(),
        createMcBrowserFile: jest.fn(),
        fetchMcBrowserFileInfo: jest.fn(),
        listMcBrowserShares: jest.fn(),
        createMcBrowserShare: jest.fn(),
        revokeMcBrowserShare: jest.fn(),
        fetchMcBrowserPolicy: jest.fn(),
        fetchMcBrowserPreferences: jest.fn(),
        updateMcBrowserPreferences: jest.fn(),
        fetchMcBrowserUsage: jest.fn(),
        downloadMcBrowserArchive: jest.fn(),
    };
});

const mockedRename = renameMcBrowserEntry as jest.MockedFunction<typeof renameMcBrowserEntry>;
const mockedDelete = deleteMcBrowserEntry as jest.MockedFunction<typeof deleteMcBrowserEntry>;
const mockedSearch = searchMcBrowserEntries as jest.MockedFunction<typeof searchMcBrowserEntries>;
const mockedCopy = copyMcBrowserEntry as jest.MockedFunction<typeof copyMcBrowserEntry>;
const mockedDeleteRecursive = deleteMcBrowserRecursive as jest.MockedFunction<
    typeof deleteMcBrowserRecursive
>;
const mockedFetchContent = fetchMcBrowserContent as jest.MockedFunction<typeof fetchMcBrowserContent>;
const mockedSaveContent = saveMcBrowserContent as jest.MockedFunction<typeof saveMcBrowserContent>;
const mockedCreateFile = createMcBrowserFile as jest.MockedFunction<typeof createMcBrowserFile>;
const mockedFetchInfo = fetchMcBrowserFileInfo as jest.MockedFunction<typeof fetchMcBrowserFileInfo>;
const mockedListShares = listMcBrowserShares as jest.MockedFunction<typeof listMcBrowserShares>;
const mockedCreateShare = createMcBrowserShare as jest.MockedFunction<typeof createMcBrowserShare>;
const mockedRevokeShare = revokeMcBrowserShare as jest.MockedFunction<typeof revokeMcBrowserShare>;
const mockedFetchPolicy = fetchMcBrowserPolicy as jest.MockedFunction<typeof fetchMcBrowserPolicy>;
const mockedFetchPrefs = fetchMcBrowserPreferences as jest.MockedFunction<
    typeof fetchMcBrowserPreferences
>;
const mockedUpdatePrefs = updateMcBrowserPreferences as jest.MockedFunction<
    typeof updateMcBrowserPreferences
>;
const mockedFetchUsage = fetchMcBrowserUsage as jest.MockedFunction<typeof fetchMcBrowserUsage>;
const mockedDownloadArchive = downloadMcBrowserArchive as jest.MockedFunction<
    typeof downloadMcBrowserArchive
>;

const SAMPLE_ENTRIES: McBrowserEntry[] = [
    {
        name: 'configs',
        path: 'configs',
        kind: 'directory',
        size: 0,
        modified: '2026-10-15T10:00:00Z',
    },
    {
        name: 'server.properties',
        path: 'server.properties',
        kind: 'file',
        size: 1024,
        modified: '2026-10-20T14:30:00Z',
    },
    {
        name: '.hidden-env',
        path: '.hidden-env',
        kind: 'file',
        size: 256,
        modified: '2026-10-21T08:00:00Z',
    },
];

describe('McBrowserWorkspace Parity Component', () => {
    const mockOnRefresh = jest.fn();
    const mockOnNavigate = jest.fn();

    beforeEach(() => {
        jest.clearAllMocks();
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
        mockedUpdatePrefs.mockImplementation(async (prefs) => prefs);
        mockedFetchUsage.mockResolvedValue({
            used_bytes: 10 * 1024 * 1024,
            quota_bytes: 100 * 1024 * 1024,
            status: 'healthy',
        });
    });

    it('keeps a published save clean while warning about pending accounting', async () => {
        const file: McBrowserEntry = { name: 'notes.txt', path: 'notes.txt', kind: 'file', size: 8, modified: null };
        mockedFetchContent.mockResolvedValueOnce({ path: file.path, content: 'original', etag: 'v1' });
        mockedSaveContent.mockResolvedValueOnce({ success: true, etag: 'v2', accounting_pending: true });
        render(<McBrowserWorkspace currentPath="" entries={[file]} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'Edit notes.txt' })).toBeEnabled());
        fireEvent.click(screen.getByRole('button', { name: 'Edit notes.txt' }));
        const dialog = await screen.findByRole('dialog', { name: 'UTF-8 Editor: notes.txt' });
        const textarea = within(dialog).getByLabelText('UTF-8 File Content');
        await waitFor(() => expect(textarea).toHaveValue('original'));
        fireEvent.change(textarea, { target: { value: 'tiny' } });
        fireEvent.click(within(dialog).getByRole('button', { name: 'Save with ETag' }));
        await waitFor(() => expect(mockAddToast).toHaveBeenCalledWith(
            'Saved "notes.txt"; storage accounting requires reconciliation', 'info'
        ));
        await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Close editor dialog' })).toBeEnabled());
        fireEvent.click(within(dialog).getByRole('button', { name: 'Close editor dialog' }));
        expect(screen.queryByRole('dialog', { name: 'UTF-8 Editor: notes.txt' })).not.toBeInTheDocument();
        expect(mockedSaveContent).toHaveBeenCalledTimes(1);
        expect(mockOnRefresh).toHaveBeenCalledTimes(1);
    });

    it.each(['list', 'grid', 'gallery', 'mosaic'] as const)('shares confined aliases using requested paths in %s', async (view) => {
        localStorage.setItem('mcbrowser-view-mode', view);
        const entries: McBrowserEntry[] = [
            { name: 'file-alias.txt', path: 'file-alias.txt', kind: 'symlink', target_kind: 'file', size: 6, modified: null },
            { name: 'dir-alias', path: 'dir-alias', kind: 'symlink', target_kind: 'directory', size: 0, modified: null },
            { name: 'broken', path: 'broken', kind: 'symlink', size: 0, modified: null },
        ];
        mockedCreateShare.mockImplementation(async (request) => ({ share: {
            id: request.path, path: request.path, allow_download: true,
            created_at: '2026-11-02T00:00:00Z', expires_at: null, url: `/share?token=${request.path}`,
        } }));
        render(<McBrowserWorkspace currentPath="" entries={entries} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'Share file-alias.txt' })).toBeEnabled());
        for (const entry of entries.slice(0, 2)) {
            fireEvent.click(screen.getByRole('button', { name: `Share ${entry.name}` }));
            const dialog = await screen.findByRole('dialog', { name: /Manage Share Links/i });
            expect(within(dialog).getByLabelText(/Relative Path to Share/i)).toHaveValue(entry.path);
            fireEvent.click(within(dialog).getByRole('button', { name: /Create Share Link/i }));
            await waitFor(() => expect(mockedCreateShare).toHaveBeenLastCalledWith(expect.objectContaining({ path: entry.path })));
            await waitFor(() => expect(within(dialog).getByRole('button', { name: /Close share links dialog/i })).toBeEnabled());
            fireEvent.click(within(dialog).getByRole('button', { name: /Close share links dialog/i }));
        }
        expect(screen.queryByRole('button', { name: 'Share broken' })).not.toBeInTheDocument();
    });

    it.each(['list', 'grid', 'gallery', 'mosaic'] as const)('inspects confined aliases from %s without replacing their paths', async (view) => {
        mockedFetchPrefs.mockResolvedValueOnce({ view, sort: 'name', direction: 'asc', show_hidden: false, single_click: false, locale: 'en-US' });
        const file: McBrowserEntry = { name: 'file-alias.txt', path: 'file-alias.txt', kind: 'symlink', target_kind: 'file', size: 5, modified: null };
        const directory: McBrowserEntry = { name: 'dir-alias', path: 'dir-alias', kind: 'symlink', target_kind: 'directory', size: 0, modified: null };
        const broken: McBrowserEntry = { name: 'broken', path: 'broken', kind: 'symlink', size: 0, modified: null };
        mockedFetchInfo.mockResolvedValueOnce({ entry: { ...file, kind: 'file' }, checksums: { sha256: 'alias-digest' } });
        mockedFetchInfo.mockResolvedValueOnce({ entry: { ...directory, kind: 'directory' }, checksums: {}, num_files: 2, num_dirs: 1 });
        render(<McBrowserWorkspace currentPath="" entries={[file, directory, broken]} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'New File' })).toBeEnabled());
        fireEvent.click(screen.getByRole('button', { name: 'Info for file-alias.txt' }));
        const fileDialog = await screen.findByRole('dialog', { name: /Entry Info & Checksums: file-alias.txt/ });
        expect(await within(fileDialog).findByText('alias-digest')).toBeInTheDocument();
        expect(mockedFetchInfo).toHaveBeenLastCalledWith('file-alias.txt', 'sha256', expect.any(AbortSignal));
        fireEvent.click(within(fileDialog).getByRole('button', { name: /Close file info dialog/ }));
        fireEvent.click(screen.getByRole('button', { name: 'Info for dir-alias' }));
        const dirDialog = await screen.findByRole('dialog', { name: /Entry Info & Checksums: dir-alias/ });
        expect(await within(dirDialog).findByText('Visible files:')).toBeInTheDocument();
        expect(within(dirDialog).getByText('2')).toBeInTheDocument();
        expect(within(dirDialog).queryByLabelText('Checksum Algorithm')).not.toBeInTheDocument();
        expect(mockedFetchInfo).toHaveBeenLastCalledWith('dir-alias', null, expect.any(AbortSignal));
        expect(screen.queryByRole('button', { name: 'Info for broken' })).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Share file-alias.txt' })).toBeEnabled();
        expect(mockOnNavigate).not.toHaveBeenCalled();
    });

    it.each(['list', 'grid', 'gallery', 'mosaic'] as const)('edits confined file aliases through their requested paths in %s', async (view) => {
        mockedFetchPrefs.mockResolvedValueOnce({ view, sort: 'name', direction: 'asc', show_hidden: false, single_click: false, locale: 'en-US' });
        const file: McBrowserEntry = { name: 'alias.txt', path: 'folder/alias.txt', kind: 'symlink', target_kind: 'file', size: 8, modified: null };
        const directory: McBrowserEntry = { name: 'directory-alias', path: 'directory-alias', kind: 'symlink', target_kind: 'directory', size: 0, modified: null };
        const broken: McBrowserEntry = { name: 'broken', path: 'broken', kind: 'symlink', size: 0, modified: null };
        mockedFetchContent.mockResolvedValueOnce({ path: file.path, content: 'original', etag: 'alias-v1' });
        mockedSaveContent.mockResolvedValueOnce({ success: true, etag: 'alias-v2' });
        render(<McBrowserWorkspace currentPath="" entries={[file, directory, broken]} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'Edit alias.txt' })).toBeEnabled());
        expect(screen.queryByRole('button', { name: 'Edit directory-alias' })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Edit broken' })).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Edit alias.txt' }));
        const dialog = await screen.findByRole('dialog', { name: 'UTF-8 Editor: alias.txt' });
        const textarea = within(dialog).getByLabelText('UTF-8 File Content');
        await waitFor(() => expect(textarea).toHaveValue('original'));
        expect(within(dialog).getByRole('note')).toHaveTextContent('The alias itself is preserved');
        expect(mockedFetchContent).toHaveBeenCalledWith(file.path, expect.any(AbortSignal));
        fireEvent.change(textarea, { target: { value: 'changed alias target' } });
        fireEvent.click(within(dialog).getByRole('button', { name: 'Save with ETag' }));
        await waitFor(() => expect(mockedSaveContent).toHaveBeenCalledWith(file.path, 'changed alias target', 'alias-v1'));
        expect(mockedSaveContent).toHaveBeenCalledTimes(1);
        expect(mockOnNavigate).not.toHaveBeenCalled();
        expect(mockOnRefresh).toHaveBeenCalledTimes(1);
    });

    it.each(
        (['list', 'grid', 'gallery', 'mosaic'] as const).flatMap((view) =>
            (['title', 'single-click'] as const).map((activation) => ({ view, activation }))
        )
    )('activates confined file aliases by $activation in $view', async ({ view, activation }) => {
        mockedFetchPrefs.mockResolvedValueOnce({ view, sort: 'name', direction: 'asc', show_hidden: false, single_click: activation === 'single-click', locale: 'en-US' });
        const file: McBrowserEntry = { name: 'alias.txt', path: 'links/alias.txt', kind: 'symlink', target_kind: 'file', size: 8, modified: null };
        mockedFetchContent.mockResolvedValueOnce({ path: file.path, content: 'original', etag: 'alias-v1' });
        render(<McBrowserWorkspace currentPath="" entries={[file]} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'Edit alias.txt' })).toBeEnabled());
        if (view === 'list') {
            await screen.findByRole('table', { name: 'Workspace selection table' });
        } else {
            await screen.findByRole('list', { name: /Workspace (grid|gallery) entries/ });
        }
        if (activation === 'title') {
            fireEvent.click(screen.getByRole('button', { name: 'alias.txt' }));
        } else {
            const entry = screen.getByLabelText('Select alias.txt').closest('tr, [role="listitem"]');
            expect(entry).not.toBeNull();
            fireEvent.click(entry!);
        }
        const dialog = await screen.findByRole('dialog', { name: 'UTF-8 Editor: alias.txt' });
        await waitFor(() => expect(within(dialog).getByLabelText('UTF-8 File Content')).toHaveValue('original'));
        expect(mockedFetchContent).toHaveBeenCalledTimes(1);
        expect(mockedFetchContent).toHaveBeenCalledWith(file.path, expect.any(AbortSignal));
        expect(mockOnNavigate).not.toHaveBeenCalled();
    });

    it('keeps alias editor permission failures and stale ETags fail closed', async () => {
        const file: McBrowserEntry = { name: 'alias.txt', path: 'alias.txt', kind: 'symlink', target_kind: 'file', size: 8, modified: null };
        mockedFetchContent.mockRejectedValueOnce(new McBrowserRequestError(403, 'FORBIDDEN', 'Alias target is denied'));
        render(<McBrowserWorkspace currentPath="" entries={[file]} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'Edit alias.txt' })).toBeEnabled());
        fireEvent.click(screen.getByRole('button', { name: 'Edit alias.txt' }));
        const dialog = await screen.findByRole('dialog', { name: 'UTF-8 Editor: alias.txt' });
        expect(await within(dialog).findByRole('alert')).toHaveTextContent('Alias target is denied');
        expect(within(dialog).getByRole('button', { name: 'Save with ETag' })).toBeDisabled();
        mockedFetchContent.mockResolvedValueOnce({ path: file.path, content: 'original', etag: 'alias-v1' });
        fireEvent.click(within(dialog).getByRole('button', { name: 'Reload from Server' }));
        const textarea = await within(dialog).findByLabelText('UTF-8 File Content');
        await waitFor(() => expect(textarea).toHaveValue('original'));
        mockedSaveContent.mockRejectedValueOnce(new McBrowserRequestError(409, 'ETAG_CONFLICT', 'Alias target changed'));
        fireEvent.change(textarea, { target: { value: 'draft' } });
        fireEvent.click(within(dialog).getByRole('button', { name: 'Save with ETag' }));
        expect(await within(dialog).findByRole('alert')).toHaveTextContent('Alias target changed');
        expect(textarea).toHaveValue('draft');
        expect(mockedSaveContent).toHaveBeenCalledTimes(1);
        expect(mockOnRefresh).not.toHaveBeenCalled();
    });

    it.each(['read', 'modify'] as const)('enforces %s permission on confined alias editing', async (denied) => {
        mockedFetchPolicy.mockResolvedValueOnce({ permissions: { read: denied !== 'read', create: true, rename: true, modify: denied !== 'modify', delete: true, share: true, download: true }, rules: [], scope: '' });
        mockedFetchContent.mockResolvedValue({ path: 'alias.txt', content: 'read-only target', etag: 'alias-v1' });
        const file: McBrowserEntry = { name: 'alias.txt', path: 'alias.txt', kind: 'symlink', target_kind: 'file', size: 16, modified: null };
        render(<McBrowserWorkspace currentPath="" entries={[file]} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'New File' })).toBeEnabled());
        const edit = screen.getByRole('button', { name: 'Edit alias.txt' });
        if (denied === 'read') {
            expect(edit).toBeDisabled();
            fireEvent.click(edit);
            expect(mockedFetchContent).not.toHaveBeenCalled();
        } else {
            fireEvent.click(edit);
            const dialog = await screen.findByRole('dialog', { name: 'UTF-8 Editor: alias.txt' });
            await waitFor(() => expect(within(dialog).getByLabelText('UTF-8 File Content')).toHaveValue('read-only target'));
            expect(within(dialog).getByLabelText('UTF-8 File Content')).toHaveAttribute('readonly');
            expect(within(dialog).getByRole('button', { name: 'Save with ETag' })).toBeDisabled();
        }
        expect(mockedSaveContent).not.toHaveBeenCalled();
    });

    it('scopes selection, search, rename and delete shortcuts without mutating on keypress', async () => {
        const onRename = jest.fn();
        render(<McBrowserWorkspace currentPath="" entries={SAMPLE_ENTRIES}
            onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} onRename={onRename} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'New File' })).toBeEnabled());
        const workspace = screen.getByRole('region', { name: 'Advanced file actions and workspace explorer' });
        const file = screen.getByRole('checkbox', { name: 'Select server.properties' });
        const query = screen.getByRole('searchbox', { name: 'Recursive search query' });

        fireEvent.keyDown(query, { key: 'a', ctrlKey: true });
        expect(file).not.toBeChecked();
        fireEvent.keyDown(workspace, { key: 'a', ctrlKey: true });
        expect(file).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'Select configs' })).toBeChecked();
        fireEvent.keyDown(workspace, { key: 'Escape' });
        expect(file).not.toBeChecked();
        fireEvent.click(file);
        fireEvent.keyDown(workspace, { key: 'F2' });
        expect(onRename).toHaveBeenCalledWith(SAMPLE_ENTRIES[1]);
        fireEvent.keyDown(workspace, { key: 'F', metaKey: true, shiftKey: true });
        expect(query).toHaveFocus();
        fireEvent.keyDown(workspace, { key: 'Delete' });
        expect(screen.getByRole('dialog')).toBeInTheDocument();
        expect(mockedDelete).not.toHaveBeenCalled();
        fireEvent.keyDown(workspace, { key: 'Escape' });
        expect(file).toBeChecked();
    });

    it('does not bypass operation permissions through keyboard shortcuts', async () => {
        mockedFetchPolicy.mockResolvedValueOnce({
            permissions: { read: true, create: false, rename: false, modify: false,
                delete: false, share: false, download: false, execute: false },
            rules: [], scope: '',
        });
        const onRename = jest.fn();
        render(<McBrowserWorkspace currentPath="" entries={SAMPLE_ENTRIES}
            onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} onRename={onRename} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'Search Server' })).toBeEnabled());
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select server.properties' }));
        const workspace = screen.getByRole('region', { name: 'Advanced file actions and workspace explorer' });
        for (const key of ['c', 'x', 'v', 's']) fireEvent.keyDown(workspace, { key, ctrlKey: true });
        for (const key of ['Delete', 'F2']) fireEvent.keyDown(workspace, { key });
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Paste into current folder' })).not.toBeInTheDocument();
        expect(mockedDownloadArchive).not.toHaveBeenCalled();
        expect(mockedDelete).not.toHaveBeenCalled();
        expect(onRename).not.toHaveBeenCalled();
    });

    it('extends checkbox selection over the displayed range while excluding unsupported entries', async () => {
        const entries: McBrowserEntry[] = [
            ...['a.txt', 'b.txt', 'c.txt'].map((name) => ({ name, path: name, kind: 'file' as const, size: 1, modified: null })),
            { name: 'b-special', path: 'b-special', kind: 'other', size: 0, modified: null },
        ];
        render(<McBrowserWorkspace currentPath="" entries={entries}
            onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'New File' })).toBeEnabled());
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select a.txt' }));
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select c.txt' }), { shiftKey: true });
        expect(screen.getByRole('checkbox', { name: 'Select b.txt' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'Select c.txt' })).toBeChecked();
        expect(screen.getByRole('checkbox', { name: 'Select b-special' })).not.toBeChecked();
    });

    it('keeps cut sources across folder navigation and clears only successful clipboard moves', async () => {
        const view = render(<McBrowserWorkspace currentPath="" entries={SAMPLE_ENTRIES}
            onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'New File' })).toBeEnabled());
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select server.properties' }));
        fireEvent.keyDown(screen.getByRole('region', { name: 'Advanced file actions and workspace explorer' }),
            { key: 'x', ctrlKey: true });
        expect(mockedRename).not.toHaveBeenCalled();

        view.rerender(<McBrowserWorkspace currentPath="backups" entries={[]}
            onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        fireEvent.click(screen.getByRole('button', { name: 'Paste into current folder' }));
        fireEvent.click(screen.getByRole('button', { name: 'Confirm Batch Move (1)' }));
        await waitFor(() => expect(mockedRename).toHaveBeenCalledWith('server.properties', 'backups/server.properties'));
        await waitFor(() => expect(screen.queryByRole('button', { name: 'Paste into current folder' })).not.toBeInTheDocument());
    });

    it('uses keep-both for same-folder clipboard copy and does not intercept editor typing', async () => {
        render(<McBrowserWorkspace currentPath="" entries={SAMPLE_ENTRIES}
            onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'New File' })).toBeEnabled());
        fireEvent.click(screen.getByRole('checkbox', { name: 'Select server.properties' }));
        const workspace = screen.getByRole('region', { name: 'Advanced file actions and workspace explorer' });
        fireEvent.keyDown(workspace, { key: 'c', metaKey: true });
        fireEvent.keyDown(workspace, { key: 'v', metaKey: true });
        expect(screen.getByRole('combobox', { name: 'Conflict Resolution Policy' })).toHaveValue('keep-both');
        fireEvent.keyDown(screen.getByRole('textbox', { name: 'Destination Relative Directory (empty for My files root)' }),
            { key: 'Delete' });
        expect(mockedDelete).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole('button', { name: 'Confirm Batch Copy (1)' }));
        await waitFor(() => expect(mockedCopy).toHaveBeenCalledWith('server.properties', 'server.properties', 'keep-both'));
    });

    it('mounts native actions with a default-off Execute gate and all archive codecs', async () => {
        render(<McBrowserWorkspace currentPath="" entries={SAMPLE_ENTRIES}
            onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByRole('button', { name: 'New File' })).toBeEnabled());
        fireEvent.click(screen.getByRole('button', { name: 'Safe Built-In Actions' }));
        expect(screen.getByTestId('mcbrowser-actions-execute-gate')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Run Native Action' })).toBeDisabled();
        const format = screen.getByLabelText('Archive format');
        expect(within(format).getAllByRole('option')).toHaveLength(9);
        expect(dispatchMcBrowserAction).not.toHaveBeenCalled();
    });

    it('dispatches an enabled native action from the real workspace panel', async () => {
        mockedFetchPolicy.mockResolvedValueOnce({
            permissions: { read: true, create: true, rename: true, modify: true, delete: true,
                share: true, download: true, execute: true },
            rules: [], scope: '',
        });
        jest.mocked(dispatchMcBrowserAction).mockResolvedValueOnce({
            action: 'compute_checksums', success: true, path: 'server.properties', size: 1024,
            checksums: { sha256: 'verified-digest' },
        });
        render(<McBrowserWorkspace currentPath="" entries={SAMPLE_ENTRIES}
            onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByLabelText('Select server.properties')).toBeEnabled());
        fireEvent.click(screen.getByLabelText('Select server.properties'));
        fireEvent.click(screen.getByRole('button', { name: 'Safe Built-In Actions' }));
        fireEvent.click(screen.getByRole('button', { name: 'Run Native Action' }));
        await screen.findByText('verified-digest');
        expect(dispatchMcBrowserAction).toHaveBeenCalledWith(
            expect.objectContaining({ action: 'compute_checksums', path: 'server.properties' }),
            expect.anything(),
        );
    });

    it('refreshes quota when directory results change and ignores stale usage responses', async () => {
        let resolveInitial: ((usage: Awaited<ReturnType<typeof fetchMcBrowserUsage>>) => void) | undefined;
        mockedFetchUsage.mockImplementationOnce(() => new Promise((resolve) => { resolveInitial = resolve; }));
        const { rerender } = render(<McBrowserWorkspace currentPath="" entries={[]} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(mockedFetchUsage).toHaveBeenCalledTimes(1));
        mockedFetchUsage.mockResolvedValueOnce({ used_bytes: 2097152, quota_bytes: 1073741824, status: 'active' });
        rerender(<McBrowserWorkspace currentPath="" entries={SAMPLE_ENTRIES} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByLabelText('Storage quota usage')).toHaveTextContent('2 MiB / 1 GiB'));
        await act(async () => { resolveInitial?.({ used_bytes: 0, quota_bytes: 1073741824, status: 'active' }); });
        expect(screen.getByLabelText('Storage quota usage')).toHaveTextContent('2 MiB / 1 GiB');
        mockedFetchUsage.mockRejectedValueOnce(new Error('Quota service unavailable'));
        rerender(<McBrowserWorkspace currentPath="" entries={[...SAMPLE_ENTRIES]} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.queryByLabelText('Storage quota usage')).not.toBeInTheDocument());
        expect(screen.getByText(/Metadata notice: Quota service unavailable/)).toBeInTheDocument();
        mockedFetchUsage.mockResolvedValueOnce({ used_bytes: 1048576, quota_bytes: 1073741824, status: 'active' });
        rerender(<McBrowserWorkspace currentPath="docs" entries={SAMPLE_ENTRIES} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await waitFor(() => expect(screen.getByLabelText('Storage quota usage')).toHaveTextContent('1 MiB / 1 GiB'));
        expect(screen.queryByText(/Quota service unavailable/)).not.toBeInTheDocument();
    });

    it('loads policy, preferences, and usage and toggles hidden files & grid view', async () => {
        render(
            <McBrowserWorkspace
                currentPath=""
                entries={SAMPLE_ENTRIES}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await screen.findByLabelText('Storage quota usage');
        expect(screen.getByText(/10 MiB \/ 100 MiB \(10%\)/i)).toBeInTheDocument();

        // Hidden file is initially filtered out because show_hidden=false
        expect(screen.queryByRole('button', { name: '.hidden-env' })).not.toBeInTheDocument();

        // Toggle hidden files on
        fireEvent.click(screen.getByRole('button', { name: /Toggle hidden files/i }));
        await waitFor(() => {
            expect(mockedUpdatePrefs).toHaveBeenCalledWith(
                expect.objectContaining({ show_hidden: true })
            );
        });
        expect(screen.getByRole('button', { name: '.hidden-env' })).toBeInTheDocument();

        // Switch to grid view
        fireEvent.click(screen.getByRole('button', { name: /Grid view/i }));
        await waitFor(() => {
            expect(
                screen.getByRole('list', { name: /Workspace grid entries/i })
            ).toBeInTheDocument();
        });
    });

    it('creates a new file and triggers onRefresh', async () => {
        mockedCreateFile.mockResolvedValueOnce({ success: true });

        render(
            <McBrowserWorkspace
                currentPath="configs"
                entries={SAMPLE_ENTRIES}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await screen.findByRole('button', { name: /New File/i });
        fireEvent.click(screen.getByRole('button', { name: /New File/i }));

        const dialog = screen.getByRole('dialog', { name: /Create New UTF-8 File/i });
        fireEvent.change(within(dialog).getByLabelText(/File Name/i), {
            target: { value: 'whitelist.json' },
        });
        fireEvent.change(within(dialog).getByLabelText(/Initial UTF-8 Content/i), {
            target: { value: '[]' },
        });

        fireEvent.click(within(dialog).getByRole('button', { name: /^Create File$/i }));

        await waitFor(() => {
            expect(mockedCreateFile).toHaveBeenCalledWith('configs/whitelist.json', '[]');
        });
        expect(mockOnRefresh).toHaveBeenCalledTimes(1);
    });

    it('opens UTF-8 editor, saves with ETag, and handles stale ETag conflict recovery', async () => {
        const maliciousContent = '<script>window.evil=true</script>motd=Test';
        mockedFetchContent.mockResolvedValueOnce({
            path: 'server.properties',
            content: maliciousContent,
            etag: 'etag-100',
        });

        render(
            <McBrowserWorkspace
                currentPath=""
                entries={SAMPLE_ENTRIES}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await screen.findByRole('button', { name: 'Edit server.properties' });
        fireEvent.click(screen.getByRole('button', { name: 'Edit server.properties' }));

        const dialog = await screen.findByRole('dialog', {
            name: /UTF-8 Editor: server\.properties/i,
        });
        const textarea = within(dialog).getByLabelText('UTF-8 File Content') as HTMLTextAreaElement;
        expect(textarea.value).toBe(maliciousContent);
        expect(dialog.querySelector('script')).toBeNull();

        // Simulate stale ETag 409 conflict on first save
        mockedSaveContent.mockRejectedValueOnce(
            new McBrowserRequestError(409, 'ETAG_CONFLICT', 'ETag mismatch')
        );

        fireEvent.change(textarea, { target: { value: 'motd=Updated' } });
        fireEvent.click(within(dialog).getByRole('button', { name: /Save with ETag/i }));

        await waitFor(() => {
            expect(within(dialog).getByRole('alert')).toHaveTextContent(/ETag mismatch/i);
        });
        expect(
            within(dialog).getByRole('button', { name: /Reload Latest Server Version/i })
        ).toBeInTheDocument();

        // Reload and save successfully
        mockedFetchContent.mockResolvedValueOnce({
            path: 'server.properties',
            content: 'motd=ServerNew',
            etag: 'etag-200',
        });
        fireEvent.click(
            within(dialog).getByRole('button', { name: /Reload Latest Server Version/i })
        );
        fireEvent.click(within(dialog).getByRole('button', { name: 'Discard changes' }));

        await waitFor(() => {
            expect(
                (within(dialog).getByLabelText('UTF-8 File Content') as HTMLTextAreaElement).value
            ).toBe('motd=ServerNew');
        });

        mockedSaveContent.mockResolvedValueOnce({
            success: true,
            etag: 'etag-201',
        });
        fireEvent.click(within(dialog).getByRole('button', { name: /Save with ETag/i }));

        await waitFor(() => {
            expect(mockedSaveContent).toHaveBeenLastCalledWith(
                'server.properties',
                'motd=ServerNew',
                'etag-200'
            );
        });
        expect(mockOnRefresh).toHaveBeenCalled();
    });

    it('protects unsaved editor content on close and browser unload until explicit discard', async () => {
        mockedFetchContent.mockResolvedValueOnce({
            path: 'server.properties', content: 'original', etag: 'initial-etag',
        });
        render(<McBrowserWorkspace currentPath="" entries={SAMPLE_ENTRIES} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        fireEvent.click(await screen.findByRole('button', { name: 'Edit server.properties' }));
        const dialog = await screen.findByRole('dialog', { name: /UTF-8 Editor: server\.properties/i });
        const textbox = await within(dialog).findByLabelText('UTF-8 File Content');
        fireEvent.change(textbox, { target: { value: 'unsaved' } });
        const beforeUnload = new Event('beforeunload', { cancelable: true });
        expect(window.dispatchEvent(beforeUnload)).toBe(false);
        fireEvent.click(within(dialog).getByRole('button', { name: 'Close editor dialog' }));
        expect(within(dialog).getByText('Unsaved changes will be lost. Discard them?')).toBeInTheDocument();
        fireEvent.click(within(dialog).getByRole('button', { name: 'Keep editing' }));
        expect(textbox).toHaveValue('unsaved');
        fireEvent.click(within(dialog).getByRole('button', { name: 'Close editor dialog' }));
        fireEvent.click(within(dialog).getByRole('button', { name: 'Discard changes' }));
        expect(screen.queryByRole('dialog', { name: /UTF-8 Editor:/i })).not.toBeInTheDocument();
        expect(window.dispatchEvent(new Event('beforeunload', { cancelable: true }))).toBe(true);
        expect(mockedSaveContent).not.toHaveBeenCalled();
    });

    it('connects editor toolbar saves to ETags and admits only one pending save', async () => {
        mockedFetchContent.mockResolvedValueOnce({
            path: 'server.properties', content: 'original', etag: 'initial-etag',
        });
        let completeSave: ((result: { success: boolean; etag: string }) => void) | undefined;
        mockedSaveContent.mockImplementationOnce(() => new Promise((resolve) => { completeSave = resolve; }));
        render(<McBrowserWorkspace currentPath="" entries={SAMPLE_ENTRIES} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        fireEvent.click(await screen.findByRole('button', { name: 'Edit server.properties' }));
        const dialog = await screen.findByRole('dialog', { name: /UTF-8 Editor: server\.properties/i });
        const textbox = await within(dialog).findByLabelText('UTF-8 File Content');
        fireEvent.change(textbox, { target: { value: 'edited' } });
        fireEvent.click(within(dialog).getByRole('button', { name: 'Trigger editor save' }));
        const form = within(dialog).getByRole('button', { name: /Save with ETag/i }).closest('form');
        expect(form).not.toBeNull();
        fireEvent.submit(form!);
        fireEvent.submit(form!);
        expect(mockedSaveContent).toHaveBeenCalledTimes(1);
        expect(mockedSaveContent).toHaveBeenCalledWith('server.properties', 'edited', 'initial-etag');
        expect(textbox).toBeDisabled();
        await act(async () => { completeSave?.({ success: true, etag: 'saved-etag' }); });
        expect(textbox).not.toBeDisabled();
        fireEvent.click(within(dialog).getByRole('button', { name: 'Close editor dialog' }));
        expect(screen.queryByRole('dialog', { name: /UTF-8 Editor:/i })).not.toBeInTheDocument();
    });

    it('performs recursive server search with FlowAI natural language pairing, type filter, and truncation status', async () => {
        mockedSearch.mockResolvedValueOnce({
            entries: [
                {
                    name: 'deep.txt',
                    path: 'configs/nested/deep.txt',
                    kind: 'file',
                    size: 42,
                    modified: '2026-10-25T00:00:00Z',
                },
            ],
            truncated: true,
            ai_interpretation: 'FlowAI smart search: matching "deep" · file types [txt]',
            ai_powered: true,
        });

        render(
            <McBrowserWorkspace
                currentPath="configs"
                entries={SAMPLE_ENTRIES}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await screen.findByLabelText('Recursive search query');
        expect(screen.getByRole('button', { name: 'Toggle FlowAI natural language search' })).toHaveAttribute('aria-pressed', 'true');
        fireEvent.change(screen.getByLabelText('Recursive search query'), {
            target: { value: 'deep' },
        });
        fireEvent.change(screen.getByLabelText('Search entry type'), {
            target: { value: 'file' },
        });
        fireEvent.click(screen.getByRole('button', { name: /Search Server/i }));

        await waitFor(() => {
            expect(mockedSearch).toHaveBeenCalledWith(
                { path: 'configs', q: 'deep', type: 'file', ai: true },
                expect.any(AbortSignal)
            );
        });

        expect(await screen.findByRole('button', { name: 'deep.txt' })).toBeInTheDocument();
        expect(screen.getByText(/FlowAI smart search: matching "deep"/i)).toBeInTheDocument();
        expect(screen.getByText(/Results truncated by server limit/i)).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Clear Search/i }));
        expect(screen.getByRole('button', { name: 'server.properties' })).toBeInTheDocument();
    });

    it('executes batch copy/move/delete with explicit confirmation and preserves failed items on partial conflict', async () => {
        mockedCopy
            .mockResolvedValueOnce({ success: true })
            .mockRejectedValueOnce(
                new McBrowserRequestError(409, 'CONFLICT', 'Destination file already exists')
            );
        mockedRename.mockResolvedValueOnce({ success: true });
        mockedDeleteRecursive.mockResolvedValueOnce({ success: true });
        mockedDelete.mockResolvedValueOnce({ success: true });

        render(
            <McBrowserWorkspace
                currentPath=""
                entries={SAMPLE_ENTRIES}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await screen.findByLabelText('Select configs');
        fireEvent.click(screen.getByLabelText('Select configs'));
        fireEvent.click(screen.getByLabelText('Select server.properties'));

        fireEvent.click(screen.getByRole('button', { name: /Batch Copy/i }));

        const dialog = screen.getByRole('dialog', { name: /Confirm Batch copy/i });
        fireEvent.change(
            within(dialog).getByLabelText(/Destination Relative Directory/i),
            { target: { value: 'archive' } }
        );
        fireEvent.click(within(dialog).getByRole('button', { name: /Confirm Batch Copy \(2\)/i }));

        await waitFor(() => {
            expect(mockedCopy).toHaveBeenCalledTimes(2);
        });
        expect(mockedCopy).toHaveBeenNthCalledWith(1, 'configs', 'archive/configs');
        expect(mockedCopy).toHaveBeenNthCalledWith(
            2,
            'server.properties',
            'archive/server.properties'
        );

        const outcomesRegion = within(dialog).getByRole('region', {
            name: /Batch operation outcomes/i,
        });
        expect(within(outcomesRegion).getByText(/SUCCESS: Copied to archive\/configs/i)).toBeInTheDocument();
        expect(
            within(outcomesRegion).getByText(/CONFLICT: Destination file already exists/i)
        ).toBeInTheDocument();

        // Failed item remains selected, succeeded item is deselected
        expect(
            within(dialog).getByRole('button', { name: /Confirm Batch Copy \(1\)/i })
        ).toBeInTheDocument();

        fireEvent.click(within(dialog).getByRole('button', { name: /^Close$/i }));

        // Batch Move remaining selected item
        fireEvent.click(screen.getByRole('button', { name: /Batch Move/i }));
        const moveDialog = screen.getByRole('dialog', { name: /Confirm Batch move/i });
        fireEvent.change(
            within(moveDialog).getByLabelText(/Destination Relative Directory/i),
            { target: { value: 'moved' } }
        );
        fireEvent.click(within(moveDialog).getByRole('button', { name: /Confirm Batch Move \(1\)/i }));
        await waitFor(() => {
            expect(mockedRename).toHaveBeenCalledWith('server.properties', 'moved/server.properties');
        });
        fireEvent.click(within(moveDialog).getByRole('button', { name: /^Close$/i }));

        // Batch Delete both directory (recursive) and file
        fireEvent.click(screen.getByLabelText('Select configs'));
        fireEvent.click(screen.getByLabelText('Select server.properties'));
        fireEvent.click(screen.getByRole('button', { name: /Batch Delete/i }));
        const deleteDialog = screen.getByRole('dialog', { name: /Confirm Batch delete/i });
        fireEvent.click(within(deleteDialog).getByRole('button', { name: /Confirm Batch Delete \(2\)/i }));
        await waitFor(() => {
            expect(mockedDeleteRecursive).toHaveBeenCalledWith('configs');
            expect(mockedDelete).toHaveBeenCalledWith('server.properties');
        });
    });

    it('inspects file info and checksums, manages share links, downloads archives, and honors policy restrictions', async () => {
        mockedFetchInfo.mockResolvedValueOnce({
            entry: SAMPLE_ENTRIES[1],
            checksums: { sha256: 'abc123sha256' },
        });
        mockedListShares.mockResolvedValueOnce({
            shares: [
                {
                    id: 'share-10',
                    path: 'server.properties',
                    expires_at: null,
                    allow_download: true,
                    created_at: '2026-11-01T00:00:00Z',
                    url: 'https://aetherflow.local/s/share-10',
                },
            ],
        });
        mockedCreateShare.mockResolvedValueOnce({
            share: {
                id: 'share-11',
                path: 'configs',
                expires_at: '2026-12-31T00:00:00Z',
                allow_download: false,
                created_at: '2026-11-01T01:00:00Z',
                url: 'https://aetherflow.local/s/share-11',
            },
        });
        mockedRevokeShare.mockResolvedValueOnce({ success: true });
        mockedDownloadArchive.mockResolvedValueOnce({
            filename: 'mcbrowser-archive.zip',
            bytesWritten: 2048,
            method: 'filesystem-access',
        });

        render(
            <McBrowserWorkspace
                currentPath=""
                entries={SAMPLE_ENTRIES}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await screen.findByRole('button', { name: 'Info for server.properties' });
        fireEvent.click(screen.getByRole('button', { name: 'Info for server.properties' }));

        const infoDialog = await screen.findByRole('dialog', {
            name: /Entry Info & Checksums: server\.properties/i,
        });
        expect(await within(infoDialog).findByText('abc123sha256')).toBeInTheDocument();
        fireEvent.click(within(infoDialog).getByRole('button', { name: /Close file info dialog/i }));

        // Share Links
        fireEvent.click(screen.getByRole('button', { name: /Share Links/i }));
        const sharesDialog = await screen.findByRole('dialog', { name: /Manage Share Links/i });
        expect(await within(sharesDialog).findByText('https://aetherflow.local/s/share-10')).toBeInTheDocument();

        fireEvent.change(within(sharesDialog).getByLabelText(/Relative Path to Share/i), {
            target: { value: 'configs' },
        });
        fireEvent.click(within(sharesDialog).getByRole('button', { name: /Create Share Link/i }));
        expect(await within(sharesDialog).findByText('https://aetherflow.local/s/share-11')).toBeInTheDocument();

        fireEvent.click(within(sharesDialog).getByRole('button', { name: /Revoke share server\.properties/i }));
        await waitFor(() => {
            expect(mockedRevokeShare).toHaveBeenCalledWith('share-10');
        });
        fireEvent.click(within(sharesDialog).getByRole('button', { name: /Close share links dialog/i }));

        // Archive Download
        fireEvent.click(screen.getByLabelText('Select server.properties'));
        fireEvent.click(screen.getByRole('button', { name: /Download Archive/i }));
        await waitFor(() => {
            expect(mockedDownloadArchive).toHaveBeenCalledWith(
                ['server.properties'],
                'zip',
                expect.objectContaining({ signal: expect.any(AbortSignal) })
            );
        });
    });

    it('disables mutation and share buttons when workspace policy denies permissions', async () => {
        mockedFetchPolicy.mockResolvedValueOnce({
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
            scope: 'Read-only scope',
        });

        render(
            <McBrowserWorkspace
                currentPath=""
                entries={SAMPLE_ENTRIES}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await screen.findByText(/Scope: Read-only scope/i);
        expect(screen.getByRole('button', { name: /New File/i })).toBeDisabled();
        expect(screen.getByRole('button', { name: /Share Links/i })).toBeDisabled();
        expect(screen.getByRole('button', { name: /Download Archive/i })).toBeDisabled();
    });

    it('consumes gallery view (including mosaic gallery alias), natural sort, exact date format, locale, and editor theme preferences', async () => {
        mockedFetchPrefs.mockResolvedValueOnce({
            view: 'mosaic gallery' as unknown as 'gallery',
            sort: 'name',
            direction: 'asc',
            show_hidden: false,
            single_click: false,
            natural_sort: true,
            redirect_after_copy_move: false,
            date_format: true,
            editor_theme: 'monokai',
            locale: 'de',
        });

        const numericEntries: McBrowserEntry[] = [
            {
                name: 'file10.txt',
                path: 'file10.txt',
                kind: 'file',
                size: 100,
                modified: '2026-10-20T14:30:00Z',
            },
            {
                name: 'file2.txt',
                path: 'file2.txt',
                kind: 'file',
                size: 100,
                modified: '2026-10-20T14:30:00Z',
            },
        ];

        render(
            <McBrowserWorkspace
                currentPath=""
                entries={numericEntries}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        const galleryList = await screen.findByRole('list', {
            name: /Workspace gallery entries/i,
        });
        expect(galleryList).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Gallery view/i })).toHaveAttribute(
            'aria-pressed',
            'true'
        );

        const itemsNatural = within(galleryList).getAllByRole('listitem');
        expect(within(itemsNatural[0]).getByRole('button', { name: 'file2.txt' })).toBeInTheDocument();
        expect(within(itemsNatural[1]).getByRole('button', { name: 'file10.txt' })).toBeInTheDocument();

        expect(within(itemsNatural[0]).getByText('2026-10-20 14:30:00 UTC')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Toggle natural sort/i }));
        await waitFor(() => {
            expect(mockedUpdatePrefs).toHaveBeenCalledWith(
                expect.objectContaining({ natural_sort: false })
            );
        });

        const itemsAscii = within(
            screen.getByRole('list', { name: /Workspace gallery entries/i })
        ).getAllByRole('listitem');
        expect(within(itemsAscii[0]).getByRole('button', { name: 'file10.txt' })).toBeInTheDocument();
        expect(within(itemsAscii[1]).getByRole('button', { name: 'file2.txt' })).toBeInTheDocument();

        mockedFetchContent.mockResolvedValueOnce({
            path: 'file2.txt',
            content: 'hello=world',
            etag: 'etag-1',
        });
        fireEvent.click(screen.getByRole('button', { name: 'Edit file2.txt' }));
        const editorDialog = await screen.findByRole('dialog', {
            name: /UTF-8 Editor: file2\.txt/i,
        });
        const textarea = within(editorDialog).getByLabelText('UTF-8 File Content');
        expect(textarea).toHaveAttribute('data-editor-theme', 'monokai');

        fireEvent.change(within(editorDialog).getByLabelText('Editor theme'), {
            target: { value: 'dracula' },
        });
        await waitFor(() => {
            expect(mockedUpdatePrefs).toHaveBeenCalledWith(
                expect.objectContaining({ editor_theme: 'dracula' })
            );
        });
        expect(within(editorDialog).getByLabelText('UTF-8 File Content')).toHaveAttribute(
            'data-editor-theme',
            'dracula'
        );
    });

    it('preserves leading/trailing whitespace in batch destination directory and redirects only after wholly successful copy/move when enabled', async () => {
        mockedFetchPrefs.mockResolvedValueOnce({
            view: 'list',
            sort: 'name',
            direction: 'asc',
            show_hidden: false,
            single_click: false,
            natural_sort: true,
            redirect_after_copy_move: true,
            date_format: false,
            editor_theme: 'chrome',
            locale: 'en-US',
        });

        mockedCopy
            .mockResolvedValueOnce({ success: true })
            .mockRejectedValueOnce(new McBrowserRequestError(409, 'CONFLICT', 'Exists'))
            .mockResolvedValueOnce({ success: true });

        render(
            <McBrowserWorkspace
                currentPath=""
                entries={SAMPLE_ENTRIES}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await screen.findByLabelText('Select configs');
        fireEvent.click(screen.getByLabelText('Select configs'));
        fireEvent.click(screen.getByLabelText('Select server.properties'));

        fireEvent.click(screen.getByRole('button', { name: /Batch Copy/i }));
        const dialog = screen.getByRole('dialog', { name: /Confirm Batch copy/i });
        fireEvent.change(
            within(dialog).getByLabelText(/Destination Relative Directory/i),
            { target: { value: '  spaced folder  ' } }
        );
        fireEvent.click(within(dialog).getByRole('button', { name: /Confirm Batch Copy \(2\)/i }));

        await waitFor(() => {
            expect(mockedCopy).toHaveBeenCalledTimes(2);
        });
        expect(mockedCopy).toHaveBeenNthCalledWith(1, 'configs', '  spaced folder  /configs');
        expect(mockedCopy).toHaveBeenNthCalledWith(
            2,
            'server.properties',
            '  spaced folder  /server.properties'
        );
        expect(mockOnNavigate).not.toHaveBeenCalled();

        fireEvent.click(within(dialog).getByRole('button', { name: /Confirm Batch Copy \(1\)/i }));
        await waitFor(() => {
            expect(mockedCopy).toHaveBeenCalledTimes(3);
        });
        expect(mockOnNavigate).toHaveBeenCalledWith('  spaced folder  ');
    });

    it('defaults batch copy/move conflict policy to error, displays actual allocated destinations for keep-both, and shows overwrite warning when overwrite is chosen', async () => {
        mockedCopy.mockResolvedValueOnce({
            success: true,
            path: 'archive/configs(1)',
            from: 'configs',
            to: 'archive/configs(1)',
        });
        mockedRename.mockResolvedValueOnce({
            success: true,
            path: 'moved/server(2).properties',
            from: 'server.properties',
            to: 'moved/server(2).properties',
        });

        render(
            <McBrowserWorkspace
                currentPath=""
                entries={SAMPLE_ENTRIES}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await screen.findByLabelText('Select configs');
        fireEvent.click(screen.getByLabelText('Select configs'));
        fireEvent.click(screen.getByRole('button', { name: /Batch Copy/i }));

        const copyDialog = screen.getByRole('dialog', { name: /Confirm Batch copy/i });
        const conflictSelect = within(copyDialog).getByLabelText(
            'Conflict Resolution Policy'
        ) as HTMLSelectElement;
        expect(conflictSelect.value).toBe('error');
        expect(
            within(copyDialog).queryByLabelText('Overwrite conflict warning')
        ).not.toBeInTheDocument();

        fireEvent.change(conflictSelect, { target: { value: 'overwrite' } });
        expect(
            within(copyDialog).getByLabelText('Overwrite conflict warning')
        ).toHaveTextContent(/permanently replaced/i);

        fireEvent.change(conflictSelect, { target: { value: 'keep-both' } });
        expect(
            within(copyDialog).queryByLabelText('Overwrite conflict warning')
        ).not.toBeInTheDocument();

        fireEvent.change(within(copyDialog).getByLabelText(/Destination Relative Directory/i), {
            target: { value: 'archive' },
        });
        fireEvent.click(
            within(copyDialog).getByRole('button', { name: /Confirm Batch Copy \(1\)/i })
        );

        await waitFor(() => {
            expect(mockedCopy).toHaveBeenCalledWith(
                'configs',
                'archive/configs',
                'keep-both'
            );
        });

        const copyOutcomes = within(copyDialog).getByRole('region', {
            name: /Batch operation outcomes/i,
        });
        expect(copyOutcomes).toHaveTextContent('SUCCESS: Copied to archive/configs(1)');

        fireEvent.click(within(copyDialog).getByRole('button', { name: 'Close' }));

        fireEvent.click(screen.getByLabelText('Select server.properties'));
        fireEvent.click(screen.getByRole('button', { name: /Batch Move/i }));

        const moveDialog = screen.getByRole('dialog', { name: /Confirm Batch move/i });
        const moveConflictSelect = within(moveDialog).getByLabelText(
            'Conflict Resolution Policy'
        ) as HTMLSelectElement;
        expect(moveConflictSelect.value).toBe('error');

        fireEvent.change(moveConflictSelect, { target: { value: 'overwrite' } });
        expect(
            within(moveDialog).getByLabelText('Overwrite conflict warning')
        ).toBeInTheDocument();
        fireEvent.change(within(moveDialog).getByLabelText(/Destination Relative Directory/i), {
            target: { value: 'moved' },
        });
        fireEvent.click(
            within(moveDialog).getByRole('button', { name: /Confirm Batch Move \(1\)/i })
        );

        await waitFor(() => {
            expect(mockedRename).toHaveBeenCalledWith(
                'server.properties',
                'moved/server.properties',
                'overwrite'
            );
        });

        const moveOutcomes = within(moveDialog).getByRole('region', {
            name: /Batch operation outcomes/i,
        });
        expect(moveOutcomes).toHaveTextContent('SUCCESS: Moved to moved/server(2).properties');
    });

    it('gates overwrite conflict policy on Modify permission in copy/move dialog', async () => {
        mockedFetchPolicy.mockResolvedValueOnce({
            permissions: {
                read: true,
                create: true,
                rename: true,
                modify: false,
                delete: true,
                share: true,
                download: true,
            },
            rules: [],
            scope: 'My files',
        });

        render(
            <McBrowserWorkspace
                currentPath=""
                entries={SAMPLE_ENTRIES}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await screen.findByLabelText('Select configs');
        await waitFor(() => {
            expect(mockedFetchPolicy).toHaveBeenCalled();
        });

        fireEvent.click(screen.getByLabelText('Select configs'));
        fireEvent.click(screen.getByRole('button', { name: /Batch Copy/i }));

        const dialog = screen.getByRole('dialog', { name: /Confirm Batch copy/i });
        const conflictSelect = within(dialog).getByLabelText(
            'Conflict Resolution Policy'
        ) as HTMLSelectElement;
        await waitFor(() => {
            const overwriteOption = within(conflictSelect).getByRole('option', {
                name: /Overwrite existing destination/i,
            }) as HTMLOptionElement;
            expect(overwriteOption.disabled).toBe(true);
        });
        expect(
            within(dialog).getByText(/Overwrite is disabled because your account does not have/i)
        ).toBeInTheDocument();
    });

    it('supports confined alias editing, copying, archiving, sharing, and link-only move/delete', async () => {
        const symlinkEntries: McBrowserEntry[] = [
            {
                name: 'conf-alias',
                path: 'conf-alias',
                kind: 'symlink',
                target_kind: 'directory',
                size: 0,
                modified: '2026-10-20T14:30:00Z',
            },
            {
                name: 'file-alias.txt',
                path: 'file-alias.txt',
                kind: 'symlink',
                target_kind: 'file',
                size: 64,
                modified: '2026-10-20T14:30:00Z',
            },
            {
                name: 'fifo.sock',
                path: 'fifo.sock',
                kind: 'other',
                size: 0,
                modified: null,
            },
        ];

        mockedRename.mockResolvedValueOnce({
            success: true,
            path: 'archive/file-alias.txt',
            from: 'file-alias.txt',
            to: 'archive/file-alias.txt',
        });

        render(
            <McBrowserWorkspace
                currentPath=""
                entries={symlinkEntries}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        const dirAliasBtn = await screen.findByRole('button', {
            name: 'conf-alias (Directory alias)',
        });
        fireEvent.click(dirAliasBtn);
        expect(mockOnNavigate).toHaveBeenCalledWith('conf-alias');

        expect(screen.getByLabelText('Select conf-alias')).toBeEnabled();
        expect(screen.getByLabelText('Select file-alias.txt')).toBeEnabled();
        expect(screen.getByLabelText('Select fifo.sock')).toBeDisabled();

        expect(
            screen.getByRole('button', { name: 'Edit file-alias.txt' })
        ).toBeEnabled();
        expect(
            screen.queryByRole('button', { name: 'Info for file-alias.txt' })
        ).toBeEnabled();
        expect(
            screen.getByRole('button', { name: 'Share file-alias.txt' })
        ).toBeEnabled();
        expect(screen.queryByText('Share pending')).not.toBeInTheDocument();

        fireEvent.click(screen.getByLabelText('Select file-alias.txt'));
        expect(screen.getByRole('button', { name: /Batch Move/i })).toBeEnabled();
        expect(screen.getByRole('button', { name: /Batch Delete/i })).toBeEnabled();
        expect(screen.getByRole('button', { name: /Batch Copy/i })).toBeEnabled();
        expect(screen.getByRole('button', { name: /Download Archive/i })).toBeEnabled();

        fireEvent.click(screen.getByRole('button', { name: /Batch Move/i }));
        const moveDialog = screen.getByRole('dialog', { name: /Confirm Batch move/i });
        fireEvent.change(within(moveDialog).getByLabelText(/Destination Relative Directory/i), {
            target: { value: 'archive' },
        });
        fireEvent.click(
            within(moveDialog).getByRole('button', { name: /Confirm Batch Move \(1\)/i })
        );

        await waitFor(() => {
            expect(mockedRename).toHaveBeenCalledWith(
                'file-alias.txt',
                'archive/file-alias.txt'
            );
        });
    });

    it('copies confined file and directory aliases via batch dialog and clipboard while blocking broken aliases', async () => {
        const entries: McBrowserEntry[] = [
            { name: 'alias.txt', path: 'alias.txt', kind: 'symlink', target_kind: 'file', size: 8, modified: null },
            { name: 'alias-dir', path: 'alias-dir', kind: 'symlink', target_kind: 'directory', size: 0, modified: null },
            { name: 'broken', path: 'broken', kind: 'symlink', size: 0, modified: null },
        ];
        mockedCopy
            .mockResolvedValueOnce({
                success: true,
                path: 'copies/alias.txt',
                from: 'alias.txt',
                to: 'copies/alias.txt',
            })
            .mockResolvedValueOnce({
                success: true,
                path: 'copies/alias-dir',
                from: 'alias-dir',
                to: 'copies/alias-dir',
            })
            .mockResolvedValueOnce({
                success: true,
                path: 'alias.txt(1)',
                from: 'alias.txt',
                to: 'alias.txt(1)',
            });

        render(<McBrowserWorkspace currentPath="" entries={entries} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await screen.findByText(/Scope: My files/i);

        fireEvent.click(screen.getByLabelText('Select alias.txt'));
        fireEvent.click(screen.getByLabelText('Select alias-dir'));
        expect(screen.getByRole('button', { name: /Batch Copy/i })).toBeEnabled();

        const workspaceSection = screen.getByRole('region', {
            name: 'Advanced file actions and workspace explorer',
        });

        fireEvent.click(screen.getByLabelText('Select broken'));
        expect(screen.getByRole('button', { name: /Batch Copy/i })).toBeDisabled();
        fireEvent.keyDown(workspaceSection, { key: 'c', ctrlKey: true });
        expect(
            screen.queryByRole('button', { name: 'Paste into current folder' })
        ).not.toBeInTheDocument();

        fireEvent.click(screen.getByLabelText('Select broken'));
        expect(screen.getByRole('button', { name: /Batch Copy/i })).toBeEnabled();

        fireEvent.click(screen.getByRole('button', { name: /Batch Copy/i }));
        const copyDialog = screen.getByRole('dialog', { name: /Confirm Batch copy/i });
        fireEvent.change(within(copyDialog).getByLabelText(/Destination Relative Directory/i), {
            target: { value: 'copies' },
        });
        fireEvent.click(
            within(copyDialog).getByRole('button', { name: /Confirm Batch Copy \(2\)/i })
        );

        await waitFor(() => {
            expect(mockedCopy).toHaveBeenCalledWith('alias.txt', 'copies/alias.txt');
            expect(mockedCopy).toHaveBeenCalledWith('alias-dir', 'copies/alias-dir');
        });
        fireEvent.click(within(copyDialog).getByRole('button', { name: 'Close' }));

        fireEvent.click(screen.getByLabelText('Select alias.txt'));
        fireEvent.keyDown(workspaceSection, { key: 'c', ctrlKey: true });
        fireEvent.keyDown(workspaceSection, { key: 'v', ctrlKey: true });

        const pasteDialog = await screen.findByRole('dialog', { name: /Confirm Batch copy/i });
        fireEvent.click(
            within(pasteDialog).getByRole('button', { name: /Confirm Batch Copy \(1\)/i })
        );

        await waitFor(() => {
            expect(mockedCopy).toHaveBeenCalledWith('alias.txt', 'alias.txt', 'keep-both');
        });
    });

    it('downloads archives of confined aliases and blocks unresolved aliases', async () => {
        const entries: McBrowserEntry[] = [
            { name: 'alias.txt', path: 'alias.txt', kind: 'symlink', target_kind: 'file', size: 8, modified: null },
            { name: 'alias-dir', path: 'alias-dir', kind: 'symlink', target_kind: 'directory', size: 0, modified: null },
            { name: 'broken', path: 'broken', kind: 'symlink', size: 0, modified: null },
        ];
        mockedDownloadArchive.mockResolvedValue({ filename: 'aliases.zip', bytesWritten: 1024, method: 'filesystem-access' });
        render(<McBrowserWorkspace currentPath="" entries={entries} onRefresh={mockOnRefresh} onNavigate={mockOnNavigate} />);
        await screen.findByText(/Scope: My files/i);
        fireEvent.click(screen.getByLabelText('Select alias.txt'));
        fireEvent.click(screen.getByLabelText('Select alias-dir'));
        expect(screen.getByRole('button', { name: /Download Archive/i })).toBeEnabled();
        fireEvent.click(screen.getByRole('button', { name: /Download Archive/i }));
        await waitFor(() => expect(mockedDownloadArchive).toHaveBeenCalledWith(
            ['alias.txt', 'alias-dir'], 'zip', expect.objectContaining({ signal: expect.any(AbortSignal) })
        ));
        await screen.findByText(/Streamed "aliases.zip"/i);
        fireEvent.click(screen.getByLabelText('Select broken'));
        expect(screen.getByRole('button', { name: /Download Archive/i })).toBeDisabled();
        expect(screen.getByLabelText('Archive format')).toBeDisabled();
    });

    it('warns about pending accounting on confirmed deletions without retaining items for retry', async () => {
        mockedDeleteRecursive.mockResolvedValueOnce({
            success: true,
            accounting_pending: true,
        });
        mockedDelete
            .mockRejectedValueOnce(
                new McBrowserRequestError(409, 'CONFLICT', 'Entry busy')
            )
            .mockResolvedValueOnce({
                success: true,
                accounting_pending: true,
            });

        render(
            <McBrowserWorkspace
                currentPath=""
                entries={SAMPLE_ENTRIES}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await screen.findByLabelText('Select configs');
        fireEvent.click(screen.getByLabelText('Select configs'));
        fireEvent.click(screen.getByLabelText('Select server.properties'));
        fireEvent.click(screen.getByRole('button', { name: /Batch Delete/i }));

        const deleteDialog = screen.getByRole('dialog', { name: /Confirm Batch delete/i });
        fireEvent.click(
            within(deleteDialog).getByRole('button', {
                name: /Confirm Batch Delete \(2\)/i,
            })
        );

        await waitFor(() => {
            expect(mockedDeleteRecursive).toHaveBeenCalledTimes(1);
            expect(mockedDelete).toHaveBeenCalledTimes(1);
        });

        const outcomesRegion = within(deleteDialog).getByRole('region', {
            name: /Batch operation outcomes/i,
        });
        expect(
            within(outcomesRegion).getByText(
                /SUCCESS: Deleted permanently; storage accounting requires reconciliation/i
            )
        ).toBeInTheDocument();
        expect(
            within(outcomesRegion).getByText(/CONFLICT: Entry busy/i)
        ).toBeInTheDocument();

        const retryButton = within(deleteDialog).getByRole('button', {
            name: /Confirm Batch Delete \(1\)/i,
        });
        fireEvent.click(retryButton);

        await waitFor(() => {
            expect(mockedDelete).toHaveBeenCalledTimes(2);
        });
        expect(mockedDeleteRecursive).toHaveBeenCalledTimes(1);
        expect(
            within(deleteDialog).queryByRole('button', { name: /Confirm Batch Delete/i })
        ).not.toBeInTheDocument();
        expect(mockOnRefresh).toHaveBeenCalledTimes(2);
    });

    it('reflows workspace selection table to usable labeled cards with wrapping long names, visible actions, and dark glass obs-checkbox', async () => {
        const testEntries: McBrowserEntry[] = [
            {
                name: 'a_very_long_configuration_filename_that_should_wrap_cleanly_on_small_screens.properties',
                path: 'configs/a_very_long_configuration_filename_that_should_wrap_cleanly_on_small_screens.properties',
                kind: 'file',
                size: 2048,
                modified: '2026-11-08T12:00:00Z',
            },
            {
                name: 'nested-folder',
                path: 'configs/nested-folder',
                kind: 'directory',
                size: 0,
                modified: '2026-11-08T12:00:00Z',
            },
            {
                name: 'device.raw',
                path: 'configs/device.raw',
                kind: 'other',
                size: 0,
                modified: null,
            },
        ];

        render(
            <McBrowserWorkspace
                currentPath="configs"
                entries={testEntries}
                onRefresh={mockOnRefresh}
                onNavigate={mockOnNavigate}
            />
        );

        await waitFor(() => expect(screen.getByRole('button', { name: 'New File' })).toBeEnabled());

        const workspaceTable = screen.getByRole('table', { name: 'Workspace selection table' });
        expect(workspaceTable).toHaveAttribute('role', 'table');
        workspaceTable.querySelectorAll('thead, tbody').forEach((rowGroup) => expect(rowGroup).toHaveAttribute('role', 'rowgroup'));
        workspaceTable.querySelectorAll('tr').forEach((row) => expect(row).toHaveAttribute('role', 'row'));
        workspaceTable.querySelectorAll('th').forEach((header) => expect(header).toHaveAttribute('role', 'columnheader'));
        workspaceTable.querySelectorAll('td').forEach((cell) => expect(cell).toHaveAttribute('role', 'cell'));
        expect(workspaceTable).toHaveClass('obs-mobile-ledger', 'w-full', 'min-w-0');
        expect(workspaceTable.parentElement).toHaveClass('overflow-x-auto', 'min-w-0', 'max-w-full');

        const checkbox = screen.getByRole('checkbox', {
            name: 'Select a_very_long_configuration_filename_that_should_wrap_cleanly_on_small_screens.properties',
        });
        expect(checkbox).toHaveClass('obs-checkbox');
        expect(checkbox).not.toBeChecked();
        expect(checkbox).toBeEnabled();

        const disabledCheckbox = screen.getByRole('checkbox', {
            name: 'Select device.raw',
        });
        expect(disabledCheckbox).toHaveClass('obs-checkbox');
        expect(disabledCheckbox).toBeDisabled();

        const fileButton = screen.getByRole('button', {
            name: 'a_very_long_configuration_filename_that_should_wrap_cleanly_on_small_screens.properties',
        });
        const fileCell = fileButton.closest('td');
        expect(fileCell).toHaveAttribute('data-primary');
        expect(fileCell).toHaveAttribute('data-label', 'Entry / Relative Path');
        expect(fileCell).toHaveClass('min-w-0');
        expect(fileButton).toHaveClass('break-words', '[overflow-wrap:anywhere]', 'min-w-0');

        const selectCell = checkbox.closest('td');
        expect(selectCell).toHaveAttribute('data-label', 'Select');
        expect(selectCell).toHaveClass('min-w-0');

        const sizeCell = screen.getByRole('cell', { name: '2 KiB' });
        expect(sizeCell).toHaveAttribute('data-label', 'Size');
        expect(sizeCell).toHaveClass('min-w-0');

        const actionsCell = screen.getByRole('button', {
            name: 'Edit a_very_long_configuration_filename_that_should_wrap_cleanly_on_small_screens.properties',
        }).closest('td');
        expect(actionsCell).toHaveAttribute('data-actions');
        expect(actionsCell).toHaveAttribute('data-label', 'Workspace Actions');
        expect(actionsCell).toHaveClass('min-w-0');

        fireEvent.click(checkbox);
        expect(checkbox).toBeChecked();
    });
});
