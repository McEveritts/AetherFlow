import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import BackupTab from './BackupTab';
import { apiFetch } from '@/lib/fetcher';
import { navigateBrowser } from '@/lib/browser-navigation';
jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/lib/browser-navigation', () => ({ navigateBrowser: jest.fn() }));
const downloadUrl = '/api/v1/admin/backup/download/snapshot.sqlite';
let valid = true;
beforeEach(() => {
    jest.clearAllMocks(); valid = true;
    jest.mocked(apiFetch).mockImplementation(async (url) => {
        const value = url === '/api/v1/admin/backup/list' ? [{ filename: 'snapshot.sqlite', size: 1024, timestamp: '2026-11-05T00:00:00Z' }]
            : url === downloadUrl ? valid ? { url: downloadUrl } : { code: 'INVALID_CURRENT_PASSWORD', message: 'Invalid current password' } : {};
        return { ok: url !== downloadUrl || valid, json: async () => value } as Response;
    });
});
async function openDownload() {
    render(<BackupTab />); fireEvent.click(await screen.findByTitle('Download SQLite Archive'));
    fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'fixture-password' } });
}
test('keeps snapshot names and timestamps readable in a tablet-width archive band', async () => {
    const filename = 'snapshot-2026-11-08-production-complete-database-with-all-managed-service-records.sqlite';
    jest.mocked(apiFetch).mockImplementation(async (url) => ({ ok: true, json: async () => url === '/api/v1/admin/backup/list' ? [{ filename, size: 1024, timestamp: '2026-11-08T04:00:00Z' }] : {} } as Response));
    render(<BackupTab />);
    const identity = await screen.findByText(filename);
    expect(identity).toHaveClass('break-words', '[overflow-wrap:anywhere]');
    expect(identity).not.toHaveClass('truncate');
    expect(identity).toHaveAttribute('title', filename);
    const timestamp = identity.parentElement?.querySelector('time');
    expect(timestamp).toHaveAttribute('dateTime', '2026-11-08T04:00:00Z');
    expect(timestamp).not.toHaveClass('truncate');
    const archiveBand = screen.getByText('Archive Snapshots').closest('.md\\:col-span-2');
    expect(archiveBand).toHaveClass('xl:col-span-1');
});

test('obtains a cookie proof before handing off the native streaming download', async () => {
    await openDownload(); expect(navigateBrowser).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Authorize download' }));
    await waitFor(() => expect(navigateBrowser).toHaveBeenCalledWith(downloadUrl));
    expect(apiFetch).toHaveBeenCalledWith(downloadUrl, { method: 'POST', headers: { 'X-Reauth-Password': 'fixture-password' } });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});
test('a rejected proof preserves the form and does not start a download', async () => {
    valid = false; await openDownload(); fireEvent.click(screen.getByRole('button', { name: 'Authorize download' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid current password');
    expect(screen.getByLabelText('Current password')).toHaveValue('fixture-password');
    expect(navigateBrowser).not.toHaveBeenCalled();
    valid = true; fireEvent.click(screen.getByRole('button', { name: 'Authorize download' }));
    await waitFor(() => expect(navigateBrowser).toHaveBeenCalledTimes(1));
});
