import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import useSWR from 'swr';
import FileshareTab from '@/components/tabs/FileshareTab';
import { apiFetch } from '@/lib/fetcher';

const mockAddToast = jest.fn();
const mockMutate = jest.fn();

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
    }),
}));

jest.mock('swr', () => jest.fn());

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
    fetcher: jest.fn(),
}));

const mockedUseSWR = useSWR as jest.Mock;
const mockedApiFetch = apiFetch as jest.Mock;

function createSizedFile(name: string, sizeBytes: number): File {
    const file = new File(['x'], name, { type: 'application/octet-stream' });
    Object.defineProperty(file, 'size', { value: sizeBytes, configurable: true });
    jest.spyOn(file, 'slice');
    return file;
}

describe('FileshareTab Chunked Upload Contract', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockedUseSWR.mockReturnValue({
            data: [],
            error: undefined,
            isLoading: false,
            isValidating: false,
            mutate: mockMutate,
        });
    });

    it('wraps full file identities without hiding the decision context', () => {
        const filename = 'enterprise-archive-2026-11-08-production-media-index-and-recovery-manifest.tar.zst';
        mockedUseSWR.mockReturnValue({ data: [{ name: filename, size: 1024, modTime: '2026-11-08T04:00:00Z', extension: 'zst' }], mutate: mockMutate });
        render(<FileshareTab />);
        const identity = screen.getByText(filename);
        expect(identity).toHaveClass('break-words', '[overflow-wrap:anywhere]');
        expect(identity).toHaveAttribute('title', filename);
        expect(identity).not.toHaveClass('truncate');
    });

    it('splits multi-chunk uploads into 5 MiB chunks with a stable 32-hex X-Upload-ID and exact chunk headers', async () => {
        const capturedCalls: Array<{ url: string; headers: Record<string, string>; hasChunk: boolean }> = [];

        mockedApiFetch.mockImplementation(async (url: string, init?: RequestInit) => {
            const form = init?.body as FormData;
            capturedCalls.push({
                url,
                headers: (init?.headers || {}) as Record<string, string>,
                hasChunk: Boolean(form instanceof FormData && form.has('file')),
            });
            return {
                ok: true,
                status: 200,
                json: async () => ({ status: 'ok' }),
            };
        });

        render(<FileshareTab />);

        const fileSize = 12 * 1024 * 1024; // 12 MiB -> 3 chunks (5 MiB, 5 MiB, 2 MiB)
        const file = createSizedFile('archive.tar.zst', fileSize);
        const input = screen.getByLabelText('Select file to upload');

        fireEvent.change(input, { target: { files: [file] } });

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith('Uploaded archive.tar.zst successfully', 'success');
        });

        expect(capturedCalls).toHaveLength(3);
        expect(capturedCalls.every((c) => c.hasChunk)).toBe(true);
        expect((file.slice as jest.Mock).mock.calls).toEqual([
            [0, 5 * 1024 * 1024],
            [5 * 1024 * 1024, 10 * 1024 * 1024],
            [10 * 1024 * 1024, 12 * 1024 * 1024],
        ]);
        const uploadId = capturedCalls[0].headers['X-Upload-ID'];
        expect(uploadId).toMatch(/^[0-9a-f]{32}$/);

        expect(capturedCalls.map((c) => c.headers)).toEqual([
            {
                'X-Upload-ID': uploadId,
                'X-Chunk-Index': '0',
                'X-Total-Chunks': '3',
                'X-Target-Path': '/',
                'X-File-Name': 'archive.tar.zst',
            },
            {
                'X-Upload-ID': uploadId,
                'X-Chunk-Index': '1',
                'X-Total-Chunks': '3',
                'X-Target-Path': '/',
                'X-File-Name': 'archive.tar.zst',
            },
            {
                'X-Upload-ID': uploadId,
                'X-Chunk-Index': '2',
                'X-Total-Chunks': '3',
                'X-Target-Path': '/',
                'X-File-Name': 'archive.tar.zst',
            },
        ]);

        expect((file.slice as jest.Mock).mock.calls).toEqual([
            [0, 5 * 1024 * 1024],
            [5 * 1024 * 1024, 10 * 1024 * 1024],
            [10 * 1024 * 1024, 12 * 1024 * 1024],
        ]);
        expect(mockMutate).toHaveBeenCalledTimes(1);
    });

    it('generates distinct X-Upload-ID headers across separate file uploads', async () => {
        const uploadIds: string[] = [];

        mockedApiFetch.mockImplementation(async (_url: string, init?: RequestInit) => {
            const headers = (init?.headers || {}) as Record<string, string>;
            uploadIds.push(headers['X-Upload-ID']);
            return {
                ok: true,
                status: 200,
                json: async () => ({ status: 'ok' }),
            };
        });

        render(<FileshareTab />);
        const input = screen.getByLabelText('Select file to upload');

        const firstFile = createSizedFile('first.txt', 1024);
        fireEvent.change(input, { target: { files: [firstFile] } });
        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith('Uploaded first.txt successfully', 'success');
        });

        const secondFile = createSizedFile('second.txt', 2048);
        fireEvent.change(input, { target: { files: [secondFile] } });
        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith('Uploaded second.txt successfully', 'success');
        });

        expect(uploadIds).toHaveLength(2);
        expect(uploadIds[0]).toMatch(/^[0-9a-f]{32}$/);
        expect(uploadIds[1]).toMatch(/^[0-9a-f]{32}$/);
        expect(uploadIds[0]).not.toBe(uploadIds[1]);
    });

    it('uploads empty (0-byte) files with nonzero totalChunks (X-Total-Chunks=1, X-Chunk-Index=0)', async () => {
        const capturedHeaders: Array<Record<string, string>> = [];

        mockedApiFetch.mockImplementation(async (_url: string, init?: RequestInit) => {
            capturedHeaders.push((init?.headers || {}) as Record<string, string>);
            return {
                ok: true,
                status: 200,
                json: async () => ({ status: 'ok' }),
            };
        });

        render(<FileshareTab />);
        const emptyFile = createSizedFile('empty.keep', 0);
        const input = screen.getByLabelText('Select file to upload');

        fireEvent.change(input, { target: { files: [emptyFile] } });

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith('Uploaded empty.keep successfully', 'success');
        });

        expect(capturedHeaders).toHaveLength(1);
        expect(capturedHeaders[0]['X-Upload-ID']).toMatch(/^[0-9a-f]{32}$/);
        expect(capturedHeaders[0]['X-Chunk-Index']).toBe('0');
        expect(capturedHeaders[0]['X-Total-Chunks']).toBe('1');
        expect(capturedHeaders[0]['X-File-Name']).toBe('empty.keep');
        expect((emptyFile.slice as jest.Mock).mock.calls).toEqual([[0, 0]]);
    });

    it('rejects files larger than 50 MiB before issuing any upload requests', async () => {
        render(<FileshareTab />);
        const oversized = createSizedFile('huge.iso', 50 * 1024 * 1024 + 1);
        const input = screen.getByLabelText('Select file to upload');

        fireEvent.change(input, { target: { files: [oversized] } });

        expect(mockAddToast).toHaveBeenCalledWith('File exceeds the 50 MiB upload limit.', 'error');
        expect(mockedApiFetch).not.toHaveBeenCalled();
    });

    it('guards against overlapping uploads and aborts an in-flight upload on unmount', async () => {
        let capturedSignal: AbortSignal | undefined;
        let resolveChunk: ((res: unknown) => void) | null = null;

        mockedApiFetch.mockImplementation((_url: string, init?: RequestInit) => {
            capturedSignal = init?.signal as AbortSignal | undefined;
            return new Promise((resolve) => {
                resolveChunk = resolve;
            });
        });

        const { unmount } = render(<FileshareTab />);
        const input = screen.getByLabelText('Select file to upload');

        const firstFile = createSizedFile('in-flight.bin', 1024);
        const overlappingFile = createSizedFile('ignored.bin', 1024);

        fireEvent.change(input, { target: { files: [firstFile] } });
        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledTimes(1);
        });

        // Triggering another upload while the first is in flight must be ignored
        fireEvent.change(input, { target: { files: [overlappingFile] } });
        expect(mockedApiFetch).toHaveBeenCalledTimes(1);

        expect(capturedSignal?.aborted).toBe(false);
        unmount();
        expect(capturedSignal?.aborted).toBe(true);

        if (resolveChunk) {
            await act(async () => {
                resolveChunk!({ ok: true, status: 200, json: async () => ({}) });
            });
        }
    });
});
