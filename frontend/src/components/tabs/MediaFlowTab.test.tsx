import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import useSWR from 'swr';
import MediaFlowTab from '@/components/tabs/MediaFlowTab';
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

jest.mock('@/components/tabs/MetadataTab', () => {
    return function MockMetadataTab() {
        return <div data-testid="metadata-tab-mock">Metadata Enrichment View</div>;
    };
});

const mockedUseSWR = useSWR as jest.Mock;
const mockedApiFetch = apiFetch as jest.Mock;
const originalEventSource = globalThis.EventSource;

beforeAll(() => {
    globalThis.EventSource = jest.fn(() => ({ close: jest.fn() })) as unknown as typeof EventSource;
});

afterAll(() => {
    globalThis.EventSource = originalEventSource;
});

describe('MediaFlowTab Embedded Canvas & Queue Contract', () => {
    const sampleQueue = [
        {
            id: 101,
            filePath: '/home/hdd/movies/sample.mkv',
            status: 'PENDING_APPROVAL',
            originalCodec: 'h264',
            originalSize: 4 * 1024 * 1024 * 1024,
            newCodec: 'hevc',
            newSize: 2 * 1024 * 1024 * 1024,
            errorLog: '',
            createdAt: new Date().toISOString(),
        },
        {
            id: 102,
            filePath: '/home/hdd/shows/test.avi',
            status: 'COMPLETED',
            originalCodec: 'mpeg4',
            originalSize: 1024 * 1024 * 1024,
            newCodec: 'av1',
            newSize: 400 * 1024 * 1024,
            errorLog: '',
            createdAt: new Date().toISOString(),
        },
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        mockedUseSWR.mockReturnValue({
            data: sampleQueue,
            error: null,
            isLoading: false,
            isValidating: false,
            mutate: mockMutate,
        });
    });

    it('renders architectural stat matrix and transcode queue table', () => {
        render(<MediaFlowTab />);

        expect(screen.getByText('MediaFlow Engine')).toBeInTheDocument();
        expect(screen.getByText('Pending Approvals')).toBeInTheDocument();
        expect(screen.getByText('Completed Jobs')).toBeInTheDocument();
        expect(screen.getByText('Space Saved')).toBeInTheDocument();
        expect(screen.getByText('Hardware Engine')).toBeInTheDocument();

        expect(screen.getByText('Transcode Approval Queue')).toBeInTheDocument();
        expect(screen.getByText('sample.mkv')).toBeInTheDocument();
        expect(screen.getByText('test.avi')).toBeInTheDocument();
    });

    it('approves a pending transcode job via POST request', async () => {
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({ status: 'ok' }),
        });

        render(<MediaFlowTab />);

        const authorizeButton = screen.getByLabelText('Authorize transcode for sample.mkv');
        fireEvent.click(authorizeButton);

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledWith('/api/v1/admin/mediaflow/approve/101', {
                method: 'POST',
            });
        });

        expect(mockAddToast).toHaveBeenCalledWith('Transcode job approved and queued.', 'success');
        expect(mockMutate).toHaveBeenCalled();
    });

    it('declines a pending transcode job via POST request', async () => {
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({ status: 'ok' }),
        });

        render(<MediaFlowTab />);

        const declineButton = screen.getByLabelText('Decline transcode for sample.mkv');
        fireEvent.click(declineButton);

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledWith('/api/v1/admin/mediaflow/decline/101', {
                method: 'POST',
            });
        });

        expect(mockAddToast).toHaveBeenCalledWith('Transcode job declined.', 'info');
        expect(mockMutate).toHaveBeenCalled();
    });

    it('switches between Transcode Queue and Metadata Enrichment tabs', () => {
        render(<MediaFlowTab />);

        expect(screen.queryByTestId('metadata-tab-mock')).not.toBeInTheDocument();

        const metadataButton = screen.getByRole('button', { name: /Metadata Enrichment/i });
        fireEvent.click(metadataButton);

        expect(screen.getByTestId('metadata-tab-mock')).toBeInTheDocument();
    });

    it('renders responsive metric strip with two-column layout before xl and wrapping labels without premature truncation', () => {
        render(<MediaFlowTab />);

        const pendingApprovalsLabel = screen.getByText('Pending Approvals');
        const metricCard = pendingApprovalsLabel.closest('div');
        expect(metricCard).not.toBeNull();
        expect(pendingApprovalsLabel).toHaveClass('break-words');
        expect(pendingApprovalsLabel).not.toHaveClass('truncate');

        const metricStrip = metricCard?.parentElement?.parentElement;
        expect(metricStrip).not.toBeNull();
        expect(metricStrip).toHaveClass('grid', 'grid-cols-1', 'sm:grid-cols-2', 'xl:grid-cols-4');
        expect(metricStrip).not.toHaveClass('obs-metric-strip');

        const hardwareEngineLabel = screen.getByText('Hardware Engine');
        expect(hardwareEngineLabel).toHaveClass('break-words');
        expect(hardwareEngineLabel).not.toHaveClass('truncate');
    });

    it('gives codec transitions a wider column and separate complete chip rows', () => {
        const originalCodec = 'HEVC (Main 10) 78.4 Mbps';
        const newCodec = 'AV1 10-bit (SVT-AV1) 22.0 Mbps';
        mockedUseSWR.mockReturnValue({ data: [{ ...sampleQueue[0], originalCodec, newCodec }], mutate: mockMutate });
        render(<MediaFlowTab />);
        expect(screen.getByRole('columnheader', { name: 'Codec Transition' })).toHaveClass('w-[28%]');
        const original = screen.getByText(originalCodec);
        const target = screen.getByText(`→ ${newCodec}`);
        expect(original.parentElement).toBe(target.parentElement);
        expect(original.parentElement).toHaveClass('flex-col', 'items-start', 'min-w-0');
        expect(original).toHaveClass('block', 'max-w-full', 'break-words');
        expect(target).toHaveClass('block', 'max-w-full', 'break-words');
    });

    it('reserves room for decimal file sizes without taking width from codec transitions', () => {
        mockedUseSWR.mockReturnValue({
            data: [
                { ...sampleQueue[0], originalSize: Math.round(858.31 * 1024 ** 2) },
                { ...sampleQueue[1], originalSize: Math.round(112.22 * 1024 ** 3) },
            ],
            mutate: mockMutate,
        });
        render(<MediaFlowTab />);

        expect(screen.getByRole('columnheader', { name: 'File' })).toHaveClass('w-[24%]');
        expect(screen.getByRole('columnheader', { name: 'Size' })).toHaveClass('w-[12%]');
        expect(screen.getByRole('columnheader', { name: 'Codec Transition' })).toHaveClass('w-[28%]');
        expect(screen.getByRole('cell', { name: /858\.31 MB/ })).toHaveAttribute('headers', 'queue-header-size');
        expect(screen.getByRole('cell', { name: /112\.22 GB/ })).toHaveAttribute('headers', 'queue-header-size');
    });

    it('renders responsive queue table with continuous hairline rows and contextual actions co-located with filename', () => {
        render(<MediaFlowTab />);

        const queueSection = screen.getByRole('region', {
            name: 'Transcode approval queue',
        });
        const tableElement = queueSection.querySelector('table');
        expect(tableElement).not.toBeNull();
        expect(tableElement).toHaveClass('block', 'xl:table', 'xl:table-fixed', 'w-full');
        expect(screen.getByText('/home/hdd/movies/sample.mkv')).toHaveClass('break-words', '[overflow-wrap:anywhere]');
        expect(screen.getByText('/home/hdd/movies/sample.mkv')).not.toHaveClass('truncate');

        const theadElement = queueSection.querySelector('thead');
        expect(theadElement).not.toBeNull();
        expect(theadElement).toHaveClass('hidden', 'xl:table-header-group');

        const authorizeButtons = screen.getAllByRole('button', {
            name: /Authorize transcode for sample\.mkv/,
        });
        expect(authorizeButtons).toHaveLength(1);
        expect(authorizeButtons[0]).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');

        const declineButtons = screen.getAllByRole('button', {
            name: /Decline transcode for sample\.mkv/,
        });
        expect(declineButtons).toHaveLength(1);
        expect(declineButtons[0]).toHaveClass('min-h-[44px]', 'obs-touch-target-standard');

        const rowElement = authorizeButtons[0].closest('tr');
        expect(rowElement).not.toBeNull();
        expect(rowElement).toHaveClass('block', 'xl:table-row');
        expect(rowElement).toHaveTextContent('sample.mkv');

        const fileCell = rowElement?.querySelector('[headers="queue-header-file"]');
        expect(fileCell).not.toBeNull();
        expect(fileCell).toHaveTextContent('sample.mkv');

        const actionCell = rowElement?.querySelector('[headers="queue-header-action"]');
        expect(actionCell).not.toBeNull();
        expect(actionCell?.contains(authorizeButtons[0])).toBe(true);
        expect(actionCell?.contains(declineButtons[0])).toBe(true);
        expect(authorizeButtons[0].parentElement).toHaveClass('flex-wrap');
        expect(within(rowElement!).getByText('Size:')).toHaveClass('text-xs', 'text-slate-400');
        expect(within(rowElement!).getByText('Codec:')).toHaveClass('text-xs', 'text-slate-400');
    });
});
