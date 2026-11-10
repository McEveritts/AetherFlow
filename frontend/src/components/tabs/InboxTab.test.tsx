import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import InboxTab from '@/components/tabs/InboxTab';
import { useActionGates } from '@/hooks/useActionGates';
import { apiFetch } from '@/lib/fetcher';

const mockAddToast = jest.fn();
jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
        toasts: [],
    }),
}));

jest.mock('@/hooks/useActionGates', () => ({
    useActionGates: jest.fn(),
}));

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
    fetcher: jest.fn(),
}));

const mockedUseActionGates = useActionGates as jest.Mock;
const mockedApiFetch = apiFetch as jest.Mock;

describe('InboxTab Embedded Canvas & Approval Contract', () => {
    const mockApproveAction = jest.fn();
    const mockRejectAction = jest.fn();
    const mockRefresh = jest.fn();

    const sampleActions = [
        {
            id: 1,
            action: 'Restart jellyfin',
            source: 'FlowAI',
            classification: 'warn' as const,
            reason: 'High memory consumption detected',
            execution_log: 'systemctl restart jellyfin',
            created_at: new Date().toISOString(),
        },
        {
            id: 2,
            action: 'Purge orphan cache',
            source: 'System',
            classification: 'safe' as const,
            reason: 'Scheduled routine',
            created_at: new Date().toISOString(),
        },
        {
            id: 3,
            action: 'Stop transmission-daemon',
            source: 'Security',
            classification: 'critical' as const,
            reason: 'Unregistered peer activity',
            created_at: new Date().toISOString(),
        },
    ];

    beforeEach(() => {
        jest.clearAllMocks();
        mockedUseActionGates.mockReturnValue({
            actions: sampleActions,
            isLoading: false,
            isError: false,
            error: null,
            isValidating: false,
            approveAction: mockApproveAction,
            rejectAction: mockRejectAction,
            refresh: mockRefresh,
        });
    });

    it('renders architectural stat matrix and pending actions', () => {
        render(<InboxTab />);

        expect(screen.getByText('Action Approval Inbox')).toBeInTheDocument();
        expect(screen.getByText('Total Pending')).toBeInTheDocument();
        expect(screen.getByText('Critical Actions')).toBeInTheDocument();
        expect(screen.getByText('Warnings')).toBeInTheDocument();
        expect(screen.getByText('Safe Routines')).toBeInTheDocument();
        const summary = screen.getByRole('button', { name: /Queue summary/ });
        expect(summary).toHaveAttribute('aria-expanded', 'false');
        expect(document.getElementById(summary.getAttribute('aria-controls')!)).toHaveClass('hidden', 'md:block');

        expect(screen.getByText('Restart jellyfin')).toBeInTheDocument();
        expect(screen.getByText('Purge orphan cache')).toBeInTheDocument();
        expect(screen.getByText('Stop transmission-daemon')).toBeInTheDocument();
    });

    it('keeps approval counts in a compact two-column mobile matrix without truncating their meaning', () => {
        render(<InboxTab />);
        const label = screen.getByText('Critical Actions');
        expect(label).toHaveClass('break-words');
        expect(label).not.toHaveClass('truncate');
        expect(screen.getByText('Immediate review required')).not.toHaveClass('truncate');
        expect(label.parentElement?.parentElement?.parentElement).toHaveClass('grid-cols-2', 'xl:grid-cols-4');
    });

    it('filters actions by classification', () => {
        render(<InboxTab />);

        const criticalFilter = screen.getByRole('button', { name: /Critical/i });
        fireEvent.click(criticalFilter);

        expect(screen.getByText('Stop transmission-daemon')).toBeInTheDocument();
        expect(screen.queryByText('Restart jellyfin')).not.toBeInTheDocument();
        expect(screen.queryByText('Purge orphan cache')).not.toBeInTheDocument();
    });

    it('handles action authorization and executes FlowAI service control when applicable', async () => {
        mockApproveAction.mockResolvedValueOnce(true);
        mockedApiFetch.mockResolvedValueOnce({ ok: true, text: async () => '' });

        render(<InboxTab />);

        const authorizeButton = screen.getByLabelText('Authorize Restart jellyfin');
        fireEvent.click(authorizeButton);

        await waitFor(() => {
            expect(mockApproveAction).toHaveBeenCalledWith(1);
        });

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledWith(
                '/api/v1/admin/services/jellyfin/control',
                expect.objectContaining({
                    method: 'POST',
                    body: JSON.stringify({ action: 'restart', process: 'jellyfin' }),
                })
            );
        });

        expect(mockAddToast).toHaveBeenCalledWith('Execution authorized: Restart jellyfin', 'success');
    });

    it('handles action rejection without executing service command', async () => {
        mockRejectAction.mockResolvedValueOnce(true);

        render(<InboxTab />);

        const rejectButton = screen.getByLabelText('Reject Restart jellyfin');
        fireEvent.click(rejectButton);

        await waitFor(() => {
            expect(mockRejectAction).toHaveBeenCalledWith(1);
        });

        expect(mockedApiFetch).not.toHaveBeenCalled();
        expect(mockAddToast).toHaveBeenCalledWith('Action rejected. Execution halted.', 'info');
    });
});
