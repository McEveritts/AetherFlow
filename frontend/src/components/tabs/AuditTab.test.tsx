import React from 'react';
import { act, render, screen, fireEvent, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { apiFetch } from '@/lib/fetcher';
import AuditTab from './AuditTab';

jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({ addToast: jest.fn() }),
}));

const mockAuditData = {
    entries: [
        {
            id: 1,
            user_id: 10,
            username: 'alice',
            action: 'service_start',
            target_type: 'service',
            target_id: 'qbittorrent',
            detail: 'Started service qbittorrent',
            ip_address: '192.168.1.100',
            user_agent: 'Mozilla/5.0',
            created_at: '2026-11-08T12:00:00Z',
        },
        {
            id: 2,
            user_id: 11,
            username: 'flowai',
            action: 'ai_action_proposed',
            target_type: 'pending_action',
            target_id: '42',
            detail: 'Optimize transmission queue',
            ip_address: '127.0.0.1',
            user_agent: 'FlowAI-Agent',
            created_at: '2026-11-08T12:05:00Z',
        },
        {
            id: 3,
            user_id: 10,
            username: 'alice',
            action: 'role_change',
            target_type: 'user',
            target_id: '11',
            detail: 'Changed the cluster operator role after reviewing the complete authorization and ownership record.',
            ip_address: '192.168.1.100',
            user_agent: 'Mozilla/5.0',
            created_at: '2026-11-08T12:10:00Z',
        },
    ],
    total: 3,
    limit: 25,
    offset: 0,
};

jest.mock('swr', () => () => ({
    data: mockAuditData,
    isLoading: false,
    isValidating: false,
    mutate: jest.fn(),
}));

describe('AuditTab', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('renders audit events, metric strip, and compliance toolbar', () => {
        render(<AuditTab />);
        expect(screen.getByText(/Audit Trail & Compliance/i)).toBeInTheDocument();
        expect(screen.getByText('Total Events')).toBeInTheDocument();
        expect(screen.getByText('Operator Approvals')).toBeInTheDocument();
        expect(screen.getByText('AI Proposed', { selector: 'p' })).toBeInTheDocument();
        expect(screen.getByText('System & Auth')).toBeInTheDocument();
        expect(screen.getAllByText('alice')).toHaveLength(2);
        expect(screen.getByText('flowai')).toBeInTheDocument();
    });

    it('allows filtering by actor search input', () => {
        render(<AuditTab />);
        const input = screen.getByPlaceholderText('Filter by actor...');
        fireEvent.change(input, { target: { value: 'alice' } });
        expect(input).toHaveValue('alice');
        fireEvent.click(screen.getByRole('button', { name: 'Filter' }));
    });

    it('opens action details with native keyboard activation and restores focus after Escape', async () => {
        jest.mocked(apiFetch).mockResolvedValue({
            ok: true,
            json: async () => ({
                id: 42,
                action: 'Optimize transmission queue',
                source: 'FlowAI',
                classification: 'warn',
                status: 'pending',
                created_at: '2026-11-08T12:01:00Z',
            }),
        } as Response);
        const user = userEvent.setup();
        render(<AuditTab />);
        const opener = screen.getByRole('button', { name: 'View action details for 42' });
        expect(screen.getByRole('button', { name: 'View logs for qbittorrent' })).toHaveAttribute('type', 'button');
        opener.focus();
        await user.keyboard('{Enter}');
        expect(await screen.findByRole('dialog', { name: 'Optimize transmission queue' })).toBeInTheDocument();
        expect(apiFetch).toHaveBeenCalledTimes(1);
        expect(apiFetch).toHaveBeenCalledWith('/api/v1/admin/actions/42');
        await user.keyboard('{Escape}');
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(opener).toHaveFocus();
    });

    it('returns pointer-invoked audit rows to their persistent disclosure button', async () => {
        jest.mocked(apiFetch).mockResolvedValue({
            ok: true,
            json: async () => ({ id: 42, action: 'Pointer audit disclosure', status: 'pending', source: 'FlowAI', classification: 'warn', created_at: '2026-11-08T12:01:00Z' }),
        } as Response);
        const user = userEvent.setup();
        render(<AuditTab />);
        const opener = screen.getByRole('button', { name: 'View action details for 42' });
        const row = opener.closest('tr') as HTMLTableRowElement;
        await user.click(within(row).getByText('flowai'));
        expect(await screen.findByRole('dialog', { name: 'Pointer audit disclosure' })).toBeVisible();
        await user.keyboard('{Escape}');
        expect(opener).toHaveFocus();
    });

    it('restores the initiating audit row after focus changes during an in-flight detail request', async () => {
        let resolveRequest: (response: Response) => void = () => undefined;
        jest.mocked(apiFetch).mockImplementation(() => new Promise<Response>(resolve => { resolveRequest = resolve; }));
        const user = userEvent.setup();
        render(<AuditTab />);
        const opener = screen.getByRole('button', { name: 'View action details for 42' });
        await user.click(opener);
        await user.click(screen.getByRole('button', { name: 'View logs for qbittorrent' }));
        expect(apiFetch).toHaveBeenCalledTimes(1);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        await act(async () => resolveRequest({ ok: true, json: async () => ({ id: 42, action: 'Delayed action disclosure', status: 'pending', source: 'FlowAI', classification: 'warn', created_at: '2026-11-08T12:01:00Z' }) } as Response));
        expect(await screen.findByRole('dialog', { name: 'Delayed action disclosure' })).toBeVisible();
        await user.keyboard('{Escape}');
        expect(opener).toHaveFocus();
    });

    it('reveals a complete non-service audit record without fetching and restores its invoker', async () => {
        const user = userEvent.setup();
        render(<AuditTab />);
        const opener = screen.getByRole('button', { name: 'View full audit record 3' });
        opener.focus();
        await user.keyboard('{Enter}');
        const dialog = screen.getByRole('dialog', { name: 'Audit Record #3' });
        expect(within(dialog).getByText(mockAuditData.entries[2].detail)).toBeVisible();
        expect(within(dialog).getByText('user/11')).toBeVisible();
        expect(within(dialog).getByText('Mozilla/5.0')).toBeVisible();
        expect(apiFetch).not.toHaveBeenCalled();
        expect(within(dialog).getByRole('button', { name: 'Close Audit Record #3' })).toHaveFocus();
        await user.keyboard('{Escape}');
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
        expect(opener).toHaveFocus();
    });

    it('provides responsive ledger card layout attributes, container query styling, and collision-free wrapping', () => {
        render(<AuditTab />);
        const auditTable = screen.getByRole('table', { name: 'Audit records' });
        expect(auditTable).toHaveAttribute('role', 'table');
        auditTable.querySelectorAll('thead, tbody').forEach((rowGroup) => expect(rowGroup).toHaveAttribute('role', 'rowgroup'));
        auditTable.querySelectorAll('tr').forEach((row) => expect(row).toHaveAttribute('role', 'row'));
        auditTable.querySelectorAll('th').forEach((header) => expect(header).toHaveAttribute('role', 'columnheader'));
        auditTable.querySelectorAll('td').forEach((cell) => expect(cell).toHaveAttribute('role', 'cell'));
        expect(auditTable).toHaveClass('obs-mobile-ledger', 'lg:table-fixed', 'w-full', 'min-w-0');
        expect(auditTable.parentElement).toHaveClass('overflow-x-auto', 'min-w-0', 'max-w-full');

        const rows = within(auditTable).getAllByRole('row');
        expect(rows.length).toBeGreaterThan(1);

        const targetButton = screen.getByRole('button', { name: 'View logs for qbittorrent' });
        const targetCell = targetButton.closest('td');
        expect(targetCell).toHaveAttribute('data-primary');
        expect(targetCell).toHaveAttribute('data-label', 'Target');
        expect(targetCell).toHaveClass('min-w-0');

        const actionCell = screen.getByRole('cell', { name: 'Start' });
        expect(actionCell).toHaveAttribute('data-label', 'Action');
        expect(actionCell).toHaveClass('min-w-0');
        const badge = within(actionCell).getByText('Start');
        expect(badge).toHaveClass('max-w-full', 'whitespace-normal', 'break-words');

        const detailCell = screen.getByRole('cell', { name: /Started service qbittorrent/i });
        expect(detailCell).toHaveAttribute('data-actions');
        expect(detailCell).toHaveAttribute('data-label', 'Detail');
        expect(detailCell).toHaveClass('min-w-0');

        const actorCell = screen.getByRole('cell', { name: 'flowai' });
        expect(actorCell).toHaveAttribute('data-label', 'Actor');
        expect(actorCell).toHaveClass('min-w-0');
        expect(within(actorCell).getByText('flowai')).toHaveClass('break-words', '[overflow-wrap:anywhere]');

        const ipCell = screen.getByRole('cell', { name: '127.0.0.1' });
        expect(ipCell).toHaveAttribute('data-label', 'IP');
        expect(ipCell).toHaveClass('break-words', '[overflow-wrap:anywhere]', 'min-w-0');

        const detailButton = screen.getByRole('button', { name: 'View full audit record 1' });
        expect(detailButton).toHaveClass('w-full', 'min-w-0', 'max-w-[220px]');
    });
});
