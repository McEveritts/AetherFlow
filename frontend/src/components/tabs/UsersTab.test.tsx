import React from 'react';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { apiFetch } from '@/lib/fetcher';
import UsersTab from './UsersTab';

jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => ({ user: { id: 1, role: 'admin' }, isAuthenticated: true }),
}));
jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({ addToast: jest.fn() }),
}));

const mockMeasureElement = jest.fn();
const mockMeasure = jest.fn();

jest.mock('@tanstack/react-virtual', () => ({
    useVirtualizer: ({ count, estimateSize }: { count: number; estimateSize: () => number }) => ({
        getVirtualItems: () => Array.from(Array(count).keys()).map(index => ({
            index,
            start: index * estimateSize(),
            end: (index + 1) * estimateSize(),
        })),
        getTotalSize: () => count * estimateSize(),
        measureElement: mockMeasureElement,
        measure: mockMeasure,
    }),
}));

const mockUsers = [
    { id: 1, username: 'adminuser', email: 'admin@example.com', role: 'admin' },
    { id: 2, username: 'stduser', email: 'std@example.com', role: 'user' },
];

let mockVisibleUsers: typeof mockUsers | undefined = mockUsers;
let mockUsersLoading = false;

jest.mock('swr', () => (url: string) => {
    if (url.includes('/api/v1/admin/users')) {
        return {
            data: mockVisibleUsers,
            isLoading: mockUsersLoading,
            error: null,
            isValidating: false,
            mutate: jest.fn(),
        };
    }
    if (url.includes('/api/v1/admin/quotas')) {
        return {
            data: { quotas: [] },
            isLoading: false,
            mutate: jest.fn(),
        };
    }
    return { data: null, isLoading: false, mutate: jest.fn() };
});

describe('UsersTab', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockVisibleUsers = mockUsers;
        mockUsersLoading = false;
    });

    afterEach(() => jest.restoreAllMocks());

    it('renders identity directory, metric strip, and sub-tab switcher', () => {
        render(<UsersTab />);
        expect(screen.getByText(/Identity & Quota Management/i)).toBeInTheDocument();
        expect(screen.getByText('Total Users')).toBeInTheDocument();
        expect(screen.getByText('Administrators')).toBeInTheDocument();
        expect(screen.getByText('Standard Users')).toBeInTheDocument();
        expect(screen.getByText('Policy Engine')).toBeInTheDocument();
        const summary = screen.getByRole('button', { name: /Directory summary/ });
        expect(summary).toHaveAttribute('aria-expanded', 'false');
        expect(document.getElementById(summary.getAttribute('aria-controls')!)).toHaveClass('hidden', 'md:block');
        expect(screen.getByText('adminuser')).toBeInTheDocument();
        expect(screen.getByText('stduser')).toBeInTheDocument();
    });

    it('keeps keyboard-focused directory actions visible without hover', () => {
        render(<UsersTab />);
        const action = screen.getByTitle('Demote to User');
        action.focus();
        expect(action).toHaveFocus();
        expect(action).toHaveClass('focus-visible:outline-2', 'min-h-[44px]');
        expect(action.parentElement?.className).not.toMatch(/opacity-0/);
        expect(screen.getAllByTitle('Delete User')).toHaveLength(2);
    });

    it('switches to storage quotas subtab', () => {
        render(<UsersTab />);
        const quotasBtn = screen.getByRole('button', { name: /Storage Quotas/i });
        fireEvent.click(quotasBtn);
        expect(screen.getByText(/User disk allocation, capacity thresholds/i)).toBeInTheDocument();
        expect(screen.queryByTitle('Refresh Users')).not.toBeInTheDocument();
        expect(screen.getByTitle('Refresh Quotas')).toBeInTheDocument();
        expect(screen.getAllByRole('button', { name: 'Refresh' })).toHaveLength(1);
    });

    it('measures responsive identity rows and retains contextual primary details and actions', () => {
        render(<UsersTab />);
        const table = screen.getByRole('table');
        expect(table).toHaveClass('obs-mobile-ledger');
        const standardUser = screen.getByText('stduser');
        const userRow = standardUser.closest('tr');
        expect(userRow).not.toBeNull();
        expect(mockMeasureElement).toHaveBeenCalledWith(userRow);
        expect(standardUser.closest('td')).toHaveAttribute('data-primary', 'true');
        const deleteButton = within(userRow!).getByRole('button', { name: 'Delete User stduser' });
        const promoteButton = within(userRow!).getByRole('button', { name: 'Promote to Admin stduser' });
        expect(deleteButton.closest('td')).toHaveAttribute('data-actions', 'true');
        expect(deleteButton).toHaveClass('min-h-[44px]', 'min-w-[44px]');
        expect(promoteButton).toHaveClass('min-h-[44px]', 'min-w-[44px]');
        expect(within(userRow!).getAllByRole('button')).toHaveLength(2);
    });

    it('identifies the selected username and email before an irreversible deletion and preserves cancellation', () => {
        const confirm = jest.spyOn(window, 'confirm').mockReturnValue(false);
        render(<UsersTab />);
        fireEvent.click(screen.getAllByTitle('Delete User')[1]);
        expect(confirm).toHaveBeenCalledWith('Permanently delete stduser (std@example.com)? This cannot be undone.');
        expect(apiFetch).not.toHaveBeenCalled();
        expect(screen.getByText('stduser')).toBeInTheDocument();
    });

    it('uses the loaded and subsequently refreshed identity after an initially empty SWR cache', () => {
        const confirm = jest.spyOn(window, 'confirm').mockReturnValue(false);
        mockVisibleUsers = undefined;
        mockUsersLoading = true;
        const view = render(<UsersTab />);
        mockVisibleUsers = mockUsers;
        mockUsersLoading = false;
        view.rerender(<UsersTab />);
        fireEvent.click(screen.getAllByTitle('Delete User')[1]);
        expect(confirm).toHaveBeenLastCalledWith('Permanently delete stduser (std@example.com)? This cannot be undone.');
        mockVisibleUsers = mockUsers.map(user => user.id === 2 ? { ...user, username: 'renamed-user', email: 'renamed@example.com' } : user);
        view.rerender(<UsersTab />);
        fireEvent.click(screen.getAllByTitle('Delete User')[1]);
        expect(confirm).toHaveBeenLastCalledWith('Permanently delete renamed-user (renamed@example.com)? This cannot be undone.');
        expect(confirm).toHaveBeenCalledTimes(2);
        expect(apiFetch).not.toHaveBeenCalled();
    });

    it('deletes only the selected account after its named confirmation is accepted', async () => {
        jest.spyOn(window, 'confirm').mockReturnValue(true);
        jest.mocked(apiFetch).mockResolvedValue({ ok: true, json: async () => ({}) } as Response);
        render(<UsersTab />);
        fireEvent.click(screen.getAllByTitle('Delete User')[1]);
        await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/v1/admin/users/2', { method: 'DELETE' }));
        expect(apiFetch).toHaveBeenCalledTimes(1);
    });
});
