import React, { useState } from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import NotificationDrawer from './NotificationDrawer';
import { useToast } from '@/contexts/ToastContext';
import { useMarketplace } from '@/hooks/useMarketplace';
import { apiFetch } from '@/lib/fetcher';

jest.mock('@/contexts/ToastContext', () => ({
    useToast: jest.fn(),
}));

jest.mock('@/hooks/useMarketplace', () => ({
    useMarketplace: jest.fn(),
}));

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

jest.mock('@/lib/design', () => ({
    triggerHaptic: jest.fn(),
}));

jest.mock('@/store/useSystemStore', () => ({
    useSystemStore: () => ({
        hapticFeedback: false,
    }),
}));

const mockMutate = jest.fn();
const mockServerNotifications = [
    {
        id: 1,
        title: 'System Alert',
        message: 'High CPU utilization',
        level: 'warning' as const,
        read: false,
        created_at: new Date().toISOString(),
    },
];

jest.mock('swr', () => ({
    __esModule: true,
    default: () => ({
        data: {
            notifications: mockServerNotifications,
            unread_count: mockServerNotifications.length,
        },
        mutate: mockMutate,
    }),
}));

describe('NotificationDrawer accessibility and focus management', () => {
    const mockToggleDrawer = jest.fn();
    const mockClearAll = jest.fn();

    beforeEach(() => {
        jest.clearAllMocks();
        (useMarketplace as unknown as jest.Mock).mockReturnValue({
            apps: [],
        });
        (useToast as unknown as jest.Mock).mockReturnValue({
            toasts: [
                {
                    id: 'toast-1',
                    message: 'Upload completed',
                    type: 'success',
                    timestamp: Date.now(),
                    dismissed: false,
                },
            ],
            isDrawerOpen: true,
            toggleDrawer: mockToggleDrawer,
            clearAll: mockClearAll,
        });
    });

    it('renders inside a dialog with accessible name and locks body overflow', () => {
        render(<NotificationDrawer />);

        const dialog = screen.getByRole('dialog', { name: 'Notifications' });
        expect(dialog).toBeInTheDocument();
        expect(dialog).toHaveAttribute('aria-modal', 'true');
        expect(dialog).toHaveAttribute('id', 'notification-drawer');
        expect(document.body.style.overflow).toBe('hidden');
    });

    it('safely focuses the close button initially rather than clear all', () => {
        render(<NotificationDrawer />);

        const closeButton = screen.getByRole('button', { name: 'Close Notifications Drawer' });
        expect(document.activeElement).toBe(closeButton);
    });

    it('renders notification counts readable at 12px or greater', () => {
        render(<NotificationDrawer />);

        const countBadge = screen.getByText('2');
        expect(countBadge).toBeInTheDocument();
        expect(countBadge).toHaveClass('text-xs');
    });

    it('contains tab key navigation within the drawer', () => {
        render(<NotificationDrawer />);

        const clearButton = screen.getByRole('button', { name: 'Clear All Notifications' });
        const closeButton = screen.getByRole('button', { name: 'Close Notifications Drawer' });

        expect(document.activeElement).toBe(closeButton);

        fireEvent.keyDown(document, { key: 'Tab' });
        expect(document.activeElement).toBe(clearButton);

        fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
        expect(document.activeElement).toBe(closeButton);
    });

    it('dismisses on Escape and calls toggleDrawer', () => {
        render(<NotificationDrawer />);

        fireEvent.keyDown(document, { key: 'Escape' });
        expect(mockToggleDrawer).toHaveBeenCalledTimes(1);
    });

    it('restores focus to the opener when closed', () => {
        function DrawerHarness() {
            const [isOpenState, setIsOpenState] = useState(false);
            (useToast as unknown as jest.Mock).mockReturnValue({
                toasts: [],
                isDrawerOpen: isOpenState,
                toggleDrawer: () => setIsOpenState(false),
                clearAll: mockClearAll,
            });

            return (
                <div>
                    <button type="button" onClick={() => setIsOpenState(true)}>Open drawer</button>
                    <NotificationDrawer />
                </div>
            );
        }

        render(<DrawerHarness />);
        const trigger = screen.getByRole('button', { name: 'Open drawer' });
        trigger.focus();
        fireEvent.click(trigger);

        const closeButton = screen.getByRole('button', { name: 'Close Notifications Drawer' });
        expect(document.activeElement).toBe(closeButton);

        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.queryByRole('dialog', { name: 'Notifications' })).not.toBeInTheDocument();
        expect(document.activeElement).toBe(trigger);
    });

    it('supports swipe right dismissal', () => {
        render(<NotificationDrawer />);

        const dialog = screen.getByRole('dialog', { name: 'Notifications' });
        fireEvent.touchStart(dialog, { touches: [{ clientX: 100 }] });
        fireEvent.touchEnd(dialog, { changedTouches: [{ clientX: 180 }] });

        expect(mockToggleDrawer).toHaveBeenCalledTimes(1);
    });

    it('clears all notifications including server notifications', async () => {
        render(<NotificationDrawer />);

        const clearButton = screen.getByRole('button', { name: 'Clear All Notifications' });
        fireEvent.click(clearButton);

        expect(mockClearAll).toHaveBeenCalledTimes(1);
        await waitFor(() => {
            expect(apiFetch).toHaveBeenCalledWith('/api/v1/auth/notifications/dismiss-all', { method: 'POST' });
            expect(mockMutate).toHaveBeenCalledTimes(1);
        });
    });

    it('does not render modal when isDrawerOpen is false', () => {
        (useToast as unknown as jest.Mock).mockReturnValue({
            toasts: [],
            isDrawerOpen: false,
            toggleDrawer: mockToggleDrawer,
            clearAll: mockClearAll,
        });

        render(<NotificationDrawer />);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
});
