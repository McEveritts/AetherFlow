import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import Header from './Header';
import { useToast } from '@/contexts/ToastContext';
import { useAuth } from '@/contexts/AuthContext';
import { useSystemStore } from '@/store/useSystemStore';
import { useConnectionStore } from '@/store/useConnectionStore';
import { useTaskStore } from '@/store/useTaskStore';
import { readFileSync } from 'fs';
import { join } from 'path';

jest.mock('@/contexts/ToastContext', () => ({
    useToast: jest.fn(),
}));

jest.mock('@/contexts/AuthContext', () => ({
    useAuth: jest.fn(),
}));

jest.mock('next/image', () => ({
    __esModule: true,
    default: (imageProperties: React.ImgHTMLAttributes<HTMLImageElement>) => (
        <span role="img" aria-label={imageProperties.alt || ''} />
    ),
}));

describe('Header accessibility and keyboard semantics', () => {
    const mockToggleDrawer = jest.fn();
    const mockLogout = jest.fn();

    beforeEach(() => {
        jest.clearAllMocks();
        useSystemStore.setState({
            activeTab: 'overview',
            isMobileMenuOpen: false,
            isCommandPaletteOpen: false,
            hapticFeedback: false,
        });
        useConnectionStore.setState({
            connectionState: 'CONNECTED',
            reconnectAttempt: 0,
        });
        useTaskStore.setState({
            tasks: [],
        });
        (useAuth as unknown as jest.Mock).mockReturnValue({
            user: { username: 'testuser', email: 'test@aetherflow.local', role: 'Operator' },
            logout: mockLogout,
        });
        (useToast as unknown as jest.Mock).mockReturnValue({
            toasts: [],
            isDrawerOpen: false,
            toggleDrawer: mockToggleDrawer,
        });
    });

    it('exposes aria-expanded and aria-controls on the notifications trigger', () => {
        const { rerender } = render(<Header />);

        const notificationTrigger = screen.getByRole('button', { name: 'Notifications' });
        expect(notificationTrigger).toHaveAttribute('aria-expanded', 'false');
        expect(notificationTrigger).toHaveAttribute('aria-controls', 'notification-drawer');

        (useToast as unknown as jest.Mock).mockReturnValue({
            toasts: [],
            isDrawerOpen: true,
            toggleDrawer: mockToggleDrawer,
        });
        rerender(<Header />);

        expect(notificationTrigger).toHaveAttribute('aria-expanded', 'true');
    });

    it('renders user menu trigger with accessible attributes and toggles on click', () => {
        render(<Header />);

        const userTrigger = screen.getByRole('button', { name: 'User Menu' });
        expect(userTrigger).toHaveAttribute('aria-haspopup', 'menu');
        expect(userTrigger).toHaveAttribute('aria-expanded', 'false');
        expect(userTrigger).toHaveAttribute('aria-controls', 'header-user-menu');

        fireEvent.click(userTrigger);
        expect(userTrigger).toHaveAttribute('aria-expanded', 'true');

        const userMenu = screen.getByRole('menu', { name: 'User Menu' });
        expect(userMenu).toBeInTheDocument();

        const menuItem = screen.getByRole('menuitem', { name: 'Sign Out' });
        expect(menuItem).toBeInTheDocument();
        expect(userMenu).toHaveFocus();
        fireEvent.keyDown(userMenu, { key: 'Enter' });
        expect(mockLogout).not.toHaveBeenCalled();
    });

    it('opens user menu with ArrowDown from trigger and focuses first item', () => {
        render(<Header />);

        const userTrigger = screen.getByRole('button', { name: 'User Menu' });
        userTrigger.focus();
        fireEvent.keyDown(userTrigger, { key: 'ArrowDown' });

        expect(userTrigger).toHaveAttribute('aria-expanded', 'true');
        const menuItem = screen.getByRole('menuitem', { name: 'Sign Out' });
        expect(document.activeElement).toBe(menuItem);
    });

    it('opens user menu with ArrowUp from trigger and focuses last item', () => {
        render(<Header />);

        const userTrigger = screen.getByRole('button', { name: 'User Menu' });
        userTrigger.focus();
        fireEvent.keyDown(userTrigger, { key: 'ArrowUp' });

        expect(userTrigger).toHaveAttribute('aria-expanded', 'true');
        const menuItem = screen.getByRole('menuitem', { name: 'Sign Out' });
        expect(document.activeElement).toBe(menuItem);
    });

    it('handles keyboard navigation within user menu and closes on Escape', () => {
        render(<Header />);

        const userTrigger = screen.getByRole('button', { name: 'User Menu' });
        fireEvent.click(userTrigger);

        const menuItem = screen.getByRole('menuitem', { name: 'Sign Out' });
        const userMenu = screen.getByRole('menu', { name: 'User Menu' });
        expect(userMenu).toHaveFocus();
        fireEvent.keyDown(userMenu, { key: 'ArrowDown' });
        expect(menuItem).toHaveFocus();

        fireEvent.keyDown(menuItem, { key: 'ArrowDown' });
        expect(document.activeElement).toBe(menuItem);

        fireEvent.keyDown(menuItem, { key: 'ArrowUp' });
        expect(document.activeElement).toBe(menuItem);

        fireEvent.keyDown(menuItem, { key: 'Home' });
        expect(document.activeElement).toBe(menuItem);

        fireEvent.keyDown(menuItem, { key: 'End' });
        expect(document.activeElement).toBe(menuItem);

        fireEvent.keyDown(menuItem, { key: 'Escape' });
        expect(screen.queryByRole('menu')).not.toBeInTheDocument();
        expect(document.activeElement).toBe(userTrigger);
    });

    it('closes user menu when clicking outside', () => {
        render(
            <div>
                <span data-testid="outside">Outside area</span>
                <Header />
            </div>
        );

        const userTrigger = screen.getByRole('button', { name: 'User Menu' });
        fireEvent.click(userTrigger);
        expect(screen.getByRole('menu')).toBeInTheDocument();

        fireEvent.pointerDown(screen.getByTestId('outside'));
        expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    });

    it('isolates user-menu text with a scoped nearly opaque glass surface', () => {
        render(<Header />);
        fireEvent.click(screen.getByRole('button', { name: 'User Menu' }));
        const menu = screen.getByRole('menu', { name: 'User Menu' });
        expect(menu).toHaveClass('glass-panel', 'obs-header-menu');
        expect(menu).toHaveFocus();
        expect(screen.getByRole('menuitem', { name: 'Sign Out' })).not.toHaveFocus();
        const stylesheet = readFileSync(join(process.cwd(), 'src/app/globals.css'), 'utf8');
        expect(stylesheet).toContain('--obs-menu-bg: linear-gradient(180deg, rgba(16, 18, 38, 0.98) 0%, rgba(12, 10, 30, 0.99) 100%);');
        expect(stylesheet).toMatch(/\.glass-panel\.obs-header-menu\s*\{\s*background: var\(--obs-menu-bg\);/);
    });

    it('calls logout when Sign Out is clicked', () => {
        render(<Header />);

        const userTrigger = screen.getByRole('button', { name: 'User Menu' });
        fireEvent.click(userTrigger);

        const signOutButton = screen.getByRole('menuitem', { name: 'Sign Out' });
        fireEvent.click(signOutButton);

        expect(mockLogout).toHaveBeenCalledTimes(1);
    });
});
