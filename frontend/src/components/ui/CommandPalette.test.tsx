import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { CommandPalette } from './CommandPalette';
import { useSystemStore } from '@/store/useSystemStore';

const mockToast = jest.fn();
jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockToast,
        toasts: [],
    }),
}));

function CommandPaletteHarness() {
    const [invokerClickCount, setInvokerClickCount] = useState(0);
    return (
        <div>
            <button
                type="button"
                onClick={() => setInvokerClickCount((previousCount) => previousCount + 1)}
            >
                Launch invoker
            </button>
            <button type="button">
                Background Reject
            </button>
            <CommandPalette />
        </div>
    );
}

describe('CommandPalette Focus Lifecycle & Navigation', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        useSystemStore.setState({
            isCommandPaletteOpen: false,
            activeTab: 'overview',
        });
    });

    it('opens via Ctrl+K, focuses search input, and assigns accessible dialog name', () => {
        render(<CommandPaletteHarness />);
        const invokerButton = screen.getByRole('button', { name: 'Launch invoker' });
        invokerButton.focus();

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });

        const dialogElement = screen.getByRole('dialog', { name: 'Command Palette' });
        expect(dialogElement).toBeInTheDocument();
        expect(dialogElement).toHaveAttribute('aria-modal', 'true');

        const searchInput = screen.getByPlaceholderText('Type a command or search...');
        expect(document.activeElement).toBe(searchInput);
    });

    it('traps Tab and Shift+Tab focus inside dialog without escaping to background buttons', () => {
        render(<CommandPaletteHarness />);
        const invokerButton = screen.getByRole('button', { name: 'Launch invoker' });
        invokerButton.focus();

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });

        const dialogElement = screen.getByRole('dialog', { name: 'Command Palette' });
        const searchInput = screen.getByPlaceholderText('Type a command or search...');
        const backgroundButton = screen.getByRole('button', { name: 'Background Reject' });

        expect(document.activeElement).toBe(searchInput);

        fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
        expect(document.activeElement).not.toBe(backgroundButton);
        expect(dialogElement.contains(document.activeElement)).toBe(true);

        fireEvent.keyDown(document, { key: 'Tab' });
        expect(document.activeElement).toBe(searchInput);
    });

    it('restores focus to invoker element when dismissed via Escape', () => {
        render(<CommandPaletteHarness />);
        const invokerButton = screen.getByRole('button', { name: 'Launch invoker' });
        invokerButton.focus();

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
        expect(screen.getByRole('dialog', { name: 'Command Palette' })).toBeInTheDocument();

        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.queryByRole('dialog', { name: 'Command Palette' })).not.toBeInTheDocument();
        expect(document.activeElement).toBe(invokerButton);
    });

    it('provides visible 44px close control that dismisses palette and returns focus', () => {
        render(<CommandPaletteHarness />);
        const invokerButton = screen.getByRole('button', { name: 'Launch invoker' });
        invokerButton.focus();

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
        const closeButton = screen.getByRole('button', { name: 'Close Command Palette' });
        expect(closeButton).toHaveClass('obs-touch-target-standard');

        fireEvent.click(closeButton);
        expect(screen.queryByRole('dialog', { name: 'Command Palette' })).not.toBeInTheDocument();
        expect(document.activeElement).toBe(invokerButton);
    });

    it('navigates actions with ArrowDown and ArrowUp and executes on Enter', () => {
        render(<CommandPaletteHarness />);
        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });

        const searchInput = screen.getByPlaceholderText('Type a command or search...');
        fireEvent.keyDown(searchInput, { key: 'ArrowDown' });
        fireEvent.keyDown(searchInput, { key: 'Enter' });

        expect(useSystemStore.getState().activeTab).toBe('services');
        expect(screen.queryByRole('dialog', { name: 'Command Palette' })).not.toBeInTheDocument();
    });

    it('filters commands with fuzzy search and resets query when reopened', () => {
        render(<CommandPaletteHarness />);
        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });

        const searchInput = screen.getByPlaceholderText('Type a command or search...');
        fireEvent.change(searchInput, { target: { value: 'logs' } });

        expect(screen.getByText('Ask AI: Analyze System Logs')).toBeInTheDocument();
        expect(screen.queryByText('Go to Overview')).not.toBeInTheDocument();

        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.queryByRole('dialog', { name: 'Command Palette' })).not.toBeInTheDocument();

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
        const reopenedInput = screen.getByPlaceholderText('Type a command or search...');
        expect(reopenedInput).toHaveValue('');
        expect(screen.getByText('Go to Overview')).toBeInTheDocument();
    });
});
