import React, { useState } from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { Modal } from './Modal';

describe('Modal', () => {
    it('portals above shell stacking contexts and restores the original body overflow on close and unmount', () => {
        document.body.style.overflow = 'auto';
        const { container, rerender, unmount } = render(
            <main className="relative z-10">
                <Modal isOpen title="Layered dialog" onClose={jest.fn()}>Content</Modal>
            </main>
        );
        const dialog = screen.getByRole('dialog', { name: 'Layered dialog' });
        expect(container).not.toContainElement(dialog);
        expect(dialog.parentElement?.parentElement).toBe(document.body);
        expect(dialog.parentElement).toHaveClass('z-[90]');
        expect(dialog).toHaveClass('glass-panel', 'obs-telemetry-surface');
        expect(document.body.style.overflow).toBe('hidden');

        rerender(<Modal isOpen={false} onClose={jest.fn()}>Content</Modal>);
        expect(document.body.style.overflow).toBe('auto');
        rerender(<Modal isOpen onClose={jest.fn()}>Content</Modal>);
        expect(document.body.style.overflow).toBe('hidden');
        unmount();
        expect(document.body.style.overflow).toBe('auto');
        document.body.style.overflow = '';
    });

    it('excludes roving and hidden controls from the modal tab sequence', () => {
        render(
            <Modal isOpen onClose={jest.fn()} title="Preferences">
                <button type="button" tabIndex={-1}>Roving option</button>
                <button type="button">Last control</button>
                <div hidden><button type="button">Hidden control</button></div>
                <button type="button" tabIndex={-1}>Another roving option</button>
            </Modal>
        );
        const first = screen.getByRole('button', { name: 'Close Preferences' });
        const last = screen.getByRole('button', { name: 'Last control' });
        last.focus();
        fireEvent.keyDown(last, { key: 'Tab' });
        expect(first).toHaveFocus();
        fireEvent.keyDown(first, { key: 'Tab', shiftKey: true });
        expect(last).toHaveFocus();
    });

    it('announces its title, traps keyboard focus, and restores focus after Escape', () => {
        function ModalHarness() {
            const [isOpen, setIsOpen] = useState(false);
            return (
                <div>
                    <button type="button" onClick={() => setIsOpen(true)}>Open logs</button>
                    <Modal isOpen={isOpen} title="Service logs" onClose={() => setIsOpen(false)}>
                        <button type="button">Refresh logs</button>
                    </Modal>
                </div>
            );
        }

        render(<ModalHarness />);
        const trigger = screen.getByRole('button', { name: 'Open logs' });
        trigger.focus();
        fireEvent.click(trigger);

        const dialog = screen.getByRole('dialog', { name: 'Service logs' });
        const closeButton = within(dialog).getByRole('button', { name: 'Close Service logs' });
        const refreshButton = within(dialog).getByRole('button', { name: 'Refresh logs' });
        expect(dialog).toHaveAttribute('aria-modal', 'true');
        expect(document.activeElement).toBe(closeButton);

        fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
        expect(document.activeElement).toBe(refreshButton);
        fireEvent.keyDown(document, { key: 'Tab' });
        expect(document.activeElement).toBe(closeButton);

        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.queryByRole('dialog', { name: 'Service logs' })).not.toBeInTheDocument();
        expect(document.activeElement).toBe(trigger);
    });

    it('labels titleless dialogs with their supplied accessible name', () => {
        render(
            <Modal isOpen aria-label="Remediation proposed" onClose={jest.fn()}>
                <p>Review the proposed action.</p>
            </Modal>
        );

        expect(screen.getByRole('dialog', { name: 'Remediation proposed' })).toHaveAttribute('aria-modal', 'true');
    });

    it('dismisses only the top nested dialog and restores each invoker in turn', () => {
        function NestedHarness() {
            const [logsOpen, setLogsOpen] = useState(false);
            const [remediationOpen, setRemediationOpen] = useState(false);
            return (
                <div>
                    <button type="button" onClick={() => setLogsOpen(true)}>Open logs</button>
                    <Modal isOpen={logsOpen} title="Service logs" onClose={() => setLogsOpen(false)}>
                        <button type="button" onClick={() => setRemediationOpen(true)}>Review remediation</button>
                        <Modal isOpen={remediationOpen} aria-label="Remediation proposed" onClose={() => setRemediationOpen(false)}>
                            <button type="button">Close remediation</button>
                        </Modal>
                    </Modal>
                </div>
            );
        }

        render(<NestedHarness />);
        const logsTrigger = screen.getByRole('button', { name: 'Open logs' });
        logsTrigger.focus();
        fireEvent.click(logsTrigger);
        const remediationTrigger = screen.getByRole('button', { name: 'Review remediation' });
        remediationTrigger.focus();
        fireEvent.click(remediationTrigger);
        expect(screen.getByRole('dialog', { name: 'Remediation proposed' }).contains(document.activeElement)).toBe(true);

        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.queryByRole('dialog', { name: 'Remediation proposed' })).not.toBeInTheDocument();
        expect(document.body.style.overflow).toBe('hidden');
        expect(screen.getByRole('dialog', { name: 'Service logs' })).toBeInTheDocument();
        expect(document.activeElement).toBe(remediationTrigger);
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.queryByRole('dialog', { name: 'Service logs' })).not.toBeInTheDocument();
        expect(document.activeElement).toBe(logsTrigger);
        expect(document.body.style.overflow).toBe('');
    });

    it('wraps long titles safely without colliding with the close control', () => {
        const longTitle = 'Apply bandwidth throttle to client 198.51.100.82';
        render(
            <Modal isOpen title={longTitle} onClose={jest.fn()}>
                <p>Modal content</p>
            </Modal>
        );

        const headingElement = screen.getByRole('heading', { name: longTitle });
        expect(headingElement).toHaveClass('min-w-0', 'break-words');
        const closeButtonElement = screen.getByRole('button', { name: `Close ${longTitle}` });
        expect(closeButtonElement).toHaveClass('shrink-0');
    });

    it('renders right-docked drawer presentation variant', () => {
        render(
            <Modal isOpen variant="drawer" aria-label="Drawer dialog" onClose={jest.fn()}>
                <div>Drawer content</div>
            </Modal>
        );

        const drawerDialog = screen.getByRole('dialog', { name: 'Drawer dialog' });
        expect(drawerDialog.parentElement).toHaveClass('justify-end');
        expect(drawerDialog).toHaveClass('border-l');
    });
});
