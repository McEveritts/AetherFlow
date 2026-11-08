import React, { useState } from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { Modal } from './Modal';

describe('Modal', () => {
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
        expect(screen.getByRole('dialog', { name: 'Service logs' })).toBeInTheDocument();
        expect(document.activeElement).toBe(remediationTrigger);
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(screen.queryByRole('dialog', { name: 'Service logs' })).not.toBeInTheDocument();
        expect(document.activeElement).toBe(logsTrigger);
    });
});
