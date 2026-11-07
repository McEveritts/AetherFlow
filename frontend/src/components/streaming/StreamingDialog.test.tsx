import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import StreamingDialog from './StreamingDialog';

describe('StreamingDialog', () => {
    it('renders dialog overlay via React portal directly in document body outside parent container', () => {
        const handleClose = jest.fn();
        render(
            <div data-testid="parent-container">
                <StreamingDialog name="Configure Server" onClose={handleClose}>
                    <p>Dialog Body</p>
                </StreamingDialog>
            </div>
        );

        const dialogElement = screen.getByRole('dialog', { name: 'Configure Server' });
        expect(dialogElement).toBeInTheDocument();
        expect(dialogElement).toHaveAttribute('aria-modal', 'true');

        const parentContainer = screen.getByTestId('parent-container');
        expect(parentContainer.querySelector('[role="dialog"]')).toBeNull();
        expect(document.body.contains(dialogElement)).toBe(true);
    });

    it('dismisses on Escape key press', () => {
        const handleClose = jest.fn();
        render(
            <StreamingDialog name="Test Dialog" onClose={handleClose}>
                <button type="button">Inside Button</button>
            </StreamingDialog>
        );

        fireEvent.keyDown(document, { key: 'Escape' });
        expect(handleClose).toHaveBeenCalledTimes(1);
    });

    it('dismisses when clicking the backdrop overlay but not when clicking inside dialog panel', () => {
        const handleClose = jest.fn();
        render(
            <StreamingDialog name="Test Dialog" onClose={handleClose}>
                <div data-testid="inner-content">
                    <button type="button">Action</button>
                </div>
            </StreamingDialog>
        );

        const innerContent = screen.getByTestId('inner-content');
        fireEvent.click(innerContent);
        expect(handleClose).not.toHaveBeenCalled();

        const dialogElement = screen.getByRole('dialog', { name: 'Test Dialog' });
        const backdropElement = dialogElement.parentElement as HTMLElement;
        fireEvent.click(backdropElement);
        expect(handleClose).toHaveBeenCalledTimes(1);
    });

    it('focuses first focusable element on mount, traps Tab navigation, and restores focus on unmount', () => {
        function DialogHarness() {
            const [isOpen, setIsOpen] = useState(false);
            return (
                <div>
                    <button
                        type="button"
                        data-testid="invoker-button"
                        onClick={() => setIsOpen(true)}
                    >
                        Open Dialog
                    </button>
                    {isOpen && (
                        <StreamingDialog name="Trap Dialog" onClose={() => setIsOpen(false)}>
                            <button type="button" data-testid="first-button">First</button>
                            <button type="button" data-testid="second-button">Second</button>
                        </StreamingDialog>
                    )}
                </div>
            );
        }

        render(<DialogHarness />);
        const invokerButton = screen.getByTestId('invoker-button');
        invokerButton.focus();
        expect(document.activeElement).toBe(invokerButton);

        fireEvent.click(invokerButton);

        const firstButton = screen.getByTestId('first-button');
        const secondButton = screen.getByTestId('second-button');
        expect(document.activeElement).toBe(firstButton);

        fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
        expect(document.activeElement).toBe(secondButton);

        fireEvent.keyDown(document, { key: 'Tab', shiftKey: false });
        expect(document.activeElement).toBe(firstButton);

        fireEvent.keyDown(document, { key: 'Escape' });
        expect(document.activeElement).toBe(invokerButton);
    });
});
