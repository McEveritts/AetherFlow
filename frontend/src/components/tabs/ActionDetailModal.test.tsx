import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { ActionDetailModal } from './ActionDetailModal';
import type { PendingAction } from '@/types/api';

const sampleLongAction: PendingAction = {
    id: 42,
    action: 'Apply bandwidth throttle to client 198.51.100.82',
    source: 'SecurityGateway',
    classification: 'critical',
    reason: 'Sustained abnormal bandwidth consumption on egress pipe',
    execution_log: 'tc qdisc replace dev eth0 root handle 1: htb default 30',
    created_at: '2026-11-08T10:00:00.000Z',
    resolved_by: 'OperatorAdmin',
    resolved_at: '2026-11-08T10:15:00.000Z',
    status: 'pending',
};

interface HarnessProps {
    action?: PendingAction | null;
    onApprove?: (actionId: number) => void;
    onReject?: (actionId: number) => void;
    onClose?: () => void;
    isProcessing?: boolean;
}

function ActionDetailModalHarness({
    action = sampleLongAction,
    onApprove = jest.fn(),
    onReject = jest.fn(),
    onClose = jest.fn(),
    isProcessing = false,
}: HarnessProps) {
    const [isOpen, setIsOpen] = useState(false);

    return (
        <div>
            <button
                type="button"
                onClick={() => setIsOpen(true)}
            >
                Open action details
            </button>
            <ActionDetailModal
                action={action}
                isOpen={isOpen}
                onClose={() => {
                    setIsOpen(false);
                    onClose();
                }}
                onApprove={onApprove}
                onReject={onReject}
                isProcessing={isProcessing}
            />
        </div>
    );
}

describe('ActionDetailModal Accessibility & Focus Lifecycle', () => {
    it('renders action-specific accessible name, wraps long title, and avoids duplicate headings', () => {
        render(<ActionDetailModalHarness />);
        const invokerButton = screen.getByRole('button', { name: 'Open action details' });
        invokerButton.focus();
        fireEvent.click(invokerButton);

        const dialogElement = screen.getByRole('dialog', {
            name: 'Apply bandwidth throttle to client 198.51.100.82',
        });
        expect(dialogElement).toBeInTheDocument();

        const headings = screen.getAllByRole('heading', {
            name: 'Apply bandwidth throttle to client 198.51.100.82',
        });
        expect(headings).toHaveLength(1);
        expect(headings[0]).toHaveClass('min-w-0', 'break-words');

        const closeButton = screen.getByRole('button', {
            name: 'Close Apply bandwidth throttle to client 198.51.100.82',
        });
        expect(closeButton).toHaveClass('shrink-0');
    });

    it('places neutral initial focus on header close control instead of consequential AUTHORIZE EXECUTION', () => {
        render(<ActionDetailModalHarness />);
        const invokerButton = screen.getByRole('button', { name: 'Open action details' });
        invokerButton.focus();
        fireEvent.click(invokerButton);

        const closeButton = screen.getByRole('button', {
            name: 'Close Apply bandwidth throttle to client 198.51.100.82',
        });
        const authorizeButton = screen.getByRole('button', { name: 'AUTHORIZE EXECUTION' });

        expect(document.activeElement).toBe(closeButton);
        expect(document.activeElement).not.toBe(authorizeButton);
    });

    it('keeps approval and rejection visually distinct through semantic glass variants', () => {
        render(<ActionDetailModalHarness />);
        fireEvent.click(screen.getByRole('button', { name: 'Open action details' }));

        expect(screen.getByRole('button', { name: 'AUTHORIZE EXECUTION' })).toHaveAttribute('data-tone', 'success');
        expect(screen.getByRole('button', { name: 'REJECT' })).toHaveAttribute('data-tone', 'danger');
    });

    it('dismisses neutrally via close button without approving or rejecting and restores focus to invoker', () => {
        const mockApprove = jest.fn();
        const mockReject = jest.fn();
        const mockClose = jest.fn();

        render(
            <ActionDetailModalHarness
                onApprove={mockApprove}
                onReject={mockReject}
                onClose={mockClose}
            />
        );

        const invokerButton = screen.getByRole('button', { name: 'Open action details' });
        invokerButton.focus();
        fireEvent.click(invokerButton);

        const closeButton = screen.getByRole('button', {
            name: 'Close Apply bandwidth throttle to client 198.51.100.82',
        });
        fireEvent.click(closeButton);

        expect(mockClose).toHaveBeenCalledTimes(1);
        expect(mockApprove).not.toHaveBeenCalled();
        expect(mockReject).not.toHaveBeenCalled();
        expect(document.activeElement).toBe(invokerButton);
    });

    it('dismisses neutrally via Escape without approving or rejecting and restores focus to invoker', () => {
        const mockApprove = jest.fn();
        const mockReject = jest.fn();
        const mockClose = jest.fn();

        render(
            <ActionDetailModalHarness
                onApprove={mockApprove}
                onReject={mockReject}
                onClose={mockClose}
            />
        );

        const invokerButton = screen.getByRole('button', { name: 'Open action details' });
        invokerButton.focus();
        fireEvent.click(invokerButton);

        fireEvent.keyDown(document, { key: 'Escape' });

        expect(mockClose).toHaveBeenCalledTimes(1);
        expect(mockApprove).not.toHaveBeenCalled();
        expect(mockReject).not.toHaveBeenCalled();
        expect(document.activeElement).toBe(invokerButton);
    });

    it('executes approve callback once when AUTHORIZE EXECUTION is clicked', () => {
        const mockApprove = jest.fn();
        const mockReject = jest.fn();
        const mockClose = jest.fn();

        render(
            <ActionDetailModalHarness
                onApprove={mockApprove}
                onReject={mockReject}
                onClose={mockClose}
            />
        );

        const invokerButton = screen.getByRole('button', { name: 'Open action details' });
        invokerButton.focus();
        fireEvent.click(invokerButton);

        const authorizeButton = screen.getByRole('button', { name: 'AUTHORIZE EXECUTION' });
        fireEvent.click(authorizeButton);

        expect(mockApprove).toHaveBeenCalledTimes(1);
        expect(mockApprove).toHaveBeenCalledWith(42);
        expect(mockReject).not.toHaveBeenCalled();
        expect(mockClose).toHaveBeenCalledTimes(1);
    });

    it('executes reject callback once when REJECT is clicked', () => {
        const mockApprove = jest.fn();
        const mockReject = jest.fn();
        const mockClose = jest.fn();

        render(
            <ActionDetailModalHarness
                onApprove={mockApprove}
                onReject={mockReject}
                onClose={mockClose}
            />
        );

        const invokerButton = screen.getByRole('button', { name: 'Open action details' });
        invokerButton.focus();
        fireEvent.click(invokerButton);

        const rejectButton = screen.getByRole('button', { name: 'REJECT' });
        fireEvent.click(rejectButton);

        expect(mockReject).toHaveBeenCalledTimes(1);
        expect(mockReject).toHaveBeenCalledWith(42);
        expect(mockApprove).not.toHaveBeenCalled();
        expect(mockClose).toHaveBeenCalledTimes(1);
    });

    it('preserves all metadata fields, logs, reason, and uses readable text size without 10px classes', () => {
        const { container } = render(
            <ActionDetailModal
                action={sampleLongAction}
                isOpen={true}
                onClose={jest.fn()}
                onApprove={jest.fn()}
                onReject={jest.fn()}
                isProcessing={false}
            />
        );

        expect(screen.getByText('SecurityGateway')).toBeInTheDocument();
        expect(screen.getByText('Sustained abnormal bandwidth consumption on egress pipe')).toBeInTheDocument();
        expect(screen.getByText('tc qdisc replace dev eth0 root handle 1: htb default 30')).toBeInTheDocument();
        expect(screen.getByText('OperatorAdmin')).toBeInTheDocument();
        expect(screen.getByText('Critical')).toBeInTheDocument();
        expect(screen.getByText('#42')).toBeInTheDocument();

        expect(container.innerHTML).not.toContain('text-[10px]');
    });
});
