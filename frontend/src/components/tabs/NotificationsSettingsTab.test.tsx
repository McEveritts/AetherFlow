import React from 'react';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import NotificationsSettingsTab from './NotificationsSettingsTab';
import { apiFetch } from '@/lib/fetcher';

const mockMutate = jest.fn();
const mockAddToast = jest.fn();

jest.mock('swr', () => ({
    __esModule: true,
    default: (url: string) => ({
        data: url.endsWith('/rules') ? { rules: [] } : { channels: [] },
        isLoading: false,
        mutate: mockMutate,
    }),
}));
jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ addToast: mockAddToast }) }));

beforeEach(() => {
    jest.clearAllMocks();
    jest.mocked(apiFetch).mockResolvedValue({ ok: true, json: async () => ({}) } as Response);
});

it('contains rule-dialog focus, closes with Escape and retains the unsaved rule draft', async () => {
    const user = userEvent.setup();
    render(<NotificationsSettingsTab />);
    const opener = screen.getByRole('button', { name: 'Add Rule' });
    await user.click(opener);
    const dialog = screen.getByRole('dialog', { name: 'Add Alert Threshold Rule' });
    const close = within(dialog).getByRole('button', { name: 'Close Add Alert Threshold Rule' });
    expect(close).toHaveFocus();
    await user.tab({ shift: true });
    expect(within(dialog).getByRole('button', { name: 'Create Rule' })).toHaveFocus();
    await user.tab();
    expect(close).toHaveFocus();
    await user.type(screen.getByLabelText('Rule Name'), 'Preserved CPU draft');
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
    expect(apiFetch).not.toHaveBeenCalled();
    await user.click(opener);
    expect(screen.getByLabelText('Rule Name')).toHaveValue('Preserved CPU draft');
    await user.click(screen.getByRole('button', { name: 'Create Rule' }));
    await waitFor(() => expect(apiFetch).toHaveBeenCalledWith('/api/v1/admin/notifications/rules', expect.objectContaining({
        method: 'POST', body: JSON.stringify({ name: 'Preserved CPU draft', condition_type: 'cpu_usage', condition_value: '85', level: 'warning' }),
    })));
    expect(mockMutate).toHaveBeenCalledTimes(1);
});

it('contains channel-dialog focus and returns to Add Channel on neutral dismissal', async () => {
    const user = userEvent.setup();
    render(<NotificationsSettingsTab />);
    await user.click(screen.getByRole('button', { name: /Delivery Channels/ }));
    const opener = screen.getByRole('button', { name: 'Add Channel' });
    await user.click(opener);
    const dialog = screen.getByRole('dialog', { name: 'Connect Notification Channel' });
    const close = within(dialog).getByRole('button', { name: 'Close Connect Notification Channel' });
    expect(close).toHaveFocus();
    await user.tab({ shift: true });
    expect(within(dialog).getByRole('button', { name: 'Connect Channel' })).toHaveFocus();
    await user.tab();
    expect(close).toHaveFocus();
    await user.type(screen.getByLabelText('Channel Name'), 'Saved channel draft');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(opener).toHaveFocus();
    await user.click(opener);
    expect(screen.getByLabelText('Channel Name')).toHaveValue('Saved channel draft');
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
    expect(apiFetch).not.toHaveBeenCalled();
});
