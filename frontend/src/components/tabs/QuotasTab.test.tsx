import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import useSWR from 'swr';
import QuotasTab from './QuotasTab';
import { apiFetch } from '@/lib/fetcher';
const mockMutate = jest.fn();
jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ addToast: jest.fn() }) }));
jest.mock('swr', () => jest.fn(() => ({ data: { quotas: [
  { user_id: 1, username: 'alice', quota_bytes: 1610612736, used_bytes: 0, configured: true },
  { user_id: 2, username: 'bob', quota_bytes: 12345, used_bytes: 0, configured: true },
  { user_id: 3, username: 'sarah.chen.cluster-operator-systems-lead', quota_bytes: 1000000000000, used_bytes: 900000000000, usage_pct: 90, configured: true },
] }, mutate: mockMutate })));
it.each([
  { name: 'legacy percentage', values: { percentage: 90 }, expected: 90 },
  { name: 'byte totals', values: {}, expected: 95 },
  { name: 'explicit zero', values: { usage_pct: 0, percentage: 90 }, expected: 0 },
  { name: 'negative percentage', values: { usage_pct: -5 }, expected: 0 },
  { name: 'non-finite percentage', values: { usage_pct: Number.NaN }, expected: 0 },
  { name: 'infinite percentage', values: { usage_pct: Number.POSITIVE_INFINITY }, expected: 0 },
  { name: 'zero ceiling', values: { quota_bytes: 0 }, expected: 0 },
  { name: 'over-quota usage', values: { usage_pct: 125 }, expected: 125 },
])('normalizes $name consistently in the utilization text and progressbar', ({ values, expected }) => {
  (useSWR as jest.Mock).mockReturnValueOnce({
    data: { quotas: [{ user_id: 1, username: 'operator', quota_bytes: 1000, used_bytes: 950, configured: true, ...values }] },
    mutate: mockMutate,
  });
  render(<QuotasTab />);
  const track = screen.getByRole('progressbar', { name: 'operator storage utilization' });
  expect(track).toHaveAttribute('aria-valuenow', String(Math.min(100, expected)));
  expect(track).toHaveAttribute('aria-valuetext', `${expected.toFixed(1)}%`);
  expect(track.firstElementChild).toHaveStyle({ width: `${Math.min(100, expected)}%` });
  expect(track.parentElement).toHaveTextContent(`${expected.toFixed(1)}%`);
  if (expected >= 95) expect(track.firstElementChild).toHaveClass('from-rose-500');
  else if (expected >= 80) expect(track.firstElementChild).toHaveClass('from-amber-500');
  else expect(track.firstElementChild).toHaveClass('from-indigo-500');
});
it('keeps exact fractional and small quotas when opening the form', () => {
  render(<QuotasTab />);
  fireEvent.click(screen.getAllByRole('button', { name: 'Edit Quota' })[0]);
  expect(screen.getByPlaceholderText('e.g. 50GB, 250GB, 1TB')).toHaveValue('1536MB');
  expect(screen.getByText('Current allocation: 1.5 GB')).toBeVisible();
  expect(screen.getByText('1,610,612,736 bytes exactly')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  fireEvent.click(screen.getAllByRole('button', { name: 'Edit Quota' })[1]);
  expect(screen.getByPlaceholderText('e.g. 50GB, 250GB, 1TB')).toHaveValue('12345B');
});
it('aligns utilization tracks in fixed shared grid columns independently of identity length', () => {
  const { container } = render(<QuotasTab />);
  const rows = container.querySelectorAll('[data-quota-row="true"]');
  expect(rows).toHaveLength(3);
  rows.forEach(row => expect(row).toHaveClass('grid', 'md:grid-cols-[minmax(0,1fr)_minmax(0,1.25fr)_auto]'));
  const track = screen.getByRole('progressbar', { name: 'sarah.chen.cluster-operator-systems-lead storage utilization' });
  expect(track).toHaveAttribute('aria-valuenow', '90');
  expect(track).toHaveAttribute('aria-valuetext', '90.0%');
  expect(track.parentElement).toHaveClass('w-full', 'min-w-0');
  expect(track.parentElement).not.toHaveClass('max-w-md');
  expect(screen.getByText('sarah.chen.cluster-operator-systems-lead')).toHaveClass('min-w-0', '[overflow-wrap:anywhere]');
  expect(screen.getByRole('button', { name: /Storage summary/ })).toHaveAttribute('aria-expanded', 'false');
});

it('contains quota editing focus and restores the exact opener on Escape', async () => {
  const user = userEvent.setup();
  render(<QuotasTab />);
  const opener = screen.getAllByRole('button', { name: 'Edit Quota' })[1];
  opener.focus();
  await user.keyboard('{Enter}');
  expect(screen.getByRole('dialog', { name: 'Update Disk Quota' })).toBeVisible();
  const quotaInput = screen.getByRole('textbox', { name: 'Allocated Disk Space' });
  expect(quotaInput).toHaveFocus();
  await user.tab();
  expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
  await user.tab();
  expect(screen.getByRole('button', { name: 'Apply Quota' })).toHaveFocus();
  await user.tab();
  expect(screen.getByRole('button', { name: 'Close Update Disk Quota' })).toHaveFocus();
  await user.tab();
  expect(quotaInput).toHaveFocus();
  await user.keyboard('{Escape}');
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(opener).toHaveFocus();
});
it.each(['edit', 'reopen'])('preserves a newer draft after an earlier save (%s)', async (change) => {
  let finish!: (value: Response) => void;
  jest.mocked(apiFetch).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  render(<QuotasTab />);
  fireEvent.click(screen.getAllByRole('button', { name: 'Edit Quota' })[0]);
  fireEvent.click(screen.getByRole('button', { name: 'Apply Quota' }));
  if (change === 'reopen') {
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    fireEvent.click(screen.getAllByRole('button', { name: 'Edit Quota' })[1]);
  }
  fireEvent.change(screen.getByPlaceholderText('e.g. 50GB, 250GB, 1TB'), { target: { value: '42GB' } });
  finish({ ok: true } as Response);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Apply Quota' })).toBeEnabled());
  expect(screen.getByPlaceholderText('e.g. 50GB, 250GB, 1TB')).toHaveValue('42GB');
});
