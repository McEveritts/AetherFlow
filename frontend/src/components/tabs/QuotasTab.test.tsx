import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import QuotasTab from './QuotasTab';
import { apiFetch } from '@/lib/fetcher';
const mockMutate = jest.fn();
jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ addToast: jest.fn() }) }));
jest.mock('swr', () => () => ({ data: { quotas: [
  { user_id: 1, username: 'alice', quota_bytes: 1610612736, used_bytes: 0, configured: true },
  { user_id: 2, username: 'bob', quota_bytes: 12345, used_bytes: 0, configured: true },
] }, mutate: mockMutate }));
it('keeps exact fractional and small quotas when opening the form', () => {
  render(<QuotasTab />);
  fireEvent.click(screen.getAllByRole('button', { name: 'Edit Quota' })[0]);
  expect(screen.getByPlaceholderText('e.g. 50GB, 250GB, 1TB')).toHaveValue('1610612736B');
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  fireEvent.click(screen.getAllByRole('button', { name: 'Edit Quota' })[1]);
  expect(screen.getByPlaceholderText('e.g. 50GB, 250GB, 1TB')).toHaveValue('12345B');
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
