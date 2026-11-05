import React from 'react';
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react';
import ProfileTab from './ProfileTab';

const mockRefreshSession = jest.fn();
const mockAddToast = jest.fn();
let mockUser = { id: 1, username: 'testuser', email: 'test@example.com', role: 'user' };

jest.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: mockUser,
    refreshSession: mockRefreshSession,
  }),
}));

jest.mock('@/contexts/ToastContext', () => ({
  useToast: () => ({
    addToast: mockAddToast,
  }),
}));

jest.mock('swr', () => () => ({
  data: { used_bytes: 1024, max_bytes: 1048576 },
  isLoading: false,
}));

describe('ProfileTab OPUS-005 Password Update Error State Preservation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockUser = { id: 1, username: 'testuser', email: 'test@example.com', role: 'user' };
    document.cookie = 'csrf_token=test-csrf; path=/';
    window.localStorage.setItem('af_logout_sync', 'sync-initial');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('preserves form state and does not trigger logout/refresh when backend returns 403 INVALID_CURRENT_PASSWORD', async () => {
    const expiredListener = jest.fn();
    window.addEventListener('af:session-expired', expiredListener);

    const fetchSpy = jest.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/api/v1/auth/profile/password')) {
        return {
          ok: false,
          status: 403,
          statusText: 'Forbidden',
          json: async () => ({
            code: 'INVALID_CURRENT_PASSWORD',
            message: 'Current password is incorrect.',
          }),
        } as Response;
      }
      return { ok: true, json: async () => ({}) } as Response;
    });

    render(<ProfileTab />);

    // Type an unsaved email edit in the main Profile form before opening password modal
    const emailInput = screen.getByDisplayValue('test@example.com');
    fireEvent.change(emailInput, { target: { value: 'unsaved-draft@example.com' } });

    // Click "Change Password" button to open modal
    const openModalBtn = screen.getByRole('button', { name: /Change Password/i });
    fireEvent.click(openModalBtn);

    // Enter current, new, and confirm password
    const currentInput = screen.getByPlaceholderText('Enter current password');
    const newInput = screen.getByPlaceholderText('Enter new secure password');
    const confirmInput = screen.getByPlaceholderText('Confirm new password');

    fireEvent.change(currentInput, { target: { value: 'wrong-current-pass' } });
    fireEvent.change(newInput, { target: { value: 'NewSecurePassword123' } });
    fireEvent.change(confirmInput, { target: { value: 'NewSecurePassword123' } });

    // Submit the password change form
    const submitBtn = screen.getByRole('button', { name: /Save Password/i });
    fireEvent.click(submitBtn);

    // Error should be displayed inline
    await waitFor(() => {
      expect(screen.getByText('Current password is incorrect.')).toBeInTheDocument();
    });

    // Both the unsaved email draft and the password modal inputs MUST be preserved
    expect((emailInput as HTMLInputElement).value).toBe('unsaved-draft@example.com');
    expect((currentInput as HTMLInputElement).value).toBe('wrong-current-pass');
    expect((newInput as HTMLInputElement).value).toBe('NewSecurePassword123');
    expect((confirmInput as HTMLInputElement).value).toBe('NewSecurePassword123');

    // Only the single password request was made (no /api/v1/public/auth/refresh or retry)
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    // No session expiry or cross-tab logout should have been dispatched
    window.removeEventListener('af:session-expired', expiredListener);
    expect(expiredListener).not.toHaveBeenCalled();
    expect(window.localStorage.getItem('af_logout_sync')).toBe('sync-initial');
    expect(mockRefreshSession).not.toHaveBeenCalled();
  });
});


describe('Profile email acknowledgement', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    document.cookie = 'csrf_token=test-csrf; path=/';
  });
  afterEach(() => jest.restoreAllMocks());
  it.each([false, true])('retires only the submitted draft (newer edit: %s)', async (newerEdit) => {
    mockUser = { id: 1, username: 'testuser', email: 'old@example.com', role: 'user' };
    let finish!: (response: Response) => void;
    const fetchSpy = jest.spyOn(global, 'fetch').mockImplementation(() => new Promise<Response>(resolve => { finish = resolve; }));
    mockRefreshSession.mockImplementation(async () => { mockUser = { ...mockUser, email: 'saved@example.com' }; });
    const view = render(<ProfileTab />);
    const input = screen.getByDisplayValue('old@example.com');
    fireEvent.change(input, { target: { value: 'saved@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'Update Email' }));
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1));
    expect(JSON.parse(fetchSpy.mock.calls[0][1]?.body as string)).toEqual({ email: 'saved@example.com' });
    if (newerEdit) fireEvent.change(input, { target: { value: 'newer@example.com' } });
    await act(async () => finish({ ok: true, status: 200, json: async () => ({}) } as Response));
    await waitFor(() => expect(screen.queryByText('Saving...')).not.toBeInTheDocument());
    mockUser = { ...mockUser, email: 'remote-update@example.com' };
    view.rerender(<ProfileTab />);
    expect(input).toHaveValue(newerEdit ? 'newer@example.com' : 'remote-update@example.com');
  });
});
