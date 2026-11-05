import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import LoginPage from './page';

const mockLogin = jest.fn();
const mockLoginLocal = jest.fn();

jest.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    login: mockLogin,
    loginLocal: mockLoginLocal,
  }),
}));

let mockSearchParams = new Map<string, string>();

jest.mock('next/navigation', () => ({
  useSearchParams: () => ({
    get: (key: string) => mockSearchParams.get(key) || null,
  }),
}));

describe('LoginPage OPUS-002 MFA Challenge & Google SSO Integration', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSearchParams = new Map<string, string>();
    window.history.replaceState(null, '', '/login');

    jest.spyOn(window.history, 'replaceState').mockImplementation((_state, _title, url) => {
      const urlStr = url ? url.toString() : '';
      const query = urlStr.includes('?') ? urlStr.split('?')[1] : '';
      const params = new URLSearchParams(query);
      mockSearchParams = new Map(params.entries());
    });

    jest.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/api/v1/public/auth/setup/check')) {
        return {
          ok: true,
          json: async () => ({ setupRequired: false }),
        } as Response;
      }
      return {
        ok: true,
        json: async () => ({}),
      } as Response;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('renders standard credentials step by default', async () => {
    render(<LoginPage />);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Username')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Password')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Unlock the Aether/i })).toBeInTheDocument();
    });
  });

  it('transitions to MFA challenge form when ?mfa=<challenge> is provided and clears query param from URL', async () => {
    mockSearchParams.set('mfa', 'test-google-challenge-token-123');
    window.history.replaceState(null, '', '/login?mfa=test-google-challenge-token-123');

    const replaceStateSpy = jest.spyOn(window.history, 'replaceState');

    render(<LoginPage />);

    // Should switch to identity verification step
    await waitFor(() => {
      expect(screen.getByText('Verify Identity')).toBeInTheDocument();
      expect(screen.getByText('Multi-factor authentication required')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Authorize Action/i })).toBeInTheDocument();
    });

    // Session is NOT prematurely established
    expect(mockLoginLocal).not.toHaveBeenCalled();

    // Sensitive query token must be cleared from the URL
    expect(replaceStateSpy).toHaveBeenCalledWith(null, '', '/login');
  });

  it('submits MFA code using the captured challenge token and calls loginLocal on success', async () => {
    mockSearchParams.set('mfa', 'valid-challenge-token');
    window.history.replaceState(null, '', '/login?mfa=valid-challenge-token');

    let verifyRequestBody: string | null = null;
    jest.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/api/v1/public/auth/setup/check')) {
        return {
          ok: true,
          json: async () => ({ setupRequired: false }),
        } as Response;
      }
      if (url.includes('/api/v1/public/auth/mfa/verify')) {
        verifyRequestBody = init?.body as string;
        return {
          ok: true,
          json: async () => ({ success: true }),
        } as Response;
      }
      return { ok: true, json: async () => ({}) } as Response;
    });

    render(<LoginPage />);

    await waitFor(() => {
      expect(screen.getByText('Verify Identity')).toBeInTheDocument();
    });

    // Switch to recovery code mode or enter 6-digit code
    const recoveryBtn = screen.getByText('Lost your device? Use recovery code');
    fireEvent.click(recoveryBtn);

    const recoveryInput = screen.getByPlaceholderText('XXXX-XXXX');
    fireEvent.change(recoveryInput, { target: { value: 'ABCD1234' } });

    const submitBtn = screen.getByRole('button', { name: /Authorize Action/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(mockLoginLocal).toHaveBeenCalledTimes(1);
    });

    expect(verifyRequestBody).not.toBeNull();
    const parsedBody = JSON.parse(verifyRequestBody!);
    expect(parsedBody.mfa_token).toBe('valid-challenge-token');
    expect(parsedBody.code).toBe('ABCD1234');
  });

  it('displays meaningful message for ?error=not_authorized and clears error param from URL', async () => {
    mockSearchParams.set('error', 'not_authorized');
    window.history.replaceState(null, '', '/login?error=not_authorized');

    const replaceStateSpy = jest.spyOn(window.history, 'replaceState');

    render(<LoginPage />);

    await waitFor(() => {
      expect(
        screen.getByText(/Google account is not authorized. Access is restricted to invited or allowlisted users./i)
      ).toBeInTheDocument();
    });

    expect(replaceStateSpy).toHaveBeenCalledWith(null, '', '/login');
  });

  it('allows returning to credentials mode when cancel is clicked in MFA challenge', async () => {
    mockSearchParams.set('mfa', 'cancel-challenge-token');
    render(<LoginPage />);

    await waitFor(() => {
      expect(screen.getByText('Verify Identity')).toBeInTheDocument();
    });

    const cancelBtn = screen.getByText('Cancel and return');
    fireEvent.click(cancelBtn);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Username')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('Password')).toBeInTheDocument();
    });
  });

  it('rejects invalid 6-digit TOTP code on Google MFA challenge without establishing a session', async () => {
    mockSearchParams.set('mfa', 'google-mfa-challenge-token-999');
    window.history.replaceState(null, '', '/login?mfa=google-mfa-challenge-token-999');

    let verifyPayload: Record<string, unknown> | null = null;
    jest.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/api/v1/public/auth/setup/check')) {
        return {
          ok: true,
          json: async () => ({ setupRequired: false }),
        } as Response;
      }
      if (url.includes('/api/v1/public/auth/mfa/verify')) {
        verifyPayload = JSON.parse(String(init?.body));
        return {
          ok: false,
          status: 401,
          json: async () => ({ code: 'UNAUTHORIZED', message: 'Invalid MFA verification code' }),
        } as Response;
      }
      return { ok: true, json: async () => ({}) } as Response;
    });

    render(<LoginPage />);

    await waitFor(() => {
      expect(screen.getByText('Verify Identity')).toBeInTheDocument();
    });

    const digitInputs = screen.getAllByRole('textbox');
    expect(digitInputs).toHaveLength(6);
    ['1', '2', '3', '4', '5', '6'].forEach((digit, idx) => {
      fireEvent.change(digitInputs[idx], { target: { value: digit } });
    });

    fireEvent.click(screen.getByRole('button', { name: /Authorize Action/i }));

    await waitFor(() => {
      expect(screen.getByText(/Invalid MFA verification code/i)).toBeInTheDocument();
    });

    expect(verifyPayload).toEqual({
      mfa_token: 'google-mfa-challenge-token-999',
      code: '123456',
    });
    expect(mockLoginLocal).not.toHaveBeenCalled();
  });
});
