import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import SecurityTab from './SecurityTab';

const mockAddToast = jest.fn();

const currentSession = {
    jti: 'current-session',
    ip_address: '127.0.0.1',
    user_agent: 'Test Browser',
    expires_at: '2026-11-09T12:00:00Z',
    last_active: '2026-11-08T12:00:00Z',
    is_current: true,
};
const mockSessions: Array<typeof currentSession> = [];

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
    }),
}));

jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => ({
        user: {
            id: 1,
            username: 'testuser',
            email: 'test@example.com',
            role: 'user',
            totp_enabled: true,
        },
    }),
}));

jest.mock('swr', () => () => ({
    data: { sessions: mockSessions },
    mutate: jest.fn(),
    isLoading: false,
}));

describe('SecurityTab OPUS-005 2FA 403 Error Handling & Session Preservation', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockSessions.length = 0;
        document.cookie = 'csrf_token=test-csrf-token; path=/';
        window.localStorage.setItem('af_logout_sync', 'sync-initial');
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    it('identifies devices without presenting opaque session identifiers as their names', () => {
        mockSessions.push(currentSession, { ...currentSession, jti: 'opaque-remote-session', is_current: false });
        render(<SecurityTab />);

        expect(screen.getByText('This device')).toBeInTheDocument();
        expect(screen.getByText('Other signed-in device')).toBeInTheDocument();
        expect(screen.queryByText('current-...')).not.toBeInTheDocument();
        expect(screen.queryByText('opaque-r...')).not.toBeInTheDocument();
    });

    it('only enables bulk revocation while another session is active', () => {
        const { rerender } = render(<SecurityTab />);
        const revokeButton = screen.getByRole('button', { name: /Revoke All Other Sessions/i });

        expect(revokeButton).toBeDisabled();

        mockSessions.push(currentSession);
        rerender(<SecurityTab />);
        expect(revokeButton).toBeDisabled();

        mockSessions.push({ ...currentSession, jti: 'other-session', is_current: false });
        rerender(<SecurityTab />);
        expect(revokeButton).toBeEnabled();

        mockSessions.pop();
        rerender(<SecurityTab />);
        expect(revokeButton).toBeDisabled();
    });

    it('preserves 2FA disable input and session when backend returns 403 INVALID_2FA_CODE', async () => {
        const expiredListener = jest.fn();
        window.addEventListener('af:session-expired', expiredListener);

        const fetchSpy = jest.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
            const url = typeof input === 'string' ? input : input.toString();
            if (url.includes('/api/v1/auth/user/2fa/disable')) {
                return {
                    ok: false,
                    status: 403,
                    statusText: 'Forbidden',
                    json: async () => ({
                        code: 'INVALID_2FA_CODE',
                        message: 'Invalid 2FA verification code.',
                    }),
                } as Response;
            }
            return { ok: true, status: 200, json: async () => ({}) } as Response;
        });

        render(<SecurityTab />);

        fireEvent.click(screen.getByRole('button', { name: /Disable Two-Factor Authentication/i }));

        const disableInput = screen.getByPlaceholderText('000000');
        fireEvent.change(disableInput, { target: { value: '654321' } });

        const confirmDisableBtn = screen.getByRole('button', { name: /Confirm Disable/i });
        fireEvent.click(confirmDisableBtn);

        await waitFor(() => {
            expect(mockAddToast).toHaveBeenCalledWith('Invalid 2FA verification code.', 'error');
        });

        // Entered code and session must remain intact; no /api/v1/public/auth/refresh call
        expect((disableInput as HTMLInputElement).value).toBe('654321');
        expect(fetchSpy).toHaveBeenCalledTimes(1);
        expect(
            fetchSpy.mock.calls.some(([url]) => String(url).includes('/api/v1/public/auth/refresh'))
        ).toBe(false);
        expect(expiredListener).not.toHaveBeenCalled();
        expect(window.localStorage.getItem('af_logout_sync')).toBe('sync-initial');

        window.removeEventListener('af:session-expired', expiredListener);
    });
});
