import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AuthProvider, useAuth } from './AuthContext';

const pushMock = jest.fn();
const addToastMock = jest.fn();
const apiFetchMock = jest.fn();

jest.mock('next/navigation', () => ({
    useRouter: () => ({ push: pushMock, replace: jest.fn() }),
    usePathname: () => '/overview',
}));

jest.mock('./ToastContext', () => ({
    useToast: () => ({ addToast: addToastMock }),
    useOptionalToast: () => ({ addToast: addToastMock }),
}));

jest.mock('@/lib/fetcher', () => ({
    apiFetch: (...args: unknown[]) => apiFetchMock(...args),
}));

function LogoutHarness() {
    const { isAuthenticated, user, logout } = useAuth();
    return (
        <div>
            <span data-testid="auth-state">{isAuthenticated ? `authed:${user?.username}` : 'anon'}</span>
            <button type="button" onClick={() => void logout()}>
                Sign Out
            </button>
        </div>
    );
}

describe('AuthContext logout revocation verification', () => {
    beforeEach(() => {
        pushMock.mockReset();
        addToastMock.mockReset();
        apiFetchMock.mockReset();
    });

    it('probes /api/v1/auth/session on 401 logout and retries logout if session silently refreshed', async () => {
        apiFetchMock
            .mockResolvedValueOnce(new Response(JSON.stringify({ id: 1, username: 'admin', role: 'admin' }), { status: 200 }))
            .mockResolvedValueOnce(new Response(JSON.stringify({ code: 'UNAUTHORIZED' }), { status: 401 }))
            .mockResolvedValueOnce(new Response(JSON.stringify({ id: 1, username: 'admin', role: 'admin' }), { status: 200 }))
            .mockResolvedValueOnce(new Response(JSON.stringify({ message: 'Logged out' }), { status: 200 }));

        render(
            <AuthProvider>
                <LogoutHarness />
            </AuthProvider>,
        );

        await waitFor(() => expect(screen.getByTestId('auth-state').textContent).toBe('authed:admin'));

        fireEvent.click(screen.getByRole('button', { name: 'Sign Out' }));

        await waitFor(() => expect(screen.getByTestId('auth-state').textContent).toBe('anon'));
        expect(pushMock).toHaveBeenCalledWith('/login');
        expect(addToastMock).not.toHaveBeenCalled();
        expect(apiFetchMock).toHaveBeenCalledTimes(4);
    });

    it('refuses to clear authenticated UI state if 401 logout probe refreshes session and retry logout fails', async () => {
        apiFetchMock
            .mockResolvedValueOnce(new Response(JSON.stringify({ id: 1, username: 'admin', role: 'admin' }), { status: 200 }))
            .mockResolvedValueOnce(new Response(JSON.stringify({ code: 'UNAUTHORIZED' }), { status: 401 }))
            .mockResolvedValueOnce(new Response(JSON.stringify({ id: 1, username: 'admin', role: 'admin' }), { status: 200 }))
            .mockResolvedValueOnce(new Response(JSON.stringify({ code: 'INTERNAL_ERROR' }), { status: 500 }))
            .mockResolvedValueOnce(new Response(JSON.stringify({ id: 1, username: 'admin', role: 'admin' }), { status: 200 }));

        render(
            <AuthProvider>
                <LogoutHarness />
            </AuthProvider>,
        );

        await waitFor(() => expect(screen.getByTestId('auth-state').textContent).toBe('authed:admin'));

        fireEvent.click(screen.getByRole('button', { name: 'Sign Out' }));

        await waitFor(() =>
            expect(addToastMock).toHaveBeenCalledWith(
                expect.stringMatching(/Sign-out failed: server could not revoke your session/i),
                'error',
            ),
        );
        expect(screen.getByTestId('auth-state').textContent).toBe('authed:admin');
        expect(pushMock).not.toHaveBeenCalled();
    });
});
