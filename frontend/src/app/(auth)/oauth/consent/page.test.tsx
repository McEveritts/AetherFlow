import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import ConsentPage from './page';
import { apiFetch } from '@/lib/fetcher';

const mockReplace = jest.fn();
let currentSearchParams = new URLSearchParams();
let mockAuthState = {
    isAuthenticated: true,
    isLoading: false,
};

jest.mock('next/navigation', () => ({
    useRouter: () => ({
        replace: mockReplace,
    }),
    useSearchParams: () => currentSearchParams,
}));

jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => mockAuthState,
}));

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

jest.mock('framer-motion', () => ({
    motion: {
        div: ({ children, className }: { children: React.ReactNode; className?: string }) => (
            <div className={className}>{children}</div>
        ),
    },
}));

describe('ConsentPage (/oauth/consent)', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockAuthState = {
            isAuthenticated: true,
            isLoading: false,
        };
        currentSearchParams = new URLSearchParams({
            client_id: 'aetherflow-cli',
            redirect_uri: 'https://client.example.com/callback',
            response_type: 'code',
            scope: 'openid profile email',
            state: 'state-xyz-123',
            nonce: 'nonce-abc-987',
            code_challenge: 'challenge-pkce-456',
            code_challenge_method: 'S256',
        });
    });

    it('forwards the nonce query parameter and PKCE fields in the POST /api/v1/auth/oidc/consent JSON payload', async () => {
        (apiFetch as jest.Mock).mockResolvedValue({
            ok: false,
            status: 400,
            json: async () => ({ message: 'Consent captured for inspection' }),
        });

        render(<ConsentPage />);

        expect(screen.getByText('aetherflow-cli')).toBeInTheDocument();
        const grantBtn = screen.getByRole('button', { name: /Grant Authorization/i });
        fireEvent.click(grantBtn);

        await waitFor(() => {
            expect(apiFetch).toHaveBeenCalledWith(
                '/api/v1/auth/oidc/consent',
                expect.objectContaining({
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                })
            );
        });

        const [, requestInit] = (apiFetch as jest.Mock).mock.calls[0];
        const parsedBody = JSON.parse(requestInit.body);
        expect(parsedBody).toEqual({
            client_id: 'aetherflow-cli',
            redirect_uri: 'https://client.example.com/callback',
            response_type: 'code',
            scope: 'openid profile email',
            state: 'state-xyz-123',
            nonce: 'nonce-abc-987',
            code_challenge: 'challenge-pkce-456',
            code_challenge_method: 'S256',
            approved: true,
        });
    });

    it('defaults nonce to empty string when omitted from query parameters and submits approved=false on deny', async () => {
        currentSearchParams = new URLSearchParams({
            client_id: 'aetherflow-web',
            redirect_uri: 'https://web.example.com/cb',
            response_type: 'code',
        });

        (apiFetch as jest.Mock).mockResolvedValue({
            ok: false,
            status: 400,
            json: async () => ({ error: 'Denied' }),
        });

        render(<ConsentPage />);

        const denyBtn = screen.getByRole('button', { name: /Reject & Revoke/i });
        fireEvent.click(denyBtn);

        await waitFor(() => {
            expect(apiFetch).toHaveBeenCalledTimes(1);
        });

        const [, requestInit] = (apiFetch as jest.Mock).mock.calls[0];
        const parsedBody = JSON.parse(requestInit.body);
        expect(parsedBody).toEqual({
            client_id: 'aetherflow-web',
            redirect_uri: 'https://web.example.com/cb',
            response_type: 'code',
            scope: 'openid profile email',
            state: '',
            nonce: '',
            code_challenge: '',
            code_challenge_method: '',
            approved: false,
        });
    });
});
