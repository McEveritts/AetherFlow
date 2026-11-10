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

    it.each(['client_id', 'redirect_uri', 'response_type'])('offers safe recovery without authorizing when %s is missing', (missingParameter) => {
        currentSearchParams.delete(missingParameter);

        render(<ConsentPage />);

        expect(screen.getByRole('main')).toHaveAttribute('aria-labelledby', 'invalid-authorization-heading');
        expect(screen.getByRole('heading', { name: 'Invalid Authorization Request', level: 1 })).toBeInTheDocument();
        expect(screen.getByText(/No access has been granted/)).toBeInTheDocument();
        expect(screen.getByRole('heading', { name: 'Start again safely' })).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Open AetherFlow' })).toHaveAttribute('href', '/');
        expect(screen.queryByRole('button', { name: /Grant Authorization/i })).not.toBeInTheDocument();
        expect(apiFetch).not.toHaveBeenCalled();
        expect(mockReplace).not.toHaveBeenCalled();
    });

    it.each([
        ['redirect_uri', 'not-a-url'],
        ['redirect_uri', '/relative/callback'],
        ['redirect_uri', 'javascript:alert(1)'],
        ['redirect_uri', 'data:text/html,callback'],
        ['redirect_uri', 'https://client.example.com/callback#fragment'],
        ['redirect_uri', 'https://client.example.com/callback#'],
        ['redirect_uri', 'https://user:password@client.example.com/callback'],
        ['redirect_uri', 'https://@client.example.com/callback'],
        ['redirect_uri', 'https:/callback'],
        ['redirect_uri', 'https:callback'],
        ['redirect_uri', 'https:///callback'],
        ['redirect_uri', 'https://client.example.com\\callback'],
        ['redirect_uri', 'https://client.example.com/oauth\\callback'],
        ['redirect_uri', 'https://client.example.com/\\callback'],
        ['redirect_uri', ' https://client.example.com/callback '],
        ['redirect_uri', 'https://client.example.com/\ncallback'],
        ['redirect_uri', 'about:blank'],
        ['redirect_uri', 'com.example.app:'],
        ['response_type', 'token'],
        ['client_id', '   '],
    ])('rejects malformed %s=%s before presenting either consent action', (parameter, value) => {
        currentSearchParams.set(parameter, value);
        render(<ConsentPage />);
        expect(screen.getByRole('heading', { name: 'Invalid Authorization Request' })).toBeInTheDocument();
        expect(screen.getByText(/No access has been granted/)).toBeVisible();
        expect(screen.queryByRole('button', { name: /Grant Authorization|Reject & Revoke/ })).not.toBeInTheDocument();
        expect(apiFetch).not.toHaveBeenCalled();
    });

    it.each(['http://127.0.0.1:4311/callback', 'http://[::1]:4311/callback', 'com.example.app:/oauth/callback', 'myapp://callback', 'com.example.app:callback', 'https://client.example.com/callback?label=operator%40example.com', 'https://client.example.com/callback?path=raw\\callback'])('preserves absolute loopback and native callback support for %s', (redirectUri) => {
        currentSearchParams.set('redirect_uri', redirectUri);
        render(<ConsentPage />);
        expect(screen.getByRole('button', { name: 'Grant Authorization' })).toBeEnabled();
        expect(screen.getByDisplayValue(redirectUri)).toBeVisible();
        expect(apiFetch).not.toHaveBeenCalled();
    });

    it('renders unboxed brand emblem and transparent hairline-separated scopes with readable descriptions', async () => {
        render(<ConsentPage />);

        const brandLogo = document.querySelector('.obs-brand-logo');
        expect(brandLogo).toBeInTheDocument();
        expect(brandLogo).not.toHaveClass('rounded-2xl');

        const scopeListElement = screen.getByRole('list');
        expect(scopeListElement).toHaveClass('divide-y');
        expect(scopeListElement).toHaveClass('divide-white/[0.07]');

        const openidDesc = screen.getByText('Core federated identity context');
        expect(openidDesc).toHaveClass('text-slate-400');
        expect(openidDesc.closest('.rounded-xl')).toBeNull();
    });
});
