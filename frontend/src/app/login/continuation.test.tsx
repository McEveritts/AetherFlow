import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import LoginPage from './page';
import { AuthProvider } from '@/contexts/AuthContext';
import { apiFetch } from '@/lib/fetcher';
import { navigateBrowser } from '@/lib/browser-navigation';
const mockPush = jest.fn();
const mockParams = { get: (key: string) => new URLSearchParams(window.location.search).get(key) };
jest.mock('next/navigation', () => ({ useRouter: () => ({ push: mockPush }), useSearchParams: () => mockParams }));
jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/lib/browser-navigation', () => ({ navigateBrowser: jest.fn() }));
jest.mock('swr', () => ({ mutate: jest.fn() }));
const destination = '/api/v1/public/oidc/authorize?client_id=fixture&state=retained&nonce=nonce';
const reply = (payload: unknown, ok = true) => ({ ok, json: async () => payload }) as Response;
let signedIn = false;
let requiresMfa = false;
beforeEach(() => {
    jest.clearAllMocks(); signedIn = false; requiresMfa = false;
    window.history.replaceState(null, '', `/login?return_to=${encodeURIComponent(destination)}`);
    jest.mocked(apiFetch).mockImplementation(async (input) => {
        if (input === '/api/v1/auth/session') return reply(signedIn ? { id: 1, username: 'admin', role: 'admin' } : {}, signedIn);
        if (input === '/api/v1/public/auth/setup/check') return reply({ setupRequired: false });
        if (input === '/api/v1/public/auth/login') {
            if (requiresMfa) return reply({ requires_mfa: true, mfa_token: 'challenge' });
            signedIn = true; return reply({ success: true });
        }
        if (input === '/api/v1/public/auth/mfa/verify') { signedIn = true; return reply({ success: true }); }
        throw new Error(`Unexpected request ${input}`);
    });
});
function mountLogin() { return render(<AuthProvider><LoginPage /></AuthProvider>); }
async function submitCredentials() {
    fireEvent.change(await screen.findByPlaceholderText('Username'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByPlaceholderText('Password'), { target: { value: 'fixture' } });
    fireEvent.click(screen.getByRole('button', { name: /Unlock the Aether/i }));
}
async function completeMfa() {
    fireEvent.click(await screen.findByText('Lost your device? Use recovery code'));
    fireEvent.change(screen.getByPlaceholderText('XXXX-XXXX'), { target: { value: 'ABCD1234' } });
    fireEvent.click(screen.getByRole('button', { name: /Authorize Action/i }));
}
test('password login resumes the API authorization request with native navigation', async () => {
    mountLogin(); await submitCredentials();
    await waitFor(() => expect(navigateBrowser).toHaveBeenCalledWith(destination));
    expect(mockPush).not.toHaveBeenCalled();
});
test('password MFA preserves continuation until factor verification succeeds', async () => {
    requiresMfa = true; mountLogin(); await submitCredentials(); await screen.findByText('Verify Identity');
    expect(navigateBrowser).not.toHaveBeenCalled(); await completeMfa();
    await waitFor(() => expect(navigateBrowser).toHaveBeenCalledWith(destination));
});
test('Google MFA removes the challenge from history while retaining the continuation', async () => {
    window.history.replaceState(null, '', `/login?mfa=google-challenge&return_to=${encodeURIComponent(destination)}`);
    mountLogin(); await screen.findByText('Verify Identity');
    expect(window.location.search).not.toContain('mfa=');
    expect(new URLSearchParams(window.location.search).get('return_to')).toBe(destination);
    await completeMfa(); await waitFor(() => expect(navigateBrowser).toHaveBeenCalledWith(destination));
});
test('Google provider handoff includes the validated local continuation', async () => {
    mountLogin(); fireEvent.click(await screen.findByRole('button', { name: /Authenticate via OIDC Core/i }));
    expect(navigateBrowser).toHaveBeenCalledWith(`/api/v1/public/auth/google/login?return_to=${encodeURIComponent(destination)}`);
});
test.each(['https://example.test/', '//example.test/', '/a/..//example.test/', '/%2fexample.test', '/%5cexample.test', '/path%0aLocation:evil', 'javascript:alert(1)'])('rejects unsafe continuation %s', async (unsafe) => {
    window.history.replaceState(null, '', `/login?return_to=${encodeURIComponent(unsafe)}`);
    mountLogin(); await submitCredentials();
    await waitFor(() => expect(mockPush).toHaveBeenCalledWith('/'));
    expect(navigateBrowser).not.toHaveBeenCalled();
});
