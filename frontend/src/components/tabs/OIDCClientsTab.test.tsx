import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import OIDCClientsTab from './OIDCClientsTab';

jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({ addToast: jest.fn() }),
}));

const mockClients = [
    {
        id: 'client-app-1',
        name: 'Grafana SSO',
        redirect_uris: JSON.stringify(['https://grafana.internal/oauth/callback']),
        created_at: '2026-11-01T00:00:00Z',
    },
];

jest.mock('swr', () => () => ({
    data: mockClients,
    isLoading: false,
    error: null,
    mutate: jest.fn(),
}));

describe('OIDCClientsTab', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('renders OIDC clients list with action buttons and redirect URIs', () => {
        render(<OIDCClientsTab />);
        expect(screen.getByText('Client Applications')).toBeInTheDocument();
        expect(screen.getByText('Grafana SSO')).toBeInTheDocument();
        expect(screen.getByText('client-app-1')).toBeInTheDocument();
        expect(screen.getByText('https://grafana.internal/oauth/callback')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /New Client/i })).toBeInTheDocument();
    });

    it('preserves complete visible client names and identifiers instead of clipping them', () => {
        render(<OIDCClientsTab />);
        expect(screen.getByText('Grafana SSO')).toHaveClass('break-words');
        expect(screen.getByText('Grafana SSO')).toHaveAttribute('title', 'Grafana SSO');
        expect(screen.getByText('client-app-1')).toHaveClass('break-all');
        expect(screen.getByText('client-app-1')).toHaveAttribute('title', 'client-app-1');
    });

    it('opens create client modal when New Client button is clicked', () => {
        render(<OIDCClientsTab />);
        fireEvent.click(screen.getByRole('button', { name: /New Client/i }));
        expect(screen.getByText('Create OIDC Client')).toBeInTheDocument();
        expect(screen.getByPlaceholderText('My Application')).toBeInTheDocument();
    });
});
