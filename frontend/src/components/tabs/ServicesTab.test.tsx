import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import ServicesTab from '@/components/tabs/ServicesTab';

const mockAddToast = jest.fn();
const mockSetActiveTab = jest.fn();
let mockServicesPayload: Record<string, unknown> = {};

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
    }),
}));

jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => ({
        user: { id: 1, username: 'admin', role: 'admin' },
        isAuthenticated: true,
    }),
}));

jest.mock('@/store/useSystemStore', () => ({
    useSystemStore: () => ({
        setActiveTab: mockSetActiveTab,
    }),
}));

jest.mock('@/components/auth/RequireClaim', () => {
    return function MockRequireClaim({ children }: { children: React.ReactNode }) {
        return <>{children}</>;
    };
});

jest.mock('@/components/tabs/ServiceLogsModal', () => {
    return function MockServiceLogsModal() {
        return null;
    };
});

jest.mock('@/components/ingress/ExternalAccessCard', () => ({
    ExternalAccessCard: () => null,
}));

jest.mock('@/components/deploy/DeploymentStatus', () => ({
    DeploymentStatus: () => null,
}));

jest.mock('swr', () => {
    const useSWRMock = jest.fn((key: string) => {
        if (key === '/api/v1/auth/services') {
            return {
                data: mockServicesPayload,
                mutate: jest.fn(),
                isLoading: false,
            };
        }
        return { data: null, mutate: jest.fn(), isLoading: false };
    });
    return {
        __esModule: true,
        default: useSWRMock,
        useSWRConfig: () => ({
            mutate: jest.fn(),
        }),
    };
});

describe('ServicesTab Maintainerr Loopback Web UI Contract', () => {
    let openSpy: jest.SpyInstance;

    beforeEach(() => {
        mockAddToast.mockReset();
        mockSetActiveTab.mockReset();
        openSpy = jest.spyOn(window, 'open').mockImplementation(() => null);
    });

    afterEach(() => {
        openSpy.mockRestore();
    });

    it('disables direct Web UI and Settings shortcuts on remote browser when external access is disabled', () => {
        mockServicesPayload = {
            Maintainerr: {
                id: 'maintainerr',
                process: 'af-maintainerr',
                status: 'running',
                version: '3.31.0',
                uptime: '2h 10m',
                managed_by: 'systemd',
                default_port: 6246,
                active_port: 6246,
                external_access_enabled: false,
                public_domain: '',
                web_path: '/',
            },
        };

        render(<ServicesTab browserOrigin={{ protocol: 'https:', hostname: 'seedbox.example.com' }} />);

        const webUiButton = screen.getByRole('button', { name: /^Web UI$/i });
        const restrictedButtons = screen.getAllByTitle(/Maintainerr binds strictly to 127\.0\.0\.1/i);
        const ingressButton = screen.getByTitle('Ingress & Deployment');

        expect(webUiButton).toBeDisabled();
        expect(webUiButton).toHaveAttribute(
            'title',
            expect.stringMatching(/Maintainerr binds strictly to 127\.0\.0\.1/i)
        );
        expect(restrictedButtons).toHaveLength(2);
        for (const button of restrictedButtons) {
            expect(button).toBeDisabled();
        }
        expect(ingressButton).not.toBeDisabled();

        fireEvent.click(webUiButton);
        expect(openSpy).not.toHaveBeenCalled();
    });

    it('opens the configured public domain on remote browser when external access is enabled', () => {
        mockServicesPayload = {
            Maintainerr: {
                id: 'maintainerr',
                process: 'af-maintainerr',
                status: 'running',
                version: '3.31.0',
                uptime: '2h 10m',
                managed_by: 'systemd',
                default_port: 6246,
                active_port: 17846,
                external_access_enabled: true,
                public_domain: 'maintainerr.example.com',
                tls_enabled: true,
                web_path: '/',
            },
        };

        render(<ServicesTab browserOrigin={{ protocol: 'https:', hostname: 'seedbox.example.com' }} />);

        const webUiButton = screen.getByRole('button', { name: /Web UI/i });
        expect(webUiButton).not.toBeDisabled();

        fireEvent.click(webUiButton);
        expect(openSpy).toHaveBeenCalledWith('https://maintainerr.example.com/', '_blank');
    });

    it.each([
        ['http:', 'localhost'],
        ['https:', 'localhost'],
        ['http:', '127.0.0.1'],
        ['https:', '127.0.0.1'],
        ['http:', '::1'],
        ['https:', '::1'],
        ['http:', '[::1]'],
        ['https:', '[::1]'],
    ])('uses the IPv4 HTTP listener for a local browser at %s//%s without public ingress', (protocol, hostname) => {
        mockServicesPayload = {
            Maintainerr: {
                id: 'maintainerr',
                process: 'af-maintainerr',
                status: 'running',
                version: '3.31.0',
                uptime: '2h 10m',
                managed_by: 'systemd',
                default_port: 6246,
                active_port: 17846,
                external_access_enabled: false,
                public_domain: '',
                web_path: '/',
            },
        };

        render(<ServicesTab browserOrigin={{ protocol, hostname }} />);

        const webUiButton = screen.getByRole('button', { name: /Web UI/i });
        expect(webUiButton).not.toBeDisabled();

        fireEvent.click(webUiButton);
        expect(openSpy).toHaveBeenCalledWith('http://127.0.0.1:17846/', '_blank');
    });

    it('leaves non-Maintainerr applications unaffected on remote browsers without public ingress', () => {
        mockServicesPayload = {
            Sonarr: {
                id: 'sonarr',
                process: 'sonarr',
                status: 'running',
                version: '4.0.0',
                uptime: '5d',
                managed_by: 'systemd',
                default_port: 8989,
                active_port: 8989,
                external_access_enabled: false,
                public_domain: '',
                web_path: '/',
            },
        };

        render(<ServicesTab browserOrigin={{ protocol: 'https:', hostname: 'seedbox.example.com' }} />);

        const webUiButton = screen.getByRole('button', { name: /Web UI/i });
        expect(webUiButton).not.toBeDisabled();

        fireEvent.click(webUiButton);
        expect(openSpy).toHaveBeenCalledWith('https://seedbox.example.com:8989/', '_blank');
    });
});
