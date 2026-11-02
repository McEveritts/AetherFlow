import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ExternalAccessCard } from './ExternalAccessCard';
import { useIngressStore } from '@/store/useIngressStore';

jest.mock('swr', () => ({ __esModule: true, default: () => ({ data: undefined }) }));

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

const { apiFetch } = jest.requireMock('@/lib/fetcher') as {
    apiFetch: jest.Mock;
};

describe('ExternalAccessCard and useIngressStore', () => {
    beforeEach(() => {
        apiFetch.mockReset();
        useIngressStore.setState({
            configs: {},
            isSaving: false,
            error: null,
            fetchConfigs: async () => {},
        });
    });

    it('preserves listenPort and explicit tlsEnabled on domain and toggle saves and applies authoritative server config', async () => {
        useIngressStore.setState({
            configs: {
                sonarr: {
                    appName: 'sonarr',
                    publicDomain: 'sonarr.old.example.com',
                    externalAccessEnabled: true,
                    listenPort: 8989,
                    tlsEnabled: false,
                    createdAt: '2026-11-01T00:00:00Z',
                    updatedAt: '2026-11-01T00:00:00Z',
                },
            },
            isSaving: false,
            error: null,
        });

        apiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                status: 'updated',
                app: 'sonarr',
                reloadSuggested: true,
                config: {
                    appName: 'sonarr',
                    publicDomain: 'sonarr.new.example.com',
                    externalAccessEnabled: true,
                    listenPort: 8989,
                    tlsEnabled: false,
                    createdAt: '2026-11-01T00:00:00Z',
                    updatedAt: '2026-11-02T12:00:00Z',
                },
            }),
        });

        render(<ExternalAccessCard appName="sonarr" />);

        const input = screen.getByRole('textbox');
        fireEvent.change(input, { target: { value: 'sonarr.new.example.com' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save' }));

        await waitFor(() => {
            expect(apiFetch).toHaveBeenCalledWith(
                '/api/v1/admin/ingress/apps/sonarr',
                expect.objectContaining({
                    method: 'PUT',
                    body: JSON.stringify({
                        appName: 'sonarr',
                        publicDomain: 'sonarr.new.example.com',
                        externalAccessEnabled: true,
                        listenPort: 8989,
                        tlsEnabled: false,
                    }),
                })
            );
        });

        expect(useIngressStore.getState().configs.sonarr).toEqual({
            appName: 'sonarr',
            publicDomain: 'sonarr.new.example.com',
            externalAccessEnabled: true,
            listenPort: 8989,
            tlsEnabled: false,
            createdAt: '2026-11-01T00:00:00Z',
            updatedAt: '2026-11-02T12:00:00Z',
        });
    });

    it('surfaces save errors visibly instead of silently swallowing failed ingress updates', async () => {
        useIngressStore.setState({
            configs: {
                radarr: {
                    appName: 'radarr',
                    publicDomain: 'radarr.example.com',
                    externalAccessEnabled: false,
                    listenPort: 7878,
                    tlsEnabled: true,
                },
            },
            isSaving: false,
            error: null,
        });

        apiFetch.mockResolvedValueOnce({
            ok: false,
            json: async () => ({
                error: 'listenPort is out of valid range',
            }),
        });

        render(<ExternalAccessCard appName="radarr" />);

        fireEvent.click(screen.getByRole('switch'));

        await waitFor(() => {
            expect(screen.getByRole('alert')).toHaveTextContent('listenPort is out of valid range');
        });
        expect(useIngressStore.getState().error).toBe('listenPort is out of valid range');
    });
});
