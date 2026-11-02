import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ExternalAccessCard } from './ExternalAccessCard';
import { useIngressStore } from '@/store/useIngressStore';

let mockBaseDomain: string | undefined;

jest.mock('swr', () => ({
    __esModule: true,
    default: () => ({ data: mockBaseDomain ? { baseDomain: mockBaseDomain } : undefined }),
}));

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
}));

const { apiFetch } = jest.requireMock('@/lib/fetcher') as {
    apiFetch: jest.Mock;
};

function setStoredDomain(appName: string, publicDomain: string) {
    useIngressStore.setState((state) => ({
        configs: {
            ...state.configs,
            [appName]: {
                appName,
                publicDomain,
                externalAccessEnabled: true,
                tlsEnabled: true,
            },
        },
    }));
}

describe('ExternalAccessCard and useIngressStore', () => {
    beforeEach(() => {
        apiFetch.mockReset();
        mockBaseDomain = undefined;
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

    it('preserves an unsaved domain when stored configuration and settings refresh', () => {
        setStoredDomain('sonarr', 'sonarr.old.example.com');
        const { rerender } = render(<ExternalAccessCard appName="sonarr" />);

        fireEvent.change(screen.getByRole('textbox'), { target: { value: 'sonarr.draft.example.com' } });
        act(() => setStoredDomain('sonarr', 'sonarr.remote.example.com'));
        mockBaseDomain = 'new.example.com';
        rerender(<ExternalAccessCard appName="sonarr" />);

        expect(screen.getByRole('textbox')).toHaveValue('sonarr.draft.example.com');
    });

    it('follows refreshed configuration when the domain has not been edited', () => {
        setStoredDomain('sonarr', 'sonarr.old.example.com');
        render(<ExternalAccessCard appName="sonarr" />);

        act(() => setStoredDomain('sonarr', 'sonarr.remote.example.com'));

        expect(screen.getByRole('textbox')).toHaveValue('sonarr.remote.example.com');
    });

    it('uses newly loaded base-domain settings without an effect-driven draft reset', () => {
        const { rerender } = render(<ExternalAccessCard appName="sonarr" />);
        expect(screen.getByRole('textbox')).toHaveValue('');

        mockBaseDomain = '*.example.com';
        rerender(<ExternalAccessCard appName="sonarr" />);

        expect(screen.getByRole('textbox')).toHaveValue('sonarr.example.com');
    });

    it('does not carry an edited domain into another app', () => {
        setStoredDomain('sonarr', 'sonarr.example.com');
        setStoredDomain('radarr', 'radarr.example.com');
        const { rerender } = render(<ExternalAccessCard appName="sonarr" />);
        fireEvent.change(screen.getByRole('textbox'), { target: { value: 'sonarr.draft.example.com' } });

        rerender(<ExternalAccessCard appName="radarr" />);

        expect(screen.getByRole('textbox')).toHaveValue('radarr.example.com');
    });

    it('adopts the authoritative domain after a successful save', async () => {
        setStoredDomain('sonarr', 'sonarr.old.example.com');
        apiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                config: {
                    appName: 'sonarr',
                    publicDomain: 'sonarr.normalized.example.com',
                    externalAccessEnabled: true,
                    tlsEnabled: true,
                },
            }),
        });
        render(<ExternalAccessCard appName="sonarr" />);
        fireEvent.change(screen.getByRole('textbox'), { target: { value: 'SONARR.NORMALIZED.EXAMPLE.COM' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save' }));

        await waitFor(() => {
            expect(screen.getByRole('textbox')).toHaveValue('sonarr.normalized.example.com');
        });
    });

    it.each(['sonarr.newer.example.com', 'sonarr.old.example.com'])('preserves %s edited while an earlier domain save is pending', async (nextDomain) => {
        setStoredDomain('sonarr', 'sonarr.old.example.com');
        let completeSave: (response: unknown) => void = () => {};
        apiFetch.mockImplementationOnce(() => new Promise((resolve) => { completeSave = resolve; }));
        render(<ExternalAccessCard appName="sonarr" />);
        fireEvent.change(screen.getByRole('textbox'), { target: { value: 'sonarr.first.example.com' } });
        fireEvent.click(screen.getByRole('button', { name: 'Save' }));
        fireEvent.change(screen.getByRole('textbox'), { target: { value: nextDomain } });

        await act(async () => {
            completeSave({
                ok: true,
                json: async () => ({
                    config: {
                        appName: 'sonarr',
                        publicDomain: 'sonarr.first.example.com',
                        externalAccessEnabled: true,
                        tlsEnabled: true,
                    },
                }),
            });
        });

        expect(screen.getByRole('textbox')).toHaveValue(nextDomain);
    });
});
