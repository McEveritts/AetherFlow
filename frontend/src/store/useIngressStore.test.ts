import { useIngressStore } from './useIngressStore';
import { apiFetch } from '@/lib/fetcher';

jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
const mockApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;

const config = { appName: 'sonarr', publicDomain: 'tv.example.com', externalAccessEnabled: true, listenPort: 8989, tlsEnabled: false };

describe('ingress store contracts', () => {
    beforeEach(() => {
        mockApiFetch.mockReset();
        useIngressStore.setState({ configs: {}, isSaving: false, error: null });
    });

    it.each([
        { configs: [config] },
        { sonarr: { public_domain: 'tv.example.com', external_access_enabled: true, listen_port: 8989, tls_enabled: false } },
    ])('normalizes array and dictionary response formats without losing explicit false', async (payload) => {
        mockApiFetch.mockResolvedValue({ ok: true, json: async () => payload } as Response);
        await useIngressStore.getState().fetchConfigs();
        expect(useIngressStore.getState().configs.sonarr).toEqual(config);
    });

    it('merges partial updates through the alias and applies authoritative server values', async () => {
        useIngressStore.setState({ configs: { sonarr: config } });
        mockApiFetch.mockResolvedValue({ ok: true, json: async () => ({ config: { ...config, publicDomain: 'server.example.com', tlsEnabled: true } }) } as Response);
        await useIngressStore.getState().updateAppIngress('sonarr', { tlsEnabled: true });
        const sent = JSON.parse(String(mockApiFetch.mock.calls[0][1]?.body));
        expect(sent).toEqual({ ...config, tlsEnabled: true });
        expect(useIngressStore.getState().configs.sonarr.publicDomain).toBe('server.example.com');
        expect(useIngressStore.getState().configs.sonarr.listenPort).toBe(8989);
    });

    it('retains the existing config and exposes errors when fetching fails', async () => {
        useIngressStore.setState({ configs: { sonarr: config } });
        mockApiFetch.mockRejectedValue(new Error('network unavailable'));
        const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        try {
            await useIngressStore.getState().fetchConfigs();
            expect(useIngressStore.getState().error).toBe('network unavailable');
            expect(useIngressStore.getState().configs.sonarr).toEqual(config);
        } finally { errorSpy.mockRestore(); }
    });
});
