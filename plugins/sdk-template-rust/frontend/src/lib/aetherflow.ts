const apiBase = (process.env.NEXT_PUBLIC_AETHERFLOW_API_BASE_URL || '').replace(/\/$/, '');

export interface SystemMetricsSnapshot {
    cpu_usage?: number;
    uptime?: string;
}

/**
 * Queries plugin or host snapshot via the sandboxed iframe postMessage capability bridge
 * (`AF_PLUGIN_PROXY_REQUEST` -> `/api/v1/auth/plugins/:id/proxy/snapshot`), falling back
 * to relative fetch only in local standalone dev.
 */
export function getSystemMetrics(pluginId = '{{PLUGIN_ID}}'): Promise<SystemMetricsSnapshot> {
    if (typeof window !== 'undefined' && window.parent && window.parent !== window) {
        return new Promise((resolve, reject) => {
            const timeout = window.setTimeout(() => {
                window.removeEventListener('message', onMessage);
                reject(new Error('Timed out waiting for host capability bridge'));
            }, 5000);

            function onMessage(event: MessageEvent) {
                const msg = event.data || {};
                if (msg.type === 'AF_PLUGIN_PROXY_RESPONSE' && (!msg.pluginId || msg.pluginId === pluginId)) {
                    window.clearTimeout(timeout);
                    window.removeEventListener('message', onMessage);
                    if (msg.error) {
                        reject(new Error(String(msg.error)));
                    } else {
                        const metrics = msg.payload?.system_metrics ?? msg.payload ?? {};
                        resolve(metrics as SystemMetricsSnapshot);
                    }
                }
            }

            window.addEventListener('message', onMessage);
            window.parent.postMessage(
                {
                    type: 'AF_PLUGIN_PROXY_REQUEST',
                    pluginId,
                    path: 'snapshot',
                    method: 'GET',
                },
                '*'
            );
        });
    }

    return fetch(`${apiBase}/api/v1/auth/plugins/${encodeURIComponent(pluginId)}/proxy/snapshot`, {
        headers: { Accept: 'application/json' },
    }).then(async (response) => {
        if (!response.ok) {
            throw new Error(`AetherFlow Plugin Proxy ${response.status}`);
        }
        const data = await response.json();
        return (data?.system_metrics ?? data) as SystemMetricsSnapshot;
    });
}
