const apiBase = (process.env.NEXT_PUBLIC_AETHERFLOW_API_BASE_URL || '').replace(/\/$/, '');

async function getJSON<T>(path: string): Promise<T> {
    const response = await fetch(`${apiBase}${path}`, {
        credentials: 'include',
        headers: {
            Accept: 'application/json',
        },
    });

    if (!response.ok) {
        throw new Error(`AetherFlow API ${response.status}`);
    }

    return response.json() as Promise<T>;
}

export interface SystemMetricsSnapshot {
    cpu_usage?: number;
    uptime?: string;
}

/**
 * Queries the verified AetherFlow v4.0.0 authenticated system metrics route
 * (`GET /api/v1/auth/system/metrics`), relying on the browser's `aetherflow_session` cookie.
 */
export function getSystemMetrics() {
    return getJSON<SystemMetricsSnapshot>('/api/v1/auth/system/metrics');
}
