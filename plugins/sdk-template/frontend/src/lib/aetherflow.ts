const apiBase = (process.env.NEXT_PUBLIC_AETHERFLOW_API_BASE_URL || '').replace(/\/$/, '');

async function getJSON<T>(path: string): Promise<T> {
    const response = await fetch(`${apiBase}${path}`, {
        credentials: 'include',
    });

    if (!response.ok) {
        throw new Error(`AetherFlow API ${response.status}`);
    }

    return response.json() as Promise<T>;
}

export function getSystemMetrics() {
    return getJSON<{ cpu_usage: number; uptime: string }>('/api/system/metrics');
}
