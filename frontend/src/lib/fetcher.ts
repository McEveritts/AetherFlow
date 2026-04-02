/**
 * Shared SWR fetcher with JSON parsing and error handling.
 * Used as the global default in SWRProvider and available for direct import.
 */
export async function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const headers = new Headers(init?.headers);
    if (!headers.has('X-API-Version')) {
        headers.set('X-API-Version', 'v1');
    }
    if (!headers.has('Accept')) {
        headers.set('Accept', 'application/vnd.aetherflow.v1+json, application/json');
    }

    return fetch(input, {
        ...init,
        headers,
        credentials: 'include',
    });
}

export async function fetcher<T = unknown>(url: string): Promise<T> {
    const res = await apiFetch(url);

    if (!res.ok) {
        const error = new Error(`Request failed: ${res.status} ${res.statusText}`);
        // Attach status for downstream error handling
        (error as Error & { status: number }).status = res.status;
        throw error;
    }

    return res.json();
}
