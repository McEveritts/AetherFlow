/**
 * Shared SWR fetcher with JSON parsing and error handling.
 * Used as the global default in SWRProvider and available for direct import.
 */
let csrfTokenPromise: Promise<string | null> | null = null;

function getRequestMethod(input: RequestInfo | URL, init?: RequestInit): string {
    if (init?.method) {
        return init.method.toUpperCase();
    }
    if (input instanceof Request) {
        return input.method.toUpperCase();
    }
    return 'GET';
}

function getRequestPath(input: RequestInfo | URL): string {
    if (typeof input === 'string') {
        if (input.startsWith('http://') || input.startsWith('https://')) {
            return new URL(input).pathname;
        }
        return input;
    }
    if (input instanceof URL) {
        return input.pathname;
    }
    return new URL(input.url, typeof window !== 'undefined' ? window.location.origin : 'http://localhost').pathname;
}

function getCookieValue(name: string): string | null {
    if (typeof document === 'undefined') {
        return null;
    }

    const prefix = `${name}=`;
    const match = document.cookie
        .split(';')
        .map(part => part.trim())
        .find(part => part.startsWith(prefix));

    if (!match) {
        return null;
    }

    return decodeURIComponent(match.slice(prefix.length));
}

function shouldAttachCSRF(input: RequestInfo | URL, init: RequestInit | undefined, headers: Headers): boolean {
    const method = getRequestMethod(input, init);
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
        return false;
    }

    const authorization = headers.get('Authorization') || headers.get('authorization') || '';
    if (authorization.startsWith('Bearer ')) {
        return false;
    }

    const path = getRequestPath(input);
    return path.startsWith('/api/v1/auth/') || path.startsWith('/api/auth/');
}

async function getCSRFToken(): Promise<string | null> {
    const existing = getCookieValue('csrf_token');
    if (existing) {
        return existing;
    }

    if (typeof window === 'undefined') {
        return null;
    }

    if (!csrfTokenPromise) {
        csrfTokenPromise = fetch('/api/v1/public/csrf-token', {
            credentials: 'include',
            headers: {
                'X-API-Version': 'v1',
                'Accept': 'application/vnd.aetherflow.v1+json',
            },
        })
            .then(async (res) => {
                if (!res.ok) {
                    return null;
                }
                const payload = await res.json().catch(() => ({} as { csrf_token?: string }));
                return payload.csrf_token || getCookieValue('csrf_token');
            })
            .finally(() => {
                csrfTokenPromise = null;
            });
    }

    return csrfTokenPromise;
}

export async function apiFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const headers = new Headers(input instanceof Request ? input.headers : undefined);
    if (init?.headers) {
        new Headers(init.headers).forEach((value, key) => headers.set(key, value));
    }
    if (!headers.has('X-API-Version')) {
        headers.set('X-API-Version', 'v1');
    }
    if (!headers.has('Accept')) {
        headers.set('Accept', 'application/vnd.aetherflow.v1+json');
    }
    if (!headers.has('X-Requested-With')) {
        headers.set('X-Requested-With', 'XMLHttpRequest');
    }
    if (!headers.has('Cache-Control')) {
        headers.set('Cache-Control', 'no-store');
    }

    if (shouldAttachCSRF(input, init, headers) && !headers.has('X-CSRF-Token')) {
        const csrfToken = await getCSRFToken();
        if (csrfToken) {
            headers.set('X-CSRF-Token', csrfToken);
        }
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
