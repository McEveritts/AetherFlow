/**
 * Shared SWR fetcher with JSON parsing and error handling.
 * Used as the global default in SWRProvider and available for direct import.
 */
export async function fetcher<T = unknown>(url: string): Promise<T> {
    const res = await fetch(url);

    if (!res.ok) {
        const error = new Error(`Request failed: ${res.status} ${res.statusText}`);
        // Attach status for downstream error handling
        (error as Error & { status: number }).status = res.status;
        throw error;
    }

    return res.json();
}
