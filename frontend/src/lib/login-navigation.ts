import { navigateBrowser } from './browser-navigation';

/** Only accept local continuation paths supplied by our login flow. */
export function safeLoginReturnTo(value: string | null | undefined): string {
    if (!value || !value.startsWith('/') || value.startsWith('//') || /[\\\u0000-\u0020\u007f]/.test(value)) return '/';
    try {
        const decoded = decodeURIComponent(value);
        if (decoded.startsWith('//') || /[\\\u0000-\u001f\u007f]/.test(decoded)) return '/';
        const url = new URL(value, 'https://aetherflow.invalid');
        if (url.origin !== 'https://aetherflow.invalid' || url.pathname.startsWith('//')) return '/';
        return `${url.pathname}${url.search}${url.hash}`;
    } catch {
        return '/';
    }
}

export function loginReturnToFromLocation(): string {
    return typeof window === 'undefined' ? '/' : safeLoginReturnTo(new URLSearchParams(window.location.search).get('return_to'));
}

// API authorization endpoints must reach the server, including in static exports.
export function navigateToLoginDestination(destination: string, push: (path: string) => void): void {
    const path = safeLoginReturnTo(destination);
    if (path.split(/[?#]/, 1)[0].startsWith('/api/')) {
        navigateBrowser(path);
    } else {
        push(path);
    }
}
