/** Native navigation for API handoffs and streaming file downloads. */
export function navigateBrowser(path: string): void {
    window.location.assign(path);
}
