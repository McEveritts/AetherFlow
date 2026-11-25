export const SITE_ORIGIN = 'https://mceveritts.github.io';

const rawBasePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';

export const BASE_PATH = rawBasePath
  ? `/${rawBasePath.replace(/^\/+|\/+$/g, '')}`
  : '';

/**
 * Prefix an internal site path with the configured Next.js basePath.
 * External URLs (`http://`, `https://`, `mailto:`, `#anchors`) are returned unchanged.
 */
export function withBasePath(path: string): string {
  if (
    !path ||
    path.startsWith('#') ||
    path.startsWith('http://') ||
    path.startsWith('https://') ||
    path.startsWith('mailto:')
  ) {
    return path;
  }
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return `${BASE_PATH}${normalized}`;
}

/**
 * Resolve a synced media file under `public/media/` with the configured basePath.
 */
export function withMediaPath(relativeMediaPath: string): string {
  const clean = relativeMediaPath.replace(/^\/+/, '');
  return withBasePath(`/media/${clean}`);
}
