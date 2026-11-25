import fs from 'node:fs';
import path from 'node:path';
import { withMediaPath } from './basePath';

export type ScreenshotTheme = 'dark' | 'light';

export interface ThemedScreenshotSet {
  dark: Record<string, string | null>;
  light: Record<string, string | null>;
}

export interface MediaAvailability {
  screenshots: ThemedScreenshotSet;
  diagrams: {
    architecture: string | null;
    peerClustering: string | null;
    v4ByTheNumbers: string | null;
    banner: string | null;
    socialPreview: string | null;
    socialCrop: string | null;
  };
  featureIcons: Record<string, string | null>;
}

export const SCREENSHOT_SLUGS = [
  'overview',
  'inbox',
  'services',
  'marketplace',
  'mcbrowser',
  'fileshare',
  'streaming',
  'mediaflow',
  'flowai',
  'network',
  'cluster',
  'users',
  'audit',
  'settings',
  'notifications',
  'quotas',
  'security',
] as const;

export type ScreenshotSlug = (typeof SCREENSHOT_SLUGS)[number];

const LEGACY_DARK_FALLBACKS: Partial<Record<ScreenshotSlug, string>> = {
  overview: 'dashboard.png',
  marketplace: 'marketplace.png',
  flowai: 'flowai.png',
};

const FEATURE_ICON_CANDIDATES: Record<string, string[]> = {
  'rust-control-plane': [
    'feature-icons/rust-core.svg',
    'feature-icons/rust-control-plane.svg',
  ],
  'leptos-wasm': ['feature-icons/wasm-ui.svg', 'feature-icons/leptos-wasm.svg'],
  marketplace: ['feature-icons/marketplace.svg'],
  'peer-clustering': [
    'feature-icons/cluster.svg',
    'feature-icons/peer-clustering.svg',
  ],
  mcbrowser: ['feature-icons/mcbrowser.svg'],
  streaming: ['feature-icons/streaming.svg'],
  flowai: ['feature-icons/flowai.svg'],
  networking: ['feature-icons/network-vpn.svg', 'feature-icons/networking.svg'],
  security: ['feature-icons/security.svg'],
  'self-update': ['feature-icons/self-update.svg'],
};

function mediaFileExists(relativePath: string): boolean {
  const fullPath = path.join(process.cwd(), 'public', 'media', relativePath);
  try {
    return fs.statSync(fullPath).isFile();
  } catch {
    return false;
  }
}

function resolveIfPresent(relativePath: string): string | null {
  return mediaFileExists(relativePath) ? withMediaPath(relativePath) : null;
}

function resolveFirstPresent(candidates: string[]): string | null {
  for (const candidate of candidates) {
    if (mediaFileExists(candidate)) {
      return withMediaPath(candidate);
    }
  }
  return null;
}

export function inspectAvailableMedia(): MediaAvailability {
  const dark: Record<string, string | null> = {};
  const light: Record<string, string | null> = {};

  for (const slug of SCREENSHOT_SLUGS) {
    const darkCandidates = [
      `screenshots/dark/${slug}.png`,
      `screenshots/${slug}.png`,
    ];
    const legacy = LEGACY_DARK_FALLBACKS[slug];
    if (legacy) {
      darkCandidates.push(legacy);
    }
    dark[slug] = resolveFirstPresent(darkCandidates);

    light[slug] = resolveIfPresent(`screenshots/light/${slug}.png`);
  }

  const featureIcons: Record<string, string | null> = {};
  for (const [id, candidates] of Object.entries(FEATURE_ICON_CANDIDATES)) {
    featureIcons[id] = resolveFirstPresent(candidates);
  }

  return {
    screenshots: { dark, light },
    diagrams: {
      architecture: resolveIfPresent('architecture.svg'),
      peerClustering: resolveIfPresent('peer-clustering.svg'),
      v4ByTheNumbers: resolveIfPresent('v4-by-the-numbers.svg'),
      banner: resolveIfPresent('banner.svg'),
      socialPreview: resolveFirstPresent([
        'social-preview.png',
        'social-preview.svg',
      ]),
      socialCrop: resolveIfPresent('screenshots/social-crop.png'),
    },
    featureIcons,
  };
}
