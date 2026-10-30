'use client';

import { useEffect } from 'react';

const LEGACY_CACHES = ['aetherflow-cache-v1'];

export default function PwaRegistry() {
  useEffect(() => {
    if (typeof window === 'undefined') return;

    // Proactively purge legacy cache-first buckets that trapped stale index.html shells
    if ('caches' in window) {
      for (const legacyCache of LEGACY_CACHES) {
        window.caches.delete(legacyCache).catch(() => {
          // Ignore cache deletion errors
        });
      }
    }

    if (!('serviceWorker' in navigator)) return;

    const registerServiceWorker = () => {
      navigator.serviceWorker
        .register('/sw.js', { updateViaCache: 'none' })
        .then((registration) => {
          console.log('AetherFlow ServiceWorker registered with scope:', registration.scope);
          void registration.update().catch(() => {
            // Ignore background update check errors
          });
        })
        .catch((err) => {
          console.error('AetherFlow ServiceWorker registration failed:', err);
        });
    };

    if (document.readyState === 'complete') {
      registerServiceWorker();
    } else {
      window.addEventListener('load', registerServiceWorker, { once: true });
      return () => window.removeEventListener('load', registerServiceWorker);
    }
  }, []);

  return null;
}
