'use client';

import { useEffect } from 'react';

export default function PwaRegistry() {
  useEffect(() => {
    if (typeof window !== 'undefined' && 'serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker
          .register('/sw.js')
          .then((registration) => {
            console.log('AetherFlow ServiceWorker registered with scope:', registration.scope);
          })
          .catch((err) => {
            console.error('AetherFlow ServiceWorker registration failed:', err);
          });
      });
    }
  }, []);

  return null;
}
