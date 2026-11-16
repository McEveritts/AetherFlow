'use client';

import { useEffect } from 'react';

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('[AetherFlow Global Error]', error);
  }, [error]);

  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6 antialiased">
        <div
          role="alert"
          className="max-w-md w-full rounded-2xl border border-slate-800 bg-slate-900 p-8 text-center space-y-4 shadow-xl"
        >
          <h1 className="text-lg font-semibold text-slate-100">
            AetherFlow encountered a critical UI error
          </h1>
          <p className="text-sm text-slate-400">
            The application shell hit an unrecoverable error. Try resetting the view or reloading the page.
          </p>
          <div className="flex items-center justify-center gap-3 pt-2">
            <button
              type="button"
              onClick={() => reset()}
              className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium"
            >
              Reset View
            </button>
          </div>
        </div>
      </body>
    </html>
  );
}
