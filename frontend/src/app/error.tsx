'use client';

import { useEffect } from 'react';
import Link from 'next/link';

export default function AppError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('[AetherFlow Route Error]', error);
  }, [error]);

  return (
    <div
      role="alert"
      className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6"
    >
      <div className="max-w-md w-full rounded-2xl border border-slate-800 bg-slate-900/80 p-8 text-center space-y-4 shadow-xl">
        <div className="mx-auto w-12 h-12 rounded-full bg-red-500/15 text-red-400 flex items-center justify-center text-xl font-bold">
          !
        </div>
        <h2 className="text-lg font-semibold text-slate-100">
          Something went wrong
        </h2>
        <p className="text-sm text-slate-400">
          An unexpected client error occurred while rendering this view.
        </p>
        {error?.digest && (
          <p className="text-xs font-mono text-slate-500">Digest: {error.digest}</p>
        )}
        <div className="flex items-center justify-center gap-3 pt-2">
          <button
            type="button"
            onClick={() => reset()}
            className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition-colors"
          >
            Try Again
          </button>
          <Link
            href="/"
            className="px-4 py-2 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-200 text-sm font-medium transition-colors"
          >
            Reload Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
