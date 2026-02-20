'use client';

import { useEffect, useState } from 'react';

interface SystemMetrics {
  cpu_usage: number;
  disk_space: {
    total: number;
    used: number;
    free: number;
  };
  is_windows: boolean;
  services: {
    [key: string]: boolean;
  };
}

export default function Dashboard() {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch metrics from the Go Backend
  useEffect(() => {
    let isMounted = true;
    const controller = new AbortController();

    const fetchMetrics = async () => {
      try {
        const res = await fetch('http://localhost:8080/api/system/metrics', {
          signal: controller.signal
        });
        if (!res.ok) throw new Error('API server unavailable or returned an error.');

        const data = await res.json();
        if (isMounted) {
          setMetrics(data);
          setError(null);
        }
      } catch (err: any) {
        if (err.name !== 'AbortError' && isMounted) {
          console.error("Failed to fetch from backend", err);
          setError(err.message || "Failed to establish a connection to the server.");
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000); // Poll every 5 seconds

    // Cleanup: unmount check & abort inflight request
    return () => {
      isMounted = false;
      clearInterval(interval);
      controller.abort();
    };
  }, []);

  return (
    <main className="min-h-screen p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <header className="flex items-center justify-between pb-4 border-b border-white/10">
        <div>
          <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent">
            AetherFlow
          </h1>
          <p className="text-slate-400 text-sm mt-1">Decoupled Architecture (Go + Next.js)</p>
        </div>
        <div className="flex items-center space-x-4">
          <span className="relative flex h-3 w-3">
            {!error && <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${loading ? 'bg-yellow-400' : 'bg-emerald-400'} opacity-75`}></span>}
            <span className={`relative inline-flex rounded-full h-3 w-3 ${error ? 'bg-red-500' : (loading ? 'bg-yellow-500' : 'bg-emerald-500')}`}></span>
          </span>
          <span className="text-sm font-medium text-slate-300">
            {error ? 'Connection Failed' : (loading ? 'Connecting...' : 'API Connected')}
          </span>
        </div>
      </header>

      {/* Global Error Fallback UI */}
      {error && !metrics && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6 flex flex-col items-center justify-center space-y-4 py-20 text-center">
          <div className="h-16 w-16 bg-red-500/20 rounded-full flex items-center justify-center">
            <svg className="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          </div>
          <h2 className="text-xl font-bold text-slate-200">System Unavailable</h2>
          <p className="text-slate-400 max-w-md">The dashboard could not connect to the Go metrics API. Make sure the backend server is running and accessible over localhost :8080.</p>
        </div>
      )}

      {/* Grid */}
      <div className={`grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 transition-opacity duration-500 ${error && !metrics ? 'opacity-30 pointer-events-none' : 'opacity-100'}`}>

        {/* CPU Widget */}
        <div className="glass-card p-6 relative overflow-hidden">
          {error && <div className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm z-10 flex items-center justify-center"><span className="text-red-400 text-sm font-medium border border-red-500/20 bg-red-500/10 px-3 py-1 rounded">Offline</span></div>}
          <h2 className="text-lg font-semibold text-slate-200 mb-4 pb-2 border-b border-white/5">CPU Utilization</h2>
          <div className="flex items-end space-x-2">
            <span className="text-4xl font-bold tracking-tighter text-blue-400">
              {metrics ? metrics.cpu_usage.toFixed(1) : (error ? '--' : '...')}
            </span>
            <span className="text-slate-400 mb-1">%</span>
          </div>

          <div className="mt-6 h-2 w-full bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full ${error ? 'bg-slate-600' : 'bg-blue-500'} transition-all duration-500 ease-out`}
              style={{ width: `${metrics ? metrics.cpu_usage : 0}%` }}
            />
          </div>
        </div>

        {/* Disk Widget */}
        <div className="glass-card p-6 relative overflow-hidden">
          {error && <div className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm z-10 flex items-center justify-center"><span className="text-red-400 text-sm font-medium border border-red-500/20 bg-red-500/10 px-3 py-1 rounded">Offline</span></div>}
          <h2 className="text-lg font-semibold text-slate-200 mb-4 pb-2 border-b border-white/5">Storage (Root Vol)</h2>
          <div className="flex items-end space-x-2">
            <span className="text-4xl font-bold tracking-tighter text-indigo-400">
              {metrics ? metrics.disk_space.used.toFixed(1) : (error ? '--' : '...')}
            </span>
            <span className="text-slate-400 mb-1">/ {metrics ? metrics.disk_space.total.toFixed(1) : (error ? '--' : '...')} GB</span>
          </div>

          <div className="mt-6 h-2 w-full bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full ${error ? 'bg-slate-600' : 'bg-indigo-500'} transition-all duration-500 ease-out flex`}
              style={{ width: `${metrics ? (metrics.disk_space.used / metrics.disk_space.total) * 100 : 0}%` }}
            />
          </div>
        </div>

        {/* Server Info Widget */}
        <div className="glass-card p-6 relative overflow-hidden">
          {error && <div className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm z-10 flex items-center justify-center"><span className="text-red-400 text-sm font-medium border border-red-500/20 bg-red-500/10 px-3 py-1 rounded">Offline</span></div>}
          <h2 className="text-lg font-semibold text-slate-200 mb-4 pb-2 border-b border-white/5">Environment</h2>
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-sm text-slate-400">OS Context</span>
              <span className="px-2 py-1 bg-white/5 rounded text-sm font-medium border border-white/10">
                {metrics ? (metrics.is_windows ? 'Windows (Mocked)' : 'Debian (Native)') : '--'}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-slate-400">Frontend</span>
              <span className="px-2 py-1 bg-white/5 rounded text-sm font-medium border border-white/10 text-emerald-400">
                Next.js (SPA)
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-slate-400">Backend</span>
              <span className="px-2 py-1 bg-white/5 rounded text-sm font-medium border border-white/10 text-cyan-400">
                Go API
              </span>
            </div>
          </div>
        </div>

        {/* Service Placeholder */}
        <div className="glass-card p-6 md:col-span-2 lg:col-span-3 relative overflow-hidden">
          {error && <div className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm z-10 flex items-center justify-center"><span className="text-red-400 text-sm font-medium border border-red-500/20 bg-red-500/10 px-3 py-1 rounded">Metrics Unavailable</span></div>}
          <h2 className="text-lg font-semibold text-slate-200 mb-4 pb-2 border-b border-white/5">Controlled Services</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {['Plex Media Server', 'rTorrent', 'Sonarr', 'Radarr'].map(service => {
              const serviceRunning = metrics?.services?.[service] || false;
              return (
                <div key={service} className="p-4 bg-white/[0.02] border border-white/[0.05] rounded-xl flex flex-col items-center justify-center space-y-3 hover:bg-white/[0.04] transition-colors cursor-pointer group">
                  <div className="h-10 w-10 rounded-full bg-slate-800 flex items-center justify-center group-hover:scale-110 transition-transform">
                    {metrics ? (
                      <span className={`block h-3 w-3 rounded-full ${serviceRunning ? 'bg-emerald-500 shadow-[0_0_10px_#10B981]' : 'bg-red-500 shadow-[0_0_10px_#EF4444]'}`}></span>
                    ) : (
                      <span className="block h-3 w-3 rounded-full bg-slate-500"></span>
                    )}
                  </div>
                  <span className="text-sm font-medium text-slate-300">{service}</span>
                </div>
              )
            })}
          </div>
        </div>

      </div>
    </main>
  );
}
