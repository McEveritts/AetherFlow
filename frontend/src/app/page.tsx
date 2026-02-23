'use client';

import { useEffect, useState } from 'react';
import {
  LayoutDashboard,
  Server,
  Sparkles,
  Settings,
  Shield,
  Activity,
  LogOut,
  ChevronRight,
  HardDrive,
  Network,
  Cpu,
  RefreshCw,
  MemoryStick,
  Box,
  Globe,
  Clock,
  Play,
  RotateCcw,
  Square,
  Bot,
  User,
  Zap,
  Lock,
  Wifi,
  Store,
  Download,
  Star,
  Search,
  Filter
} from 'lucide-react';

type TabId = 'overview' | 'services' | 'marketplace' | 'ai' | 'security' | 'settings' | 'logout';

interface SystemMetrics {
  cpu_usage: number;
  disk_space: {
    total: number;
    used: number;
    free: number;
  };
  is_windows: boolean;
  services: {
    [key: string]: { status: 'running' | 'stopped' | 'error', uptime: string, version: string };
  };
  memory: {
    total: number;
    used: number;
  };
  network: {
    down: string;
    up: string;
    active_connections: number;
  };
  uptime: string;
  load_average: [number, number, number];
}

const MOCK_DATA: SystemMetrics = {
  cpu_usage: 24.8,
  disk_space: {
    total: 4096.0,
    used: 2145.5,
    free: 1950.5
  },
  is_windows: false,
  services: {
    'Plex Media Server': { status: 'running', uptime: '14d 2h', version: '1.32.5' },
    'rTorrent': { status: 'running', uptime: '45d 1h', version: '0.9.8' },
    'Sonarr': { status: 'running', uptime: '12d 5h', version: '3.0.9' },
    'Radarr': { status: 'running', uptime: '12d 5h', version: '4.3.2' },
    'Lidarr': { status: 'stopped', uptime: '-', version: '1.0.2' },
    'Readarr': { status: 'running', uptime: '5d 10h', version: '0.1.1' },
    'Tautulli': { status: 'running', uptime: '45d 1h', version: '2.14.3' },
    'Overseerr': { status: 'running', uptime: '30d 12h', version: '1.33.2' },
    'Nginx Proxy Manager': { status: 'running', uptime: '80d 4h', version: '2.9.18' },
    'Docker Engine': { status: 'running', uptime: '80d 5h', version: '24.0.2' },
    'WireGuard VPN': { status: 'error', uptime: '-', version: '1.0.20210914' },
    'Jackett': { status: 'running', uptime: '10d 2h', version: '0.21.1' }
  },
  memory: {
    total: 64.0,
    used: 14.2
  },
  network: {
    down: "125.4 MB/s",
    up: "12.2 MB/s",
    active_connections: 342
  },
  uptime: "80 Days, 5 Hours",
  load_average: [1.25, 2.10, 1.85]
};

export default function Dashboard() {
  const [metrics, setMetrics] = useState<SystemMetrics>(MOCK_DATA);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [isSidebarHovered, setIsSidebarHovered] = useState(false);
  const [isLive, setIsLive] = useState(false);

  useEffect(() => {
    let isMounted = true;
    const controller = new AbortController();

    const fetchMetrics = async () => {
      try {
        const res = await fetch('http://localhost:8080/api/system/metrics', {
          signal: controller.signal
        });
        if (!res.ok) throw new Error('API server unavailable.');

        const data = await res.json();
        if (isMounted) {
          setMetrics({
            ...MOCK_DATA,
            cpu_usage: data.cpu_usage || MOCK_DATA.cpu_usage,
            disk_space: data.disk_space || MOCK_DATA.disk_space
          });
          setError(null);
          setIsLive(true);
        }
      } catch (err: any) {
        if (err.name !== 'AbortError' && isMounted) {
          setError("Backend Offline. Displaying Representative Environment.");
          setMetrics(MOCK_DATA);
          setIsLive(false);
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);

    return () => {
      isMounted = false;
      clearInterval(interval);
      controller.abort();
    };
  }, []);

  const NAVIGATION = [
    { id: 'overview' as TabId, label: 'Overview', icon: <LayoutDashboard size={20} /> },
    { id: 'services' as TabId, label: 'Services', icon: <Server size={20} /> },
    { id: 'marketplace' as TabId, label: 'Marketplace', icon: <Store size={20} /> },
    { id: 'ai' as TabId, label: 'FlowAI', icon: <Sparkles size={20} className="text-indigo-400 group-hover:text-indigo-300 transition-colors" /> },
  ];

  const BOTTOM_NAVIGATION = [
    { id: 'security' as TabId, label: 'Security', icon: <Shield size={18} /> },
    { id: 'settings' as TabId, label: 'Settings', icon: <Settings size={18} /> },
    { id: 'logout' as TabId, label: 'Log Out', icon: <LogOut size={18} /> },
  ];

  const renderContent = () => {
    if (activeTab === 'overview') {
      return (
        <div className="space-y-6 animate-fade-in">

          {/* Quick Stats Row */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 flex items-center gap-4 backdrop-blur-md">
              <div className="p-3 bg-blue-500/10 rounded-xl"><Clock size={20} className="text-blue-400" /></div>
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold tracking-wider">System Uptime</p>
                <p className="text-lg font-bold text-slate-100">{metrics.uptime}</p>
              </div>
            </div>
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 flex items-center gap-4 backdrop-blur-md">
              <div className="p-3 bg-emerald-500/10 rounded-xl"><Activity size={20} className="text-emerald-400" /></div>
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold tracking-wider">Load Average</p>
                <p className="text-lg font-bold text-slate-100">{metrics.load_average.join(' / ')}</p>
              </div>
            </div>
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 flex items-center gap-4 backdrop-blur-md">
              <div className="p-3 bg-indigo-500/10 rounded-xl"><Globe size={20} className="text-indigo-400" /></div>
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold tracking-wider">Active Connections</p>
                <p className="text-lg font-bold text-slate-100">{metrics.network.active_connections}</p>
              </div>
            </div>
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-5 flex items-center gap-4 backdrop-blur-md">
              <div className="p-3 bg-amber-500/10 rounded-xl"><Zap size={20} className="text-amber-400" /></div>
              <div>
                <p className="text-xs text-slate-400 uppercase font-semibold tracking-wider">Status</p>
                <p className="text-lg font-bold text-emerald-400 tracking-tight">System Optimal</p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* CPU Widget */}
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-6 relative overflow-hidden group hover:bg-white/[0.04] transition-colors backdrop-blur-xl">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
                  <Cpu size={18} className="text-blue-400" /> CPU Allocation
                </h2>
                <span className="text-xs font-medium px-2.5 py-1 bg-white/5 rounded-full text-slate-400">AMD EPYC</span>
              </div>

              <div className="flex flex-col items-center justify-center py-4 relative">
                {/* Mock Circle Graph */}
                <div className="w-32 h-32 rounded-full border-[12px] border-slate-800 relative flex items-center justify-center">
                  <svg className="absolute inset-0 w-full h-full -rotate-90" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="44" stroke="currentColor" strokeWidth="12" fill="none" className="text-blue-500" strokeDasharray={`${metrics.cpu_usage * 2.76} 276`} strokeLinecap="round" />
                  </svg>
                  <div className="text-center absolute">
                    <span className="text-3xl font-bold tracking-tighter text-slate-100">{metrics.cpu_usage.toFixed(1)}</span>
                    <span className="text-sm text-slate-400 block">%</span>
                  </div>
                </div>
              </div>

              {/* Decorative background glow */}
              <div className="absolute -bottom-16 -right-16 w-48 h-48 bg-blue-500/10 rounded-full blur-3xl pointer-events-none"></div>
            </div>

            {/* Memory Widget */}
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-6 relative overflow-hidden group hover:bg-white/[0.04] transition-colors backdrop-blur-xl">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
                  <MemoryStick size={18} className="text-purple-400" /> Memory Usage
                </h2>
                <span className="text-xs font-medium px-2.5 py-1 bg-white/5 rounded-full text-slate-400">DDR5</span>
              </div>
              <div className="flex items-end space-x-2 mt-4">
                <span className="text-5xl font-bold tracking-tighter text-purple-400 relative z-10 w-24">
                  {metrics.memory.used.toFixed(1)}
                </span>
                <span className="text-slate-400 mb-2 relative z-10 font-medium">/ {metrics.memory.total.toFixed(0)} GB</span>
              </div>

              <div className="mt-8 space-y-2 relative z-10">
                <div className="flex justify-between text-xs text-slate-400 font-medium">
                  <span>Used ({(metrics.memory.used / metrics.memory.total * 100).toFixed(0)}%)</span>
                  <span>Free</span>
                </div>
                <div className="h-3 w-full bg-slate-800/80 rounded-full overflow-hidden shadow-inner flex">
                  <div
                    className="h-full bg-gradient-to-r from-purple-600 to-purple-400 transition-all duration-500 ease-out"
                    style={{ width: `${(metrics.memory.used / metrics.memory.total) * 100}%` }}
                  />
                </div>
              </div>
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full h-full bg-purple-500/5 rounded-full blur-3xl pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity"></div>
            </div>

            {/* Network Widget */}
            <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-6 relative overflow-hidden group hover:bg-white/[0.04] transition-colors backdrop-blur-xl border-t-emerald-500/20 shadow-[0_-4px_24px_-12px_rgba(16,185,129,0.1)]">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
                  <Network size={18} className="text-emerald-400" /> Network Traffic
                </h2>
                <span className="flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-2 w-2 rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
              </div>

              <div className="space-y-6 relative z-10 mt-2">
                <div className="bg-slate-900/50 p-4 rounded-2xl border border-white/5 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-emerald-500/20 rounded-lg"><ChevronRight size={16} className="text-emerald-400 rotate-90" /></div>
                    <span className="text-sm font-medium text-slate-300">Download</span>
                  </div>
                  <span className="text-xl font-bold tracking-tight text-white">{metrics.network.down}</span>
                </div>
                <div className="bg-slate-900/50 p-4 rounded-2xl border border-white/5 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-500/20 rounded-lg"><ChevronRight size={16} className="text-blue-400 -rotate-90" /></div>
                    <span className="text-sm font-medium text-slate-300">Upload</span>
                  </div>
                  <span className="text-xl font-bold tracking-tight text-white">{metrics.network.up}</span>
                </div>
              </div>
            </div>

            {/* Storage Volume Widget (Spans 2 cols) */}
            <div className="md:col-span-2 lg:col-span-3 bg-white/[0.02] border border-white/[0.05] rounded-3xl p-6 relative overflow-hidden group backdrop-blur-xl">
              <div className="flex items-center justify-between mb-8">
                <h2 className="text-base font-semibold text-slate-200 flex items-center gap-2">
                  <HardDrive size={18} className="text-amber-400" /> ZFS Storage Pools
                </h2>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {/* Pool 1 */}
                <div>
                  <div className="flex justify-between items-end mb-3">
                    <div>
                      <h3 className="text-sm font-bold text-slate-200">/mnt/tank (Media)</h3>
                      <p className="text-xs text-slate-500 mt-0.5">RAID-Z2 • {metrics.disk_space.total.toFixed(0)} GB Total</p>
                    </div>
                    <span className="text-2xl font-bold tracking-tight text-amber-400">{((metrics.disk_space.used / metrics.disk_space.total) * 100).toFixed(1)}%</span>
                  </div>
                  <div className="h-4 w-full bg-slate-800/80 rounded-full overflow-hidden shadow-inner flex mb-2">
                    <div className="h-full bg-gradient-to-r from-amber-600 to-amber-400" style={{ width: `${(metrics.disk_space.used / metrics.disk_space.total) * 100}%` }} />
                  </div>
                  <div className="flex justify-between text-xs text-slate-400">
                    <span>{metrics.disk_space.used.toFixed(1)} GB Used</span>
                    <span>{metrics.disk_space.free.toFixed(1)} GB Free</span>
                  </div>
                </div>

                {/* Pool 2 */}
                <div>
                  <div className="flex justify-between items-end mb-3">
                    <div>
                      <h3 className="text-sm font-bold text-slate-200">/ (Root)</h3>
                      <p className="text-xs text-slate-500 mt-0.5">NVMe SSD • 512 GB Total</p>
                    </div>
                    <span className="text-2xl font-bold tracking-tight text-slate-300">18.4%</span>
                  </div>
                  <div className="h-4 w-full bg-slate-800/80 rounded-full overflow-hidden shadow-inner flex mb-2">
                    <div className="h-full bg-slate-500" style={{ width: `18.4%` }} />
                  </div>
                  <div className="flex justify-between text-xs text-slate-400">
                    <span>94.2 GB Used</span>
                    <span>417.8 GB Free</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      );
    }

    if (activeTab === 'services') {
      const servicesEntries = Object.entries(metrics.services);

      return (
        <div className="space-y-6 animate-fade-in">
          <div className="flex justify-between items-end mb-8">
            <div>
              <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
                App Ecosystem
                <span className="text-xs font-semibold px-2.5 py-1 bg-white/10 rounded-full text-slate-300 border border-white/5">{servicesEntries.length} Total</span>
              </h2>
              <p className="text-slate-400 text-sm mt-2">Manage and monitor containerized services within the nexus.</p>
            </div>
            <div className="flex gap-3">
              <button className="px-4 py-2 bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 rounded-lg text-sm font-medium text-slate-300 transition-all flex items-center gap-2">
                <RefreshCw size={14} /> Sync All
              </button>
              <button
                onClick={() => setActiveTab('marketplace')}
                className="px-4 py-2 bg-indigo-500 hover:bg-indigo-400 rounded-lg text-sm font-semibold text-white transition-all shadow-lg shadow-indigo-500/20"
              >
                Deploy App
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-5">
            {servicesEntries.map(([name, data]) => {
              const isRunning = data.status === 'running';
              const isError = data.status === 'error';

              return (
                <div key={name} className="bg-white/[0.02] border border-white/[0.05] rounded-2xl p-6 hover:bg-white/[0.04] transition-all hover:border-white/10 group cursor-default relative overflow-hidden">

                  {/* Status Glow Banner */}
                  <div className={`absolute top-0 left-0 w-1 h-full ${isRunning ? 'bg-emerald-500/50' : (isError ? 'bg-red-500/50' : 'bg-slate-500/50')} transition-colors`}></div>

                  <div className="flex justify-between items-start mb-6">
                    <div className="flex items-center gap-4">
                      <div className="h-12 w-12 rounded-2xl bg-slate-900 border border-white/10 flex items-center justify-center shadow-inner group-hover:scale-105 transition-transform">
                        <Box size={24} className={isRunning ? 'text-emerald-400' : (isError ? 'text-red-400' : 'text-slate-500')} />
                      </div>
                      <div>
                        <h3 className="text-base font-bold text-slate-200 group-hover:text-white transition-colors">{name}</h3>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="relative flex h-2 w-2">
                            {isRunning && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
                            <span className={`relative inline-flex rounded-full h-2 w-2 ${isRunning ? 'bg-emerald-500' : (isError ? 'bg-red-500' : 'bg-slate-500')}`}></span>
                          </span>
                          <span className="text-xs font-medium text-slate-400 capitalize">{data.status}</span>
                        </div>
                      </div>
                    </div>
                    <button className="p-2 text-slate-500 hover:text-slate-300 hover:bg-white/5 rounded-lg transition-colors">
                      <Settings size={18} />
                    </button>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mb-6">
                    <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.02]">
                      <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Version</span>
                      <p className="text-sm font-medium text-slate-300 mt-0.5">{data.version}</p>
                    </div>
                    <div className="bg-slate-900/50 rounded-xl p-3 border border-white/[0.02]">
                      <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Uptime</span>
                      <p className="text-sm font-medium text-slate-300 mt-0.5">{data.uptime}</p>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    {isRunning ? (
                      <>
                        <button className="flex-1 py-2 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2">
                          <Globe size={14} /> Web UI
                        </button>
                        <button className="p-2 bg-slate-800/80 hover:bg-amber-500/20 hover:text-amber-400 text-slate-400 rounded-lg transition-colors">
                          <RotateCcw size={16} />
                        </button>
                        <button className="p-2 bg-slate-800/80 hover:bg-red-500/20 hover:text-red-400 text-slate-400 rounded-lg transition-colors">
                          <Square size={16} className="fill-current" />
                        </button>
                      </>
                    ) : (
                      <button className="w-full py-2 bg-indigo-500/20 hover:bg-indigo-500 text-indigo-300 hover:text-white text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-2 border border-indigo-500/30">
                        <Play size={14} className="fill-current" /> Start Service
                      </button>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )
    }

    if (activeTab === 'marketplace') {
      const MOCK_APPS = [
        { name: 'Jellyfin', desc: 'The Free Software Media System.', hits: 15400, category: 'Media' },
        { name: 'Nextcloud', desc: 'A safe home for all your data.', hits: 32000, category: 'Storage' },
        { name: 'Home Assistant', desc: 'Open source home automation.', hits: 25000, category: 'Smart Home' },
        { name: 'Pi-hole', desc: 'Network-wide Ad Blocking.', hits: 18500, category: 'Network' },
        { name: 'qBittorrent', desc: 'A Qt5 bittorrent client.', hits: 11200, category: 'Downloaders' },
        { name: 'Vaultwarden', desc: 'Unofficial Bitwarden compatible server.', hits: 9000, category: 'Security' },
      ];

      return (
        <div className="space-y-6 animate-fade-in relative z-10 w-full min-h-screen">
          <div className="absolute inset-0 bg-blue-500/5 rounded-full blur-[120px] pointer-events-none -translate-y-1/2 -translate-x-1/2"></div>

          <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-6 mb-8 relative z-10">
            <div>
              <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
                <Store size={28} className="text-indigo-400" />
                AetherMarketplace
              </h2>
              <p className="text-slate-400 text-sm mt-2">Discover and deploy containerized applications with a single click.</p>
            </div>
            <div className="flex gap-3 w-full md:w-auto">
              <div className="relative flex-1 md:w-64">
                <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search applications..."
                  className="w-full bg-slate-900/80 border border-white/10 rounded-lg py-2 pl-9 pr-4 text-sm text-slate-200 focus:outline-none focus:border-indigo-500/50 transition-colors"
                />
              </div>
              <button className="px-3 py-2 bg-slate-900/80 border border-white/10 rounded-lg text-slate-300 hover:text-white transition-colors flex items-center justify-center">
                <Filter size={16} />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 relative z-10">
            {MOCK_APPS.map((app, idx) => (
              <div key={idx} className="bg-slate-950/80 border border-white/10 rounded-2xl p-6 backdrop-blur-xl hover:border-indigo-500/50 transition-all group flex flex-col justify-between h-full">
                <div>
                  <div className="flex items-start justify-between mb-4">
                    <div className="h-14 w-14 bg-white/5 rounded-xl border border-white/10 flex items-center justify-center shadow-inner overflow-hidden">
                      <Box size={28} className="text-slate-300 group-hover:text-indigo-400 transition-colors" />
                    </div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 bg-white/5 px-2 py-1 rounded-md border border-white/5">
                      {app.category}
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-slate-200 group-hover:text-white transition-colors">{app.name}</h3>
                  <p className="text-sm text-slate-400 mt-2 line-clamp-2 leading-relaxed">{app.desc}</p>
                </div>

                <div className="mt-8 pt-4 border-t border-white/5 flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-slate-500 text-xs font-medium">
                    <Download size={14} />
                    {(app.hits / 1000).toFixed(1)}k Installs
                  </div>
                  <button className="px-4 py-1.5 bg-indigo-500 hover:bg-indigo-400 text-white text-xs font-semibold rounded-lg shadow-sm transition-all group-hover:shadow-[0_0_15px_rgba(99,102,241,0.4)]">
                    Install
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )
    }

    if (activeTab === 'ai') {
      return (
        <div className="h-[calc(100vh-10rem)] flex flex-col bg-white/[0.01] border border-white/[0.03] rounded-3xl relative overflow-hidden animate-fade-in shadow-2xl backdrop-blur-xl">

          {/* Background gradient effects */}
          <div className="absolute top-0 left-0 w-[500px] h-[500px] bg-indigo-500/10 rounded-full blur-[100px] pointer-events-none -translate-x-1/2 -translate-y-1/2"></div>
          <div className="absolute bottom-0 right-0 w-[600px] h-[600px] bg-blue-500/5 rounded-full blur-[120px] pointer-events-none translate-x-1/3 translate-y-1/3"></div>

          <div className="flex items-center justify-between p-6 border-b border-white/[0.05] bg-slate-900/50 relative z-10 backdrop-blur-md">
            <div className="flex items-center gap-4">
              <div className="h-10 w-10 bg-indigo-500/20 rounded-xl flex items-center justify-center border border-indigo-500/30">
                <Sparkles size={20} className="text-indigo-400" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-200 tracking-tight">FlowAI Assistant</h2>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="relative flex h-1.5 w-1.5"><span className="absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span><span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-indigo-500"></span></span>
                  <span className="text-xs text-slate-400 font-medium tracking-wide">Ready via Selected Google AI Model</span>
                </div>
              </div>
            </div>
            <button onClick={() => setActiveTab('settings')} className="p-2 text-slate-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors">
              <Settings size={18} />
            </button>
          </div>

          {/* Chat Area Mockup */}
          <div className="flex-1 overflow-y-auto p-8 space-y-8 relative z-10 no-scrollbar">
            {/* Assistant Intro */}
            <div className="flex gap-4 max-w-3xl">
              <div className="h-8 w-8 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0 mt-1">
                <Bot size={16} className="text-indigo-400" />
              </div>
              <div className="space-y-2">
                <div className="bg-white/[0.03] border border-white/[0.05] p-5 rounded-2xl rounded-tl-sm text-slate-200 text-sm leading-relaxed shadow-sm">
                  Hello! I am FlowAI, your localized infrastructure management assistant. I'm connected to your system metrics, docker containers, and media pipelines.
                  <br /><br />
                  I noticed **WireGuard VPN** is currently returning an <span className="text-red-400 font-mono bg-red-500/10 px-1 py-0.5 rounded">error</span> state. Would you like me to pull the trace logs for you, or restart the container?
                </div>
                <div className="flex gap-2">
                  <button className="px-3 py-1.5 bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 rounded-md text-[11px] font-medium text-slate-300 transition-colors">Pull Trace Logs</button>
                  <button className="px-3 py-1.5 bg-white/[0.03] hover:bg-white/[0.08] border border-white/10 rounded-md text-[11px] font-medium text-slate-300 transition-colors">Force Restart</button>
                </div>
              </div>
            </div>

            {/* User Message */}
            <div className="flex gap-4 max-w-3xl ml-auto justify-end">
              <div className="bg-indigo-600 p-5 rounded-2xl rounded-tr-sm text-white text-sm leading-relaxed shadow-md font-medium">
                Actually, let's look at the storage. How is the cache drive holding up?
              </div>
              <div className="h-8 w-8 rounded-full bg-slate-700/50 border border-white/10 flex items-center justify-center shrink-0 mt-1">
                <User size={16} className="text-slate-300" />
              </div>
            </div>

            {/* Assistant Reply */}
            <div className="flex gap-4 max-w-3xl">
              <div className="h-8 w-8 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center shrink-0 mt-1">
                <Bot size={16} className="text-indigo-400" />
              </div>
              <div className="bg-white/[0.03] border border-white/[0.05] p-5 rounded-2xl rounded-tl-sm text-slate-200 text-sm leading-relaxed shadow-sm space-y-4">
                <p>Your NVMe cache drive (`/` Root) is currently in excellent condition. It is at **18.4% capacity** (94.2 GB used out of 512 GB).</p>

                <div className="p-4 bg-slate-900/50 rounded-xl border border-white/5 font-mono text-xs text-slate-400">
                  $ df -h /<br />
                  Filesystem      Size  Used Avail Use% Mounted on<br />
                  /dev/nvme0n1p2  512G   94G  418G  19% /
                </div>
                <p className="text-slate-400 italic text-xs">I can configure an automated alert if capacity exceeds 80%. Should I set that up?</p>
              </div>
            </div>
          </div>

          {/* Input Area */}
          <div className="p-6 bg-slate-950/80 backdrop-blur-xl border-t border-white/[0.05] relative z-10 w-full">
            <div className="relative max-w-4xl mx-auto flex items-end overflow-hidden rounded-2xl bg-white/[0.02] border border-white/10 focus-within:border-indigo-500/50 focus-within:bg-white/[0.04] transition-all shadow-inner">
              <textarea
                placeholder="Ask FlowAI about your system..."
                className="w-full bg-transparent py-4 pl-6 pr-16 text-slate-200 placeholder:text-slate-500 focus:outline-none resize-none overflow-hidden min-h-[56px] text-sm"
                rows={1}
              />
              <div className="absolute right-2 bottom-2 flex gap-2">
                <button className="p-2 text-slate-400 hover:text-white hover:bg-white/10 rounded-xl transition-colors">
                  <Lock size={18} />
                </button>
                <button className="p-2 bg-indigo-500 rounded-xl text-white hover:bg-indigo-400 shadow-md transition-colors">
                  <ChevronRight size={18} />
                </button>
              </div>
            </div>
            <div className="text-center mt-3">
              <p className="text-[10px] text-slate-500 font-medium">FlowAI can make mistakes. Verify critical configuration changes before applying.</p>
            </div>
          </div>
        </div>
      )
    }

    if (activeTab === 'settings') {
      return (
        <div className="space-y-6 animate-fade-in relative z-10">
          <div className="bg-white/[0.02] border border-white/[0.05] rounded-3xl p-10 backdrop-blur-xl relative overflow-hidden">
            {/* Background glow for settings */}
            <div className="absolute top-0 right-0 w-[400px] h-[400px] bg-slate-500/10 rounded-full blur-[100px] pointer-events-none -translate-y-1/2 translate-x-1/3"></div>

            <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3 mb-8 pb-4 border-b border-white/5 relative z-10">
              <Settings size={24} className="text-slate-400" />
              System Settings & AI Configuration
            </h2>

            <div className="max-w-2xl space-y-8 relative z-10">
              {/* FlowAI Config block */}
              <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6">
                <h3 className="text-lg font-bold text-slate-200 mb-6 flex items-center gap-2">
                  <Sparkles size={18} className="text-indigo-400" /> FlowAI Engine
                </h3>
                <div className="space-y-6">
                  <div>
                    <label className="block text-sm font-semibold text-slate-300 mb-2">Active Language Model (Google OAuth)</label>
                    <div className="relative">
                      <select className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3.5 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors appearance-none cursor-pointer">
                        <option value="gemini-1.5-ultra">Gemini 1.5 Ultra (Google OAuth Connected)</option>
                        <option value="gemini-1.5-pro">Gemini 1.5 Pro (Google OAuth Connected)</option>
                        <option value="gemini-1.0-pro">Gemini 1.0 Pro</option>
                      </select>
                      <ChevronRight size={16} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 rotate-90 pointer-events-none" />
                    </div>
                    <p className="text-xs text-slate-500 mt-2">Select the underlying model for FlowAI computations. Ultra provides best performance for complex log analysis.</p>
                  </div>

                  <div>
                    <label className="block text-sm font-semibold text-slate-300 mb-2">Default System Prompt</label>
                    <textarea
                      className="w-full bg-slate-900 border border-white/10 rounded-xl px-4 py-3 text-slate-200 text-sm focus:outline-none focus:border-indigo-500/50 transition-colors min-h-[100px] resize-none"
                      defaultValue="You are FlowAI, a highly intelligent infrastructure assistant connected to a local Next.js + Go Nexus environment. Always prioritize safe and performant configurations."
                    />
                    <p className="text-xs text-slate-500 mt-2">Tune the prompt to modify the assistant's behavior and strictness.</p>
                  </div>
                </div>
              </div>

              {/* Other settings mock */}
              <div className="bg-slate-950/50 border border-white/10 rounded-2xl p-6 opacity-50 pointer-events-none">
                <h3 className="text-lg font-bold text-slate-200 mb-6 flex items-center gap-2">
                  <Shield size={18} className="text-emerald-400" /> Security Policies
                  <span className="text-[10px] font-bold bg-white/10 px-2 py-0.5 rounded ml-2">Coming Soon</span>
                </h3>
                <div className="space-y-4 text-sm text-slate-400">
                  Configuration restricted in demo mode.
                </div>
              </div>

              <button className="px-8 py-3 bg-indigo-500 hover:bg-indigo-400 rounded-xl text-sm font-bold text-white transition-all shadow-lg shadow-indigo-500/20">
                Save Configuration
              </button>
            </div>
          </div>
        </div>
      );
    }

    // Fallback if blank
    return <div className="text-slate-400">Please select an option from the sidebar.</div>
  }; // <-- Added missing semicolon/closing brace here

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-50 overflow-hidden font-sans selection:bg-indigo-500/30">

      {/* Background ambient lighting */}
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-full pointer-events-none z-0">
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-indigo-900/20 rounded-full blur-[120px]"></div>
        <div className="absolute top-[20%] right-[-10%] w-[40%] h-[40%] bg-blue-900/10 rounded-full blur-[100px]"></div>
      </div>

      {/* Vertical Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex flex-col bg-slate-950/80 backdrop-blur-2xl border-r border-white/5 transition-all duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] ${isSidebarHovered ? 'w-64' : 'w-20'} shadow-2xl`}
        onMouseEnter={() => setIsSidebarHovered(true)}
        onMouseLeave={() => setIsSidebarHovered(false)}
      >
        <div className="flex h-20 items-center px-6 border-b border-white/5 relative overflow-hidden shrink-0">
          {/* Header Glow */}
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-indigo-500/50 to-transparent"></div>

          <div className="flex items-center gap-4 w-full relative z-10 mt-1">
            <div className="h-9 w-9 min-w-[2.25rem] rounded-xl bg-gradient-to-br from-indigo-500 via-blue-600 to-indigo-800 flex items-center justify-center shadow-[0_0_20px_rgba(99,102,241,0.3)] relative overflow-hidden">
              <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI4IiBoZWlnaHQ9IjgiPgo8cmVjdCB3aWR0aD0iOCIgaGVpZ2h0PSI4IiBmaWxsPSIjZmZmIiBmaWxsLW9wYWNpdHk9IjAuMSIvPgo8L3N2Zz4=')] opacity-30 mix-blend-overlay"></div>
              <span className="font-extrabold text-white text-lg tracking-tighter mix-blend-screen drop-shadow-md">A</span>
            </div>
            <h1 className={`text-xl font-bold tracking-tight bg-gradient-to-r from-slate-100 to-slate-400 bg-clip-text text-transparent transition-opacity duration-300 truncate whitespace-nowrap ${isSidebarHovered ? 'opacity-100' : 'opacity-0 w-0'}`}>
              AetherFlow
            </h1>
          </div>
        </div>

        <nav className="flex-1 px-3 py-6 space-y-1.5 overflow-y-auto no-scrollbar relative z-10">
          <div className={`px-4 pb-2 text-[10px] font-bold text-slate-500 uppercase tracking-widest transition-opacity duration-300 ${isSidebarHovered ? 'opacity-100' : 'opacity-0'}`}>Nexus</div>
          {NAVIGATION.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center relative gap-4 px-3.5 py-3 rounded-xl transition-all duration-300 group overflow-hidden ${isActive
                  ? 'bg-indigo-500/10 text-indigo-100 shadow-sm border border-indigo-500/20'
                  : 'text-slate-400 hover:bg-white/5 hover:text-slate-200 border border-transparent'
                  }`}
              >
                {/* Active Indicator Line */}
                <div className={`absolute left-0 top-1/2 -translate-y-1/2 w-1 h-1/2 bg-indigo-500 rounded-r-full transition-all duration-300 ${isActive ? 'scale-y-100 opacity-100' : 'scale-y-0 opacity-0'}`}></div>

                <div className={`min-w-[1.25rem] flex items-center justify-center transition-colors ${isActive ? 'text-indigo-400 drop-shadow-[0_0_8px_rgba(129,140,248,0.5)]' : 'group-hover:text-slate-300'}`}>
                  {item.icon}
                </div>
                <span className={`font-semibold transition-all duration-300 whitespace-nowrap truncate text-sm tracking-wide ${isSidebarHovered ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4'}`}>
                  {item.label}
                </span>

                {/* AI Sparkle specific active state */}
                {isActive && item.id === 'ai' && (
                  <div className="absolute right-4 w-1.5 h-1.5 rounded-full bg-indigo-400 shadow-[0_0_8px_#818CF8] animate-pulse"></div>
                )}
              </button>
            )
          })}
        </nav>

        <div className="p-4 border-t border-white/5 bg-slate-950/50 backdrop-blur-md relative z-10 shrink-0">
          {BOTTOM_NAVIGATION.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center gap-4 px-3 py-2.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-white/5 transition-all duration-300 group overflow-hidden ${activeTab === item.id ? 'bg-white/10 text-white' : ''}`}
            >
              <div className="min-w-[1.125rem] flex items-center justify-center group-hover:scale-110 transition-transform">
                {item.icon}
              </div>
              <span className={`text-sm font-semibold tracking-wide transition-all duration-300 whitespace-nowrap truncate ${isSidebarHovered ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-4'}`}>
                {item.label}
              </span>
            </button>
          ))}
        </div>
      </aside>

      {/* Main Content Area */}
      <main className={`flex-1 transition-all duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] relative z-10 h-screen overflow-y-auto no-scrollbar ${isSidebarHovered ? 'ml-64' : 'ml-20'}`}>
        {/* Top Header */}
        <header className="h-20 px-10 flex items-center justify-between border-b border-white/[0.02] bg-slate-950/40 backdrop-blur-xl sticky top-0 z-40">
          <div className="flex items-center gap-6">
            <h2 className="text-2xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent capitalize tracking-tight flex items-center gap-3">
              {activeTab === 'settings' || activeTab === 'security' || activeTab === 'logout'
                ? BOTTOM_NAVIGATION.find(n => n.id === activeTab)?.label
                : NAVIGATION.find(n => n.id === activeTab)?.label}
            </h2>
          </div>

          <div className="flex items-center gap-4">
            {/* API Status Badge */}
            <div className="flex items-center space-x-3 bg-slate-950 border border-white/10 px-4 py-2 rounded-full shadow-inner mr-2">
              <Wifi size={14} className={error ? 'text-red-400' : 'text-emerald-400'} />
              <span className="text-[11px] font-bold text-slate-300 tracking-wider uppercase">
                {error ? 'API Offline (Mock Mode)' : 'API Connected'}
              </span>
            </div>

            {/* User Profile Mock */}
            <div className="h-10 w-10 rounded-full bg-slate-800 border border-white/10 flex items-center justify-center overflow-hidden cursor-pointer hover:border-indigo-500/50 transition-colors">
              <div className="absolute inset-0 bg-gradient-to-tr from-indigo-500/20 to-blue-500/20"></div>
              <User size={18} className="text-slate-300" />
            </div>
          </div>
        </header>

        {/* Scrollable Content */}
        <div className="p-10 max-w-[1600px] mx-auto min-h-[calc(100vh-5rem)]">
          {renderContent()}
        </div>
      </main>
    </div>
  );
}
