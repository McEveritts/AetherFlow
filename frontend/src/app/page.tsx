'use client';

import { useEffect, useState } from 'react';
import { TabId, SystemMetrics } from '@/types/dashboard';
import Sidebar from '@/components/layout/Sidebar';
import Header from '@/components/layout/Header';
import OverviewTab from '@/components/tabs/OverviewTab';
import ServicesTab from '@/components/tabs/ServicesTab';
import MarketplaceTab from '@/components/tabs/MarketplaceTab';
import AiChatTab from '@/components/tabs/AiChatTab';
import SettingsTab from '@/components/tabs/SettingsTab';

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

  const renderContent = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewTab metrics={metrics} />;
      case 'services':
        return <ServicesTab metrics={metrics} onDeployApp={() => setActiveTab('marketplace')} />;
      case 'marketplace':
        return <MarketplaceTab />;
      case 'ai':
        return <AiChatTab setActiveTab={setActiveTab} />;
      case 'settings':
        return <SettingsTab />;
      default:
        return <div className="text-slate-400">Please select an option from the sidebar.</div>;
    }
  };

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-50 overflow-hidden font-sans selection:bg-indigo-500/30">

      {/* Background ambient lighting */}
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-full pointer-events-none z-0">
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-indigo-900/20 rounded-full blur-[120px]"></div>
        <div className="absolute top-[20%] right-[-10%] w-[40%] h-[40%] bg-blue-900/10 rounded-full blur-[100px]"></div>
      </div>

      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isSidebarHovered={isSidebarHovered}
        setIsSidebarHovered={setIsSidebarHovered}
      />

      <main className={`flex-1 transition-all duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] relative z-10 h-screen overflow-y-auto no-scrollbar ${isSidebarHovered ? 'ml-64' : 'ml-20'}`}>
        <Header activeTab={activeTab} error={error} />

        {/* Scrollable Content */}
        <div className="p-10 max-w-[1600px] mx-auto min-h-[calc(100vh-5rem)]">
          {renderContent()}
        </div>
      </main>
    </div>
  );
}
