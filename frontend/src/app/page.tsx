'use client';

import { useSystemStore } from '@/store/useSystemStore';
import Sidebar from '@/components/layout/Sidebar';
import Header from '@/components/layout/Header';
import GlobalBanners from '@/components/layout/GlobalBanners';
import dynamic from 'next/dynamic';

const OverviewTab = dynamic(() => import('@/components/tabs/OverviewTab'), { ssr: false, loading: () => <OverviewSkeleton /> });
const InboxTab = dynamic(() => import('@/components/tabs/InboxTab'), { ssr: false });
const ServicesTab = dynamic(() => import('@/components/tabs/ServicesTab'), { ssr: false });
const MarketplaceTab = dynamic(() => import('@/components/tabs/MarketplaceTab'), { ssr: false });
const AiChatTab = dynamic(() => import('@/components/tabs/AiChatTab'), { ssr: false });
const SettingsTab = dynamic(() => import('@/components/tabs/SettingsTab'), { ssr: false });
const FileshareTab = dynamic(() => import('@/components/tabs/FileshareTab'), { ssr: false });
const ProfileTab = dynamic(() => import('@/components/tabs/ProfileTab'), { ssr: false });
const UsersTab = dynamic(() => import('@/components/tabs/UsersTab'), { ssr: false });
const AuditTab = dynamic(() => import('@/components/tabs/AuditTab'), { ssr: false });
import { useMetrics } from '@/hooks/useMetrics';
import { OverviewSkeleton } from '@/components/layout/SkeletonBox';
import OnboardingWizard from '@/components/layout/OnboardingWizard';
import { ErrorBoundary } from '@/components/ui/ErrorBoundary';
import useSWR from 'swr';

export default function Dashboard() {
  const { activeTab, isSidebarHovered } = useSystemStore();
  const { metrics, hardware, history, isLoading, isError, connectionState } = useMetrics();

  const { data: settingsData, mutate: mutateSettings } = useSWR('/api/v1/auth/settings');

  const renderContent = () => {
    if (isLoading) {
      if (activeTab === 'overview') {
        return <OverviewSkeleton />;
      }

      return (
        <div className="flex items-center justify-center h-full min-h-[50vh]">
          <div className="flex flex-col items-center gap-4 text-slate-400">
            <div className="w-10 h-10 border-4 border-indigo-500/20 border-t-indigo-500 rounded-full animate-spin"></div>
            <p className="font-medium tracking-wide">Establishing Nexus Link...</p>
          </div>
        </div>
      );
    }

    if (isError || !metrics) {
      // Graduated error states instead of a single hard "System Offline" panel
      const isReconnecting = connectionState === 'RECONNECTING';
      const isFallback = connectionState === 'FALLBACK';

      return (
        <div className="flex items-center justify-center h-full min-h-[50vh]">
          <div className={`${isReconnecting ? 'bg-amber-500/10 border-amber-500/20' : isFallback ? 'bg-blue-500/10 border-blue-500/20' : 'bg-red-500/10 border-red-500/20'} border p-8 rounded-2xl flex flex-col items-center gap-4 text-center max-w-md backdrop-blur-md`}>
            <div className={`w-12 h-12 ${isReconnecting ? 'bg-amber-500/20' : isFallback ? 'bg-blue-500/20' : 'bg-red-500/20'} rounded-full flex items-center justify-center text-2xl font-bold ${isReconnecting ? 'text-amber-400' : isFallback ? 'text-blue-400' : 'text-red-400'}`}>
              {isReconnecting ? '⟳' : isFallback ? '◌' : '!'}
            </div>
            <h3 className="text-lg font-bold text-slate-200">
              {isReconnecting ? 'Reconnecting...' : isFallback ? 'Degraded Mode' : 'System Offline'}
            </h3>
            <p className="text-sm text-slate-400">
              {isReconnecting
                ? 'Lost connection to AetherFlow backend. Attempting to reconnect automatically.'
                : isFallback
                  ? 'Live connection unavailable. Polling for system data...'
                  : 'Unable to connect to the AetherFlow backend API. Make sure the Go service is running.'}
            </p>
            <p className={`text-xs font-mono px-2 py-1 rounded truncate max-w-full ${isReconnecting ? 'text-amber-400/80 bg-amber-500/10' : isFallback ? 'text-blue-400/80 bg-blue-500/10' : 'text-red-400/80 bg-red-500/10'}`}>
              {isReconnecting ? `Attempt ${connectionState === 'RECONNECTING' ? 'in progress' : 'pending'}` : isFallback ? 'Waiting for data...' : 'Connection refused'}
            </p>
          </div>
        </div>
      );
    }

    switch (activeTab) {
      case 'overview':
        return <OverviewTab metrics={metrics} hardware={hardware} history={history} />;
      case 'inbox':
        return <InboxTab />;
      case 'services':
        return <ServicesTab />;
      case 'marketplace':
        return <MarketplaceTab />;
      case 'ai':
        return <AiChatTab />;
      case 'settings':
        return <SettingsTab />;
      case 'users':
        return <UsersTab />;
      case 'fileshare':
        return <FileshareTab />;
      case 'profile':
        return <ProfileTab />;
      case 'audit':
        return <AuditTab />;
      default:
        return <div className="text-slate-400">Please select an option from the sidebar.</div>;
    }
  };

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-50 overflow-hidden font-sans selection:bg-indigo-500/30">

      {settingsData && !settingsData.setupCompleted && (
        <OnboardingWizard
          initialSettings={settingsData}
          onComplete={() => mutateSettings({ ...settingsData, setupCompleted: true })}
        />
      )}

      {/* Background ambient lighting */}
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-full pointer-events-none z-0">
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-indigo-900/20 rounded-full blur-[120px]"></div>
        <div className="absolute top-[20%] right-[-10%] w-[40%] h-[40%] bg-blue-900/10 rounded-full blur-[100px]"></div>
      </div>

      <Sidebar />

      <main className={`flex-1 transition-all duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] relative z-10 h-screen overflow-y-auto no-scrollbar ${isSidebarHovered ? 'md:ml-64' : 'md:ml-20'} ml-0`}>
        <Header />

        <div className="mt-4">
          <GlobalBanners />
        </div>

        {/* Scrollable Content */}
        <div className="px-4 pb-4 md:px-10 md:pb-10 max-w-[1600px] mx-auto min-h-[calc(100vh-8rem)]">
          <ErrorBoundary key={activeTab}>
            {renderContent()}
          </ErrorBoundary>
        </div>
      </main>
    </div>
  );
}
