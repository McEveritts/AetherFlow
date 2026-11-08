'use client';

import { useEffect, useRef } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { useSystemStore } from '@/store/useSystemStore';
import { useShallow } from 'zustand/react/shallow';
import Sidebar from '@/components/layout/Sidebar';
import Header from '@/components/layout/Header';
import GlobalBanners from '@/components/layout/GlobalBanners';
import dynamic from 'next/dynamic';

const OverviewTab = dynamic(() => import('@/components/tabs/OverviewTab'), { ssr: false, loading: () => <OverviewSkeleton /> });
const InboxTab = dynamic(() => import('@/components/tabs/InboxTab'), { ssr: false });
const ServicesTab = dynamic(() => import('@/components/tabs/ServicesTab'), { ssr: false });
const MarketplaceTab = dynamic(() => import('@/components/tabs/MarketplaceTab'), { ssr: false });
const AiChatTab = dynamic(() => import('@/components/tabs/AiChatTab'), { ssr: false });
const MediaFlowTab = dynamic(() => import('@/components/tabs/MediaFlowTab'), { ssr: false });
const StreamingTab = dynamic(() => import('@/components/tabs/StreamingTab'), { ssr: false });
const SettingsTab = dynamic(() => import('@/components/tabs/SettingsTab'), { ssr: false });
const McBrowserTab = dynamic(() => import('@/components/tabs/McBrowserTab'), { ssr: false });
const FileshareTab = dynamic(() => import('@/components/tabs/FileshareTab'), { ssr: false });
const UsersTab = dynamic(() => import('@/components/tabs/UsersTab'), { ssr: false });
const AuditTab = dynamic(() => import('@/components/tabs/AuditTab'), { ssr: false });
const NetworkTab = dynamic(() => import('@/components/tabs/NetworkTab'), { ssr: false });
const ClusterTab = dynamic(() => import('@/components/tabs/ClusterTab'), { ssr: false });
const NotificationsSettingsTab = dynamic(() => import('@/components/tabs/NotificationsSettingsTab'), { ssr: false });
const QuotasTab = dynamic(() => import('@/components/tabs/QuotasTab'), { ssr: false });
import { useMetrics } from '@/hooks/useMetrics';
import { OverviewSkeleton } from '@/components/layout/SkeletonBox';
import OnboardingWizard from '@/components/layout/OnboardingWizard';
import { ErrorBoundary } from '@/components/ui/ErrorBoundary';
import useSWR from 'swr';

function OverviewTelemetrySection() {
  const { metrics, hardware, history, isLoading, isError, connectionState } = useMetrics();

  if (isLoading) {
    return <OverviewSkeleton />;
  }

  if (isError || !metrics) {
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

  return <OverviewTab metrics={metrics} hardware={hardware} history={history} />;
}

export default function Dashboard() {
  const { user } = useAuth();
  const { activeTab } = useSystemStore(
    useShallow((state) => ({
      activeTab: state.activeTab,
    }))
  );

  const { data: settingsData, mutate: mutateSettings } = useSWR('/api/v1/auth/settings');
  const mainRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (mainRef.current) mainRef.current.scrollTop = 0;
    window.scrollTo(0, 0);
  }, [activeTab]);

  const renderContent = () => {
    if (activeTab === 'mcbrowser') {
      return null;
    }

    switch (activeTab) {
      case 'overview':
        return <OverviewTelemetrySection />;
      case 'inbox':
        return <InboxTab />;
      case 'services':
        return <ServicesTab />;
      case 'marketplace':
        return <MarketplaceTab />;
      case 'ai':
        return <AiChatTab />;
      case 'mediaflow':
        return <MediaFlowTab />;
      case 'streaming':
        return <StreamingTab />;
      case 'settings':
        return <SettingsTab />;
      case 'users':
        return <UsersTab />;
      case 'fileshare':
        return <FileshareTab />;
      case 'audit':
        return <AuditTab />;
      case 'network':
        return <NetworkTab />;
      case 'cluster':
        return <ClusterTab />;
      case 'notifications':
        return <NotificationsSettingsTab />;
      case 'quotas':
        return <QuotasTab />;
      default:
        return <div className="text-slate-400">Please select an option from the sidebar.</div>;
    }
  };

  return (
    <div className="flex min-h-screen bg-transparent text-slate-50 font-sans selection:bg-indigo-500/30">

      {settingsData && !settingsData.setupCompleted && (
        <OnboardingWizard
          initialSettings={settingsData}
          onComplete={() => mutateSettings({ ...settingsData, setupCompleted: true })}
        />
      )}

      <Sidebar />

      <main ref={mainRef} className="flex-1 min-w-0 max-w-full relative z-10 h-screen overflow-y-auto no-scrollbar">
        <Header />

        <div className={activeTab === 'overview' ? undefined : 'mt-4'}>
          <GlobalBanners />
        </div>

        {/* Scrollable Content with mobile dock bottom clearance (pb-24) */}
        <div className={`pb-24 md:pb-10 min-h-[calc(100vh-8rem)] min-w-0 max-w-full ${activeTab === 'overview' ? 'w-full' : 'px-4 md:px-10 max-w-[1600px] mx-auto'}`}>
          <div hidden={activeTab !== 'mcbrowser'}>
            {user && <ErrorBoundary key={`mcbrowser-${user.id}`}>
              <McBrowserTab isActive={activeTab === 'mcbrowser'} />
            </ErrorBoundary>}
          </div>
          <ErrorBoundary key={activeTab}>
            {renderContent()}
          </ErrorBoundary>
        </div>
      </main>
    </div>
  );
}
