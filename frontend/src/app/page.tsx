'use client';

import { useState } from 'react';
import { TabId } from '@/types/dashboard';
import Sidebar from '@/components/layout/Sidebar';
import Header from '@/components/layout/Header';
import OverviewTab from '@/components/tabs/OverviewTab';
import ServicesTab from '@/components/tabs/ServicesTab';
import MarketplaceTab from '@/components/tabs/MarketplaceTab';
import AiChatTab from '@/components/tabs/AiChatTab';
import SettingsTab from '@/components/tabs/SettingsTab';
import SecurityTab from '@/components/tabs/SecurityTab';
import FileshareTab from '@/components/tabs/FileshareTab';
import BackupTab from '@/components/tabs/BackupTab';
import ProfileTab from '@/components/tabs/ProfileTab';
import UsersTab from '@/components/tabs/UsersTab';
import { useMetrics } from '@/hooks/useMetrics';
import { OverviewSkeleton } from '@/components/layout/SkeletonBox';
import OnboardingWizard from '@/components/layout/OnboardingWizard';
import useSWR from 'swr';

const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [isSidebarHovered, setIsSidebarHovered] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const { metrics, services, hardware, isLoading, isError, error } = useMetrics();

  const { data: settingsData, mutate: mutateSettings } = useSWR(
    '/api/settings',
    fetcher,
    { revalidateOnFocus: false }
  );

  const handleTabChange = (tab: TabId) => {
    setActiveTab(tab);
    setIsMobileMenuOpen(false); // Close sidebar automatically on mobile picking a tab
  };

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
      return (
        <div className="flex items-center justify-center h-full min-h-[50vh]">
          <div className="bg-red-500/10 border border-red-500/20 p-8 rounded-2xl flex flex-col items-center gap-4 text-center max-w-md backdrop-blur-md">
            <div className="w-12 h-12 bg-red-500/20 rounded-full flex items-center justify-center text-red-400 text-2xl font-bold">!</div>
            <h3 className="text-lg font-bold text-slate-200">System Offline</h3>
            <p className="text-sm text-slate-400">Unable to connect to the AetherFlow backend API. Make sure the Go service is running.</p>
            <p className="text-xs text-red-400/80 font-mono bg-red-500/10 px-2 py-1 rounded truncate max-w-full">{error?.message || 'Connection refused'}</p>
          </div>
        </div>
      );
    }

    switch (activeTab) {
      case 'overview':
        return <OverviewTab metrics={metrics} hardware={hardware} />;
      case 'services':
        return <ServicesTab />;
      case 'marketplace':
        return <MarketplaceTab />;
      case 'ai':
        return <AiChatTab setActiveTab={handleTabChange} />;
      case 'settings':
        return <SettingsTab />;
      case 'security':
        return <SecurityTab />;
      case 'users':
        return <UsersTab />;
      case 'fileshare':
        return <FileshareTab />;
      case 'backups':
        return <BackupTab />;
      case 'profile':
        return <ProfileTab />;
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

      <Sidebar
        activeTab={activeTab}
        setActiveTab={handleTabChange}
        isSidebarHovered={isSidebarHovered}
        setIsSidebarHovered={setIsSidebarHovered}
        isMobileMenuOpen={isMobileMenuOpen}
        setIsMobileMenuOpen={setIsMobileMenuOpen}
      />

      <main className={`flex-1 transition-all duration-300 ease-[cubic-bezier(0.4,0,0.2,1)] relative z-10 h-screen overflow-y-auto no-scrollbar ${isSidebarHovered ? 'md:ml-64' : 'md:ml-20'} ml-0`}>
        <Header activeTab={activeTab} error={isError ? "API Offline" : null} toggleMobileMenu={() => setIsMobileMenuOpen(!isMobileMenuOpen)} />

        {/* Scrollable Content */}
        <div className="p-4 md:p-10 max-w-[1600px] mx-auto min-h-[calc(100vh-5rem)]">
          {renderContent()}
        </div>
      </main>
    </div>
  );
}
