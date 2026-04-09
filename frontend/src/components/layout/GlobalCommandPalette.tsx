'use client';

import React from 'react';
import {
  LayoutDashboard,
  Server,
  Shield,
  Settings,
  Users,
  Store,
  FolderOpen
} from 'lucide-react';
import { useSystemStore } from '@/store/useSystemStore';
import { TabId } from '@/types/dashboard';
import { CommandPalette, PaletteAction } from '@aetherflow/ui';

const standardActions: PaletteAction[] = [
  { id: 'nav-overview', title: 'Go to Overview', icon: LayoutDashboard, type: 'navigate', tab: 'overview' },
  { id: 'nav-services', title: 'Go to Services', icon: Server, type: 'navigate', tab: 'services' },
  { id: 'nav-marketplace', title: 'Go to Marketplace', icon: Store, type: 'navigate', tab: 'marketplace' },
  { id: 'nav-fileshare', title: 'Go to File Share', icon: FolderOpen, type: 'navigate', tab: 'fileshare' },
  { id: 'nav-security', title: 'Go to Security', icon: Shield, type: 'navigate', tab: 'security' },
  { id: 'nav-users', title: 'Manage Users', icon: Users, type: 'navigate', tab: 'users' },
  { id: 'nav-settings', title: 'Go to Settings', icon: Settings, type: 'navigate', tab: 'settings' },
];

export function GlobalCommandPalette() {
  const { setActiveTab } = useSystemStore();

  const handleAction = (action: PaletteAction) => {
    if (action.type === 'navigate' && action.tab) {
      setActiveTab(action.tab as TabId);
    }
  };

  return <CommandPalette actions={standardActions} onAction={handleAction} />;
}
