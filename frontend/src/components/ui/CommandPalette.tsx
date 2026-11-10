'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
  Command,
  Settings,
  LayoutDashboard,
  Server,
  Shield,
  Database,
  Trash2,
  RefreshCw,
  Users,
  Store,
  Folder,
  FolderOpen,
  Bot,
  X,
  Radio,
  Boxes,
  Tv
} from 'lucide-react';
import { useSystemStore } from '@/store/useSystemStore';
import { TabId } from '@/types/dashboard';
import { useToast } from '@/contexts/ToastContext';
import { triggerHaptic } from '@/lib/design';
import { Modal } from '@/components/ui/Modal';

type ActionType = 'navigate' | 'task';

interface PaletteAction {
  id: string;
  title: string;
  icon: React.ElementType;
  type: ActionType;
  tab?: TabId;
  taskTitle?: string;
  taskDuration?: number;
}

const actions: PaletteAction[] = [
  { id: 'nav-overview', title: 'Go to Overview', icon: LayoutDashboard, type: 'navigate', tab: 'overview' },
  { id: 'nav-services', title: 'Go to Services', icon: Server, type: 'navigate', tab: 'services' },
  { id: 'nav-marketplace', title: 'Go to Marketplace', icon: Store, type: 'navigate', tab: 'marketplace' },
  { id: 'nav-mcbrowser', title: 'Go to McBrowser', icon: Folder, type: 'navigate', tab: 'mcbrowser' },
  { id: 'nav-fileshare', title: 'Go to File Share', icon: FolderOpen, type: 'navigate', tab: 'fileshare' },
  { id: 'nav-streaming', title: 'Go to Streaming Dashboard', icon: Tv, type: 'navigate', tab: 'streaming' },
  { id: 'nav-network', title: 'Go to Network & VPN', icon: Radio, type: 'navigate', tab: 'network' },
  { id: 'nav-cluster', title: 'Go to Cluster Mesh', icon: Boxes, type: 'navigate', tab: 'cluster' },
  { id: 'nav-security', title: 'Go to Security', icon: Shield, type: 'navigate', tab: 'security' },
  { id: 'nav-users', title: 'Manage Users & Quotas', icon: Users, type: 'navigate', tab: 'users' },
  { id: 'nav-settings', title: 'Go to Settings', icon: Settings, type: 'navigate', tab: 'settings' },

  { id: 'task-backup', title: 'Start Database Backup', icon: Database, type: 'task', taskTitle: 'Database Backup', taskDuration: 5000 },
  { id: 'task-cache', title: 'Clear System Cache', icon: Trash2, type: 'task', taskTitle: 'Cache Clearance', taskDuration: 2000 },
  { id: 'task-restart', title: 'Restart AetherFlow API', icon: RefreshCw, type: 'task', taskTitle: 'API Restart', taskDuration: 8000 },

  { id: 'ai-analyze', title: 'Ask AI: Analyze System Logs', icon: Bot, type: 'task', taskTitle: 'AI Log Analysis', taskDuration: 12000 },
  { id: 'ai-optimize', title: 'Ask AI: Run Deep Optimizer', icon: Bot, type: 'task', taskTitle: 'Deep Analytics Optimization', taskDuration: 15000 },
];

function fuzzyMatch(pattern: string, sourceString: string): boolean {
  let patternIndex = 0;
  let sourceIndex = 0;
  const lowercasePattern = pattern.toLowerCase();
  const lowercaseSource = sourceString.toLowerCase();
  while (patternIndex < lowercasePattern.length && sourceIndex < lowercaseSource.length) {
    if (lowercasePattern[patternIndex] === lowercaseSource[sourceIndex]) {
      patternIndex++;
    }
    sourceIndex++;
  }
  return patternIndex === lowercasePattern.length;
}

export function CommandPalette() {
  const {
    setActiveTab,
    isCommandPaletteOpen: isOpen,
    setIsCommandPaletteOpen: setIsOpen,
    hapticFeedback,
  } = useSystemStore();
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);

  const { addToast } = useToast();
  const inputRef = useRef<HTMLInputElement>(null);

  const filteredActions = query === '' 
    ? actions 
    : actions.filter((action) => fuzzyMatch(query, action.title));

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
    }
  }, [isOpen]);

  useEffect(() => {
    const handleGlobalKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setIsOpen(!useSystemStore.getState().isCommandPaletteOpen);
      }
    };

    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, [setIsOpen]);

  const executeTask = (title: string, duration: number) => {
    addToast(`Started task: ${title}`, 'info');
    window.setTimeout(() => {
      addToast(`${title} completed successfully`, 'success');
    }, duration);
  };

  const executeAction = (action: PaletteAction) => {
    triggerHaptic(8, hapticFeedback);
    if (action.type === 'navigate' && action.tab) {
      setActiveTab(action.tab);
    } else if (action.type === 'task' && action.taskTitle && action.taskDuration) {
      executeTask(action.taskTitle, action.taskDuration);
    }
    setIsOpen(false);
  };

  const handleInputKeyDown = (event: React.KeyboardEvent) => {
    if (filteredActions.length === 0) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setSelectedIndex((previousIndex) => (previousIndex + 1) % filteredActions.length);
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setSelectedIndex((previousIndex) => (previousIndex - 1 + filteredActions.length) % filteredActions.length);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      if (filteredActions[selectedIndex]) {
        executeAction(filteredActions[selectedIndex]);
      }
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={() => setIsOpen(false)}
      aria-label="Command Palette"
      initialFocusRef={inputRef}
      className="max-w-2xl p-0 overflow-hidden rounded-3xl border border-white/10 bg-slate-900/90 shadow-2xl backdrop-blur-2xl"
    >
      <div className="flex flex-col">
        <div className="flex items-center border-b border-white/10 px-4 py-3">
          <Search className="h-5 w-5 text-slate-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Type a command or search..."
            aria-label="Search commands and navigation"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setSelectedIndex(0);
            }}
            onKeyDown={handleInputKeyDown}
            className="flex-1 bg-transparent px-4 py-2 text-slate-100 placeholder:text-slate-500 focus:outline-none min-w-0"
          />
          <div className="hidden sm:flex items-center gap-1 text-xs text-slate-500 mr-2">
            <kbd className="rounded border border-white/10 bg-slate-800 px-1.5 py-0.5 font-sans">esc</kbd>
          </div>
          <button
            type="button"
            onClick={() => setIsOpen(false)}
            aria-label="Close Command Palette"
            className="obs-touch-target-standard obs-gpu-120hz-interactive p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/10 flex items-center justify-center shrink-0"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-2 min-h-[280px] max-h-[60vh] obs-scroller">
          {filteredActions.length === 0 ? (
            <div className="p-8 text-center text-slate-500">
              <Command className="mx-auto mb-3 h-8 w-8 opacity-50" />
              <p>No results found for &quot;{query}&quot;</p>
            </div>
          ) : (
            <div className="flex flex-col gap-1">
              {filteredActions.map((action, actionIndex) => {
                const isSelected = actionIndex === selectedIndex;
                const ActionIcon = action.icon;
                return (
                  <button
                    key={action.id}
                    type="button"
                    className={`flex w-full items-center gap-3 rounded-xl px-4 py-3 text-left obs-touch-target-standard obs-gpu-120hz-interactive ${
                      isSelected ? 'bg-indigo-500/20 text-indigo-100' : 'text-slate-300 hover:bg-white/5'
                    }`}
                    onClick={() => executeAction(action)}
                    onMouseEnter={() => setSelectedIndex(actionIndex)}
                  >
                    <div className={`rounded-lg p-2 ${isSelected ? 'bg-indigo-500/30 text-indigo-400' : 'bg-white/[0.05] text-slate-400'}`}>
                      <ActionIcon className="h-4 w-4" />
                    </div>
                    <span className="flex-1 font-medium">{action.title}</span>
                    {action.type === 'navigate' ? (
                      <span className="text-xs font-bold uppercase tracking-wider text-slate-500">Jump To</span>
                    ) : (
                      <span className="text-xs font-bold uppercase tracking-wider text-amber-500">Run Task</span>
                    )}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div className="bg-slate-950/50 p-3 text-xs text-slate-500 flex justify-between items-center border-t border-white/5">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5"><kbd className="rounded bg-white/5 px-1 pb-0.5 border border-white/10 font-sans">↕</kbd> to navigate</span>
            <span className="flex items-center gap-1.5"><kbd className="rounded bg-white/5 px-1 pb-0.5 border border-white/10 font-sans">↵</kbd> to execute</span>
          </div>
          <div className="flex items-center gap-1.5 font-medium text-slate-400">
            AetherFlow Command Palette
          </div>
        </div>
      </div>
    </Modal>
  );
}
