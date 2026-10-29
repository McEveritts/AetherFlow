'use client';

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
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
  // Navigation
  { id: 'nav-overview', title: 'Go to Overview', icon: LayoutDashboard, type: 'navigate', tab: 'overview' },
  { id: 'nav-services', title: 'Go to Services', icon: Server, type: 'navigate', tab: 'services' },
  { id: 'nav-marketplace', title: 'Go to Marketplace', icon: Store, type: 'navigate', tab: 'marketplace' },
  { id: 'nav-fileshare', title: 'Go to File Share', icon: FolderOpen, type: 'navigate', tab: 'fileshare' },
  { id: 'nav-streaming', title: 'Go to Streaming Dashboard', icon: Tv, type: 'navigate', tab: 'streaming' },
  { id: 'nav-network', title: 'Go to Network & VPN', icon: Radio, type: 'navigate', tab: 'network' },
  { id: 'nav-cluster', title: 'Go to Cluster Mesh', icon: Boxes, type: 'navigate', tab: 'cluster' },
  { id: 'nav-security', title: 'Go to Security', icon: Shield, type: 'navigate', tab: 'security' },
  { id: 'nav-users', title: 'Manage Users & Quotas', icon: Users, type: 'navigate', tab: 'users' },
  { id: 'nav-settings', title: 'Go to Settings', icon: Settings, type: 'navigate', tab: 'settings' },

  // Background Tasks
  { id: 'task-backup', title: 'Start Database Backup', icon: Database, type: 'task', taskTitle: 'Database Backup', taskDuration: 5000 },
  { id: 'task-cache', title: 'Clear System Cache', icon: Trash2, type: 'task', taskTitle: 'Cache Clearance', taskDuration: 2000 },
  { id: 'task-restart', title: 'Restart AetherFlow API', icon: RefreshCw, type: 'task', taskTitle: 'API Restart', taskDuration: 8000 },

  // AI Operations
  { id: 'ai-analyze', title: 'Ask AI: Analyze System Logs', icon: Bot, type: 'task', taskTitle: 'AI Log Analysis', taskDuration: 12000 },
  { id: 'ai-optimize', title: 'Ask AI: Run Deep Optimizer', icon: Bot, type: 'task', taskTitle: 'Deep Analytics Optimization', taskDuration: 15000 },
];

function fuzzyMatch(pattern: string, str: string): boolean {
  let patternIdx = 0;
  let strIdx = 0;
  const p = pattern.toLowerCase();
  const s = str.toLowerCase();
  while (patternIdx < p.length && strIdx < s.length) {
    if (p[patternIdx] === s[strIdx]) {
      patternIdx++;
    }
    strIdx++;
  }
  return patternIdx === p.length;
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

  // Filter actions based on fuzzy search query
  const filteredActions = query === '' 
    ? actions 
    : actions.filter((action) => fuzzyMatch(query, action.title));

  useEffect(() => {
    if (!isOpen) return;
    const timer = setTimeout(() => {
      setQuery('');
      setSelectedIndex(0);
      inputRef.current?.focus();
    }, 60);
    return () => clearTimeout(timer);
  }, [isOpen]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsOpen(!useSystemStore.getState().isCommandPaletteOpen);
      } else if (e.key === 'Escape') {
        setIsOpen(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
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

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % filteredActions.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filteredActions.length) % filteredActions.length);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredActions[selectedIndex]) {
        executeAction(filteredActions[selectedIndex]);
      }
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.16, ease: [0.22, 1, 0.36, 1] }}
            className="fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-sm transition-opacity"
            onClick={() => setIsOpen(false)}
          />

          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: -16 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: -16 }}
            transition={{ type: 'spring', damping: 30, stiffness: 420, mass: 0.75 }}
            className="fixed inset-x-4 top-[10vh] sm:inset-auto sm:left-1/2 sm:-translate-x-1/2 sm:top-[16vh] z-50 flex max-h-[80vh] w-auto sm:w-full max-w-2xl flex-col overflow-hidden rounded-3xl border border-white/10 bg-slate-900/90 shadow-2xl backdrop-blur-2xl"
          >
            <div className="flex items-center border-b border-white/10 px-4 py-3">
              <Search className="h-5 w-5 text-slate-400 shrink-0" />
              <input
                ref={inputRef}
                type="text"
                placeholder="Type a command or search..."
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setSelectedIndex(0);
                }}
                onKeyDown={handleKeyDown}
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

            <div className="flex-1 overflow-y-auto p-2 min-h-[280px] obs-scroller">
              {filteredActions.length === 0 ? (
                <div className="p-8 text-center text-slate-500">
                  <Command className="mx-auto mb-3 h-8 w-8 opacity-50" />
                  <p>No results found for &quot;{query}&quot;</p>
                </div>
              ) : (
                <div className="flex flex-col gap-1">
                  {filteredActions.map((action, index) => {
                    const isSelected = index === selectedIndex;
                    const Icon = action.icon;
                    return (
                      <button
                        key={action.id}
                        className={`flex w-full items-center gap-3 rounded-xl px-4 py-3 text-left obs-touch-target-standard obs-gpu-120hz-interactive ${
                          isSelected ? 'bg-indigo-500/20 text-indigo-100' : 'text-slate-300 hover:bg-white/5'
                        }`}
                        onClick={() => executeAction(action)}
                        onMouseEnter={() => setSelectedIndex(index)}
                      >
                        <div className={`rounded-lg p-2 ${isSelected ? 'bg-indigo-500/30 text-indigo-400' : 'bg-white/[0.05] text-slate-400'}`}>
                          <Icon className="h-4 w-4" />
                        </div>
                        <span className="flex-1 font-medium">{action.title}</span>
                        {action.type === 'navigate' ? (
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Jump To</span>
                        ) : (
                          <span className="text-[10px] font-bold uppercase tracking-wider text-amber-500">Run Task</span>
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
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
