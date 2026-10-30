'use client';

import React, { useState, useEffect, useRef } from 'react';
import { Folder, ChevronRight, ChevronDown, Loader2, CornerLeftUp } from 'lucide-react';
import { apiFetch } from '@/lib/fetcher';

interface PathSelectorProps {
  value: string;
  onChange: (path: string) => void;
  placeholder?: string;
  className?: string;
}

const ALLOWED_ROOT_PRESETS = ['/home', '/mnt', '/media', '/opt/AetherFlow', '/var/lib/aetherflow'];

export default function PathSelector({ value, onChange, placeholder = "Enter absolute path (e.g. /mnt/media)", className = "" }: PathSelectorProps) {
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [directories, setDirectories] = useState<string[]>([]);
  
  const dropdownRef = useRef<HTMLDivElement>(null);
  const skipDebounceRef = useRef<boolean>(false);

  useEffect(() => {
    const handleClickOutside = (event: PointerEvent | MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('pointerdown', handleClickOutside);
    return () => document.removeEventListener('pointerdown', handleClickOutside);
  }, []);

  const fetchDirectories = async (path: string) => {
    const trimmed = path.trim();
    if (!trimmed) return;
    if (trimmed === '/') {
      setDirectories([]);
      setIsLoading(false);
      return;
    }
    
    setIsLoading(true);
    try {
      const response = await apiFetch(`/api/v1/auth/fs?path=${encodeURIComponent(trimmed)}`);
      if (response.ok) {
        const data = await response.json();
        if (Array.isArray(data.directories)) {
          setDirectories(data.directories);
        } else if (Array.isArray(data.entries)) {
          const dirNames = data.entries
            .filter((entry: { is_dir?: boolean }) => entry.is_dir)
            .map((entry: { name: string }) => entry.name);
          setDirectories(dirNames);
        } else {
          setDirectories([]);
        }
      } else {
        setDirectories([]); 
      }
    } catch {
      setDirectories([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!isOpen || !value) return;
    if (skipDebounceRef.current) {
      skipDebounceRef.current = false;
      fetchDirectories(value);
      return;
    }
    const timer = setTimeout(() => fetchDirectories(value), 250);
    return () => clearTimeout(timer);
  }, [isOpen, value]);

  const handleToggle = () => {
    const nextOpen = !isOpen;
    if (nextOpen) {
      skipDebounceRef.current = true;
    }
    setIsOpen(nextOpen);
  };

  const handleInputFocus = () => {
    if (!isOpen) {
      skipDebounceRef.current = true;
      setIsOpen(true);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.value);
  };

  const handleSelectDir = (dir: string) => {
    let newPath = value;
    
    if (dir === '..') {
      const parts = value.split(/[/\\]/).filter(Boolean);
      parts.pop(); 
      newPath = value.startsWith('/') ? '/' + parts.join('/') : parts.join('/');
      if (newPath === '') newPath = '/';
    } else {
      const separator = value.includes('\\') ? '\\' : '/';
      newPath = value.endsWith(separator) ? `${value}${dir}` : `${value}${separator}${dir}`;
    }

    skipDebounceRef.current = true;
    onChange(newPath);
  };

  const handleSelectRoot = (root: string) => {
    skipDebounceRef.current = true;
    onChange(root);
  };

  const isRoot = value === '/' || (/^[a-zA-Z]:\\[^\\]*$/.test(value) && value.length <= 3);

  return (
    <div className={`relative w-full ${isOpen ? 'z-50' : 'z-20'} ${className}`} ref={dropdownRef}>
      <div className="relative flex items-center">
        <button
          type="button"
          onClick={handleToggle}
          aria-label="Browse Directories"
          className="absolute left-0 p-3 obs-touch-target-standard text-slate-400 hover:text-indigo-400 focus:outline-none transition-colors z-10 flex items-center justify-center"
        >
          <Folder size={18} className={isOpen ? "text-indigo-400" : "text-slate-400"} />
        </button>
        
        <input
          type="text"
          value={value}
          onChange={handleInputChange}
          onFocus={handleInputFocus}
          placeholder={placeholder}
          className="w-full min-h-[44px] bg-black/60 border border-white/10 text-slate-100 placeholder-slate-500 rounded-xl py-2.5 pl-11 pr-9 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/30 transition-all text-xs"
        />

        <button
          type="button"
          onClick={handleToggle}
          tabIndex={-1}
          aria-label="Toggle Directory Dropdown"
          className="absolute right-0 px-2.5 h-full text-slate-400 hover:text-indigo-400 focus:outline-none transition-colors z-10 flex items-center justify-center"
        >
          <ChevronDown size={15} className={`transition-transform duration-200 ${isOpen ? 'rotate-180 text-indigo-400' : 'text-slate-400'}`} />
        </button>
      </div>

      {isOpen && (
        <div className="absolute left-0 right-0 z-50 w-full mt-2 glass-panel bg-slate-950/95 backdrop-blur-2xl border border-white/15 rounded-xl shadow-[0_20px_50px_rgba(0,0,0,0.85)] max-h-64 overflow-y-auto obs-scroller scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
          {isLoading ? (
            <div className="flex justify-center items-center py-6 text-slate-400">
              <Loader2 className="animate-spin mr-3 text-indigo-400" size={18} />
              <span className="text-xs font-medium">Scanning directory...</span>
            </div>
          ) : (
            <ul className="py-1">
              {!isRoot && value.length > 0 && (
                <li>
                  <button
                    type="button"
                    onClick={() => handleSelectDir('..')}
                    className="w-full min-h-[44px] obs-touch-target-standard text-left px-4 py-2 text-xs text-slate-300 hover:bg-white/[0.06] hover:text-indigo-300 flex items-center transition-colors border-b border-white/5 pb-2 mb-1"
                  >
                    <CornerLeftUp size={14} className="mr-2 text-slate-500" />
                    <span className="font-medium flex-1">..</span>
                    <span className="text-xs text-slate-500">(Go up)</span>
                  </button>
                </li>
              )}
              
              {directories.length === 0 ? (
                <li className="px-4 py-3 text-xs text-slate-400">
                  <div className="text-center text-slate-500 mb-2">
                    {value === '/' ? 'Select an allowed root directory:' : 'No subdirectories found in this path'}
                  </div>
                  <div className="flex flex-wrap gap-1.5 justify-center">
                    {ALLOWED_ROOT_PRESETS.map((root) => (
                      <button
                        key={root}
                        type="button"
                        onClick={() => handleSelectRoot(root)}
                        className="px-2.5 py-1 rounded-lg bg-white/[0.05] hover:bg-indigo-500/20 border border-white/[0.08] hover:border-indigo-500/40 text-slate-300 hover:text-indigo-200 font-mono text-[11px] transition-colors"
                      >
                        {root}
                      </button>
                    ))}
                  </div>
                </li>
              ) : (
                directories.map((dir) => (
                  <li key={dir}>
                    <button
                      type="button"
                      onClick={() => handleSelectDir(dir)}
                      className="w-full min-h-[44px] obs-touch-target-standard text-left px-4 py-2 text-xs text-slate-300 hover:bg-white/[0.06] hover:text-white flex items-center transition-colors group"
                    >
                      <Folder size={14} className="mr-2 text-indigo-400/80 group-hover:text-indigo-400 transition-colors" />
                      <span className="truncate flex-1">{dir}</span>
                      <ChevronRight size={12} className="text-slate-500 obs-touch-action-reveal opacity-60 md:opacity-0 md:group-hover:opacity-100 transition-opacity" />
                    </button>
                  </li>
                ))
              )}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
