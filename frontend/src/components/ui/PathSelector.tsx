'use client';

import React, { useState, useEffect, useRef } from 'react';
import { Folder, ChevronRight, Loader2, CornerLeftUp } from 'lucide-react';

// Added Props so the parent form can actually use the selected path!
interface PathSelectorProps {
  value: string;
  onChange: (path: string) => void;
}

export default function PathSelector({ value, onChange }: PathSelectorProps) {
  const [isOpen, setIsOpen] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [directories, setDirectories] = useState<string[]>([]);
  
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const fetchDirectories = async (path: string) => {
    if (!path.trim()) return;
    
    setIsLoading(true);
    try {
      const response = await fetch(`/api/fs?path=${encodeURIComponent(path)}`);
      if (response.ok) {
        const data = await response.json();
        setDirectories(data.directories || []);
      } else {
        setDirectories([]); 
      }
    } catch (error) {
      setDirectories([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && value) {
      const timer = setTimeout(() => fetchDirectories(value), 300);
      return () => clearTimeout(timer);
    }
  }, [isOpen, value]);

  const handleToggle = () => {
    setIsOpen(!isOpen);
    if (!isOpen && value) fetchDirectories(value);
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.value); // Report back to parent form
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

    onChange(newPath); // Report back to parent form
  };

  // Prevent users from going "up" beyond the root directory
  const isRoot = value === '/' || (/^[a-zA-Z]:\\[^\\]*$/.test(value) && value.length <= 3);

  return (
    <div className="relative w-full max-w-xl font-sans" ref={dropdownRef}>
      <div className="relative flex items-center">
        <button
          type="button"
          onClick={handleToggle}
          className="absolute left-0 p-3 text-gray-400 hover:text-blue-400 focus:outline-none transition-colors z-10"
        >
          <Folder size={18} className={isOpen ? "text-blue-500" : "text-gray-400"} />
        </button>
        
        <input
          type="text"
          value={value}
          onChange={handleInputChange}
          placeholder="Enter absolute path (e.g. /mnt/media/movies)"
          className="w-full bg-gray-900 border border-gray-700 text-gray-100 placeholder-gray-600 rounded-md py-2.5 pl-10 pr-4 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all shadow-inner"
        />
      </div>

      {isOpen && (
        <div className="absolute z-20 w-full mt-2 bg-gray-900 border border-gray-700 rounded-md shadow-2xl max-h-64 overflow-y-auto scrollbar-thin scrollbar-thumb-gray-600 scrollbar-track-transparent">
          {isLoading ? (
            <div className="flex justify-center items-center py-8 text-gray-400">
              <Loader2 className="animate-spin mr-3" size={20} />
              <span className="text-sm font-medium">Scanning directory...</span>
            </div>
          ) : (
            <ul className="py-2">
              {!isRoot && value.length > 0 && (
                <li>
                  <button
                    onClick={() => handleSelectDir('..')}
                    className="w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-800 hover:text-blue-400 flex items-center transition-colors border-b border-gray-800/50 pb-3 mb-1"
                  >
                    <CornerLeftUp size={16} className="mr-3 text-gray-500" />
                    <span className="font-medium flex-1">..</span>
                    <span className="text-xs text-gray-500">(Go up)</span>
                  </button>
                </li>
              )}
              
              {directories.length === 0 ? (
                <li className="px-4 py-4 text-sm text-gray-500 text-center">
                  No subdirectories found or Access Denied
                </li>
              ) : (
                directories.map((dir) => (
                  <li key={dir}>
                    <button
                      onClick={() => handleSelectDir(dir)}
                      className="w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-800 hover:text-white flex items-center transition-colors group"
                    >
                      <Folder size={16} className="mr-3 text-blue-500/70 group-hover:text-blue-400 transition-colors" />
                      <span className="truncate flex-1">{dir}</span>
                      <ChevronRight size={14} className="text-gray-600 opacity-0 group-hover:opacity-100 transition-opacity" />
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
