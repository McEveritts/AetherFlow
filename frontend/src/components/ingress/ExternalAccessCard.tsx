'use client';

import React, { useEffect, useState } from 'react';
import useSWR from 'swr';
import { Globe, Check } from 'lucide-react';
import { useIngressStore } from '../../store/useIngressStore';

interface ExternalAccessCardProps {
  appName: string;
}

const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export function ExternalAccessCard({ appName }: ExternalAccessCardProps) {
  const { configs, fetchConfigs, updateConfig } = useIngressStore();
  const { data: settingsData } = useSWR<{ baseDomain?: string }>('/api/v1/auth/settings');
  const cleanBaseDomain = (settingsData?.baseDomain || '').trim().replace(/^\*\./, '');
  const suggestedDomain = cleanBaseDomain ? `${appName}.${cleanBaseDomain}` : `${appName}.mydomain.com`;

  const config = configs[appName] || {
    publicDomain: cleanBaseDomain ? `${appName}.${cleanBaseDomain}` : '',
    externalAccessEnabled: Boolean(cleanBaseDomain),
  };
  const [draftDomain, setDraftDomain] = useState<string>(config.publicDomain || '');
  const [validationError, setValidationError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState<boolean>(false);

  useEffect(() => {
    fetchConfigs();
  }, [fetchConfigs]);

  useEffect(() => {
    setDraftDomain(config.publicDomain || (cleanBaseDomain ? `${appName}.${cleanBaseDomain}` : ''));
  }, [config.publicDomain, appName, cleanBaseDomain]);

  const validateDomain = (domain: string, requireNonEmpty: boolean): boolean => {
    const trimmed = domain.trim();
    if (!trimmed) {
      if (requireNonEmpty) {
        setValidationError('Enter a valid public domain before enabling external access.');
        return false;
      }
      setValidationError(null);
      return true;
    }
    if (!DOMAIN_REGEX.test(trimmed)) {
      setValidationError('Please enter a valid domain name (e.g., app.mydomain.com).');
      return false;
    }
    setValidationError(null);
    return true;
  };

  const handleToggle = async () => {
    const nextEnabled = !config.externalAccessEnabled;
    const trimmed = draftDomain.trim();
    if (nextEnabled && !validateDomain(trimmed, true)) {
      return;
    }
    setIsSaving(true);
    try {
      await updateConfig(appName, {
        publicDomain: trimmed,
        externalAccessEnabled: nextEnabled,
      });
    } finally {
      setIsSaving(false);
    }
  };

  const handleSaveDomain = async () => {
    const trimmed = draftDomain.trim();
    if (!validateDomain(trimmed, config.externalAccessEnabled)) {
      return;
    }
    setIsSaving(true);
    try {
      await updateConfig(appName, {
        publicDomain: trimmed,
        externalAccessEnabled: config.externalAccessEnabled,
      });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="glass-card rounded-2xl p-6 shadow-2xl relative overflow-hidden mt-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-white">External Access</h3>
          <p className="text-sm text-zinc-400">Route public internet traffic securely to this application.</p>
        </div>

        {/* Toggle Switch Component */}
        <button
          type="button"
          onClick={handleToggle}
          disabled={isSaving}
          className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-600 focus:ring-offset-2 focus:ring-offset-black disabled:opacity-50 ${config.externalAccessEnabled ? 'bg-blue-600' : 'bg-zinc-700'}`}
          role="switch"
          aria-checked={config.externalAccessEnabled}
        >
          <span className="sr-only">Enable external access</span>
          <span
            aria-hidden="true"
            className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${config.externalAccessEnabled ? 'translate-x-5' : 'translate-x-0'}`}
          />
        </button>
      </div>

      <div className="transition-all duration-300">
        <label className="block text-sm font-medium text-zinc-300 mb-2 mt-4">Public Custom Domain</label>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Globe className="h-4 w-4 text-zinc-500" />
            </div>
            <input
              type="text"
              value={draftDomain}
              onChange={(e) => {
                setDraftDomain(e.target.value);
                if (validationError) setValidationError(null);
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  handleSaveDomain();
                }
              }}
              placeholder={suggestedDomain}
              className="block w-full pl-10 pr-3 py-2 bg-black/20 border border-white/10 rounded-md text-zinc-100 placeholder-zinc-600 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-shadow"
            />
          </div>
          <button
            type="button"
            onClick={handleSaveDomain}
            disabled={isSaving || draftDomain.trim() === (config.publicDomain || '')}
            className="px-3 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-zinc-800 disabled:text-zinc-500 text-white text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5"
          >
            <Check className="h-3.5 w-3.5" />
            Save
          </button>
        </div>
        {validationError && (
          <p className="mt-2 text-xs text-red-400">{validationError}</p>
        )}
        <p className="mt-2 text-xs text-zinc-500">
          Auto-SSL generation is handled natively via Let&apos;s Encrypt. Ensure your DNS A-records are pointed strictly to this host IP.
        </p>
      </div>
    </div>
  );
}
