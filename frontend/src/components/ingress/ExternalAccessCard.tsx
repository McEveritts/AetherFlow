import React from 'react';
import { Globe } from 'lucide-react';
import { useIngressStore } from '../../store/useIngressStore';

interface ExternalAccessCardProps {
  appName: string;
}

export function ExternalAccessCard({ appName }: ExternalAccessCardProps) {
  const { configs, updateConfig } = useIngressStore();
  
  // Default structure if undefined in store yet
  const config = configs[appName] || { publicDomain: '', externalAccessEnabled: false };

  // Helper toggle function
  const handleToggle = () => {
    updateConfig(appName, { 
      ...config, 
      externalAccessEnabled: !config.externalAccessEnabled 
    });
  };

  return (
    <div className="bg-white/5 border border-white/10 rounded-xl p-6 shadow-2xl backdrop-blur-sm mt-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-white">External Access</h3>
          <p className="text-sm text-zinc-400">Route public internet traffic securely to this application.</p>
        </div>
        
        {/* Toggle Switch Component */}
        <button 
          type="button"
          onClick={handleToggle}
          className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-600 focus:ring-offset-2 focus:ring-offset-black ${config.externalAccessEnabled ? 'bg-blue-600' : 'bg-zinc-700'}`}
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

      <div className={`transition-all duration-300 ${config.externalAccessEnabled ? 'opacity-100' : 'opacity-50 pointer-events-none'}`}>
        <label className="block text-sm font-medium text-zinc-300 mb-2 mt-4">Public Custom Domain</label>
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Globe className="h-4 w-4 text-zinc-500" />
          </div>
          <input 
            type="text" 
            value={config.publicDomain}
            onChange={(e) => updateConfig(appName, { ...config, publicDomain: e.target.value })}
            placeholder={`${appName}.mydomain.com`}
            className="block w-full pl-10 pr-3 py-2 bg-black/20 border border-white/10 rounded-md text-zinc-100 placeholder-zinc-600 focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition-shadow"
            readOnly={!config.externalAccessEnabled}
          />
        </div>
        <p className="mt-2 text-xs text-zinc-500">
          Auto-SSL generation is handled natively via Let&apos;s Encrypt. Ensure your DNS A-records are pointed strictly to this host IP.
        </p>
      </div>
    </div>
  );
}
