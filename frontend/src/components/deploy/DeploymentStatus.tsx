import React from 'react';
import { Loader2, CheckCircle2, AlertTriangle, AlertCircle } from 'lucide-react';
import { useDeploymentStream } from '../../hooks/useDeploymentStream';

interface DeploymentStatusProps {
  appName: string;
  isTriggered: boolean;
  onDeployComplete?: () => void;
}

export function DeploymentStatus({ appName, isTriggered }: DeploymentStatusProps) {
  const { logs, isDeploying, error } = useDeploymentStream(appName, isTriggered);

  // Derive status
  const hasSuccess = logs.some(log => log.includes('[SUCCESS]'));
  const hasRollback = logs.some(log => log.includes('[ROLLBACK]'));

  if (!isTriggered) return null;

  return (
    <div className="bg-white/5 border border-white/10 rounded-xl p-6 shadow-2xl backdrop-blur-sm mt-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            Deployment Orchestrator
            {isDeploying && <Loader2 className="w-4 h-4 text-blue-500 animate-spin" />}
            {hasSuccess && <CheckCircle2 className="w-4 h-4 text-emerald-500" />}
            {hasRollback && <AlertTriangle className="w-4 h-4 text-orange-500" />}
          </h3>
          <p className="text-sm text-zinc-400">Streaming atomic deployment status.</p>
        </div>
      </div>

      <div className="space-y-2 mt-4 font-mono text-sm">
        {logs.length === 0 && isDeploying && (
          <p className="text-zinc-500 animate-pulse">Initializing pipeline...</p>
        )}
        
        {logs.map((log, i) => {
          // Subtle highlighting mapping dependent on bracket type
          let colorClass = "text-zinc-300";
          if (log.includes("[STEP")) colorClass = "text-blue-400";
          if (log.includes("[SUCCESS]")) colorClass = "text-emerald-400 font-semibold";
          if (log.includes("[ROLLBACK]")) colorClass = "text-orange-400 font-semibold";

          return (
             <div 
               key={i} 
               className={`transition-all duration-300 opacity-100 translate-y-0 ${colorClass}`}
             >
               {log}
             </div>
          );
        })}

        {error && (
          <div className="flex items-center gap-2 text-red-400 mt-2">
            <AlertCircle className="w-4 h-4" />
            <span>{error.message}</span>
          </div>
        )}
      </div>
    </div>
  );
}
