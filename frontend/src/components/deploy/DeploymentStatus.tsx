import React from 'react';
import { Loader2, CheckCircle2, AlertTriangle, AlertCircle } from 'lucide-react';
import { useDeploymentStream } from '../../hooks/useDeploymentStream';
import { Card } from '@/components/ui/Card';

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
  const hasError = logs.some(log => log.includes('[ERROR]'));

  if (!isTriggered) return null;

  return (
    <Card variant="embedded" className="p-4 sm:p-5 mt-4 border-t border-white/[0.07]" data-testid="deployment-status-card" aria-label="Deployment status">
      <div className="flex items-center justify-between mb-3 min-w-0">
        <div>
          <h3 className="text-sm sm:text-base font-bold text-white flex items-center gap-2">
            Deployment Orchestrator
            {isDeploying && <Loader2 className="w-4 h-4 text-blue-500 animate-spin" />}
            {hasSuccess && <CheckCircle2 className="w-4 h-4 text-emerald-500" />}
            {(hasRollback || hasError) && <AlertTriangle className="w-4 h-4 text-orange-500" />}
          </h3>
          <p className="text-xs text-zinc-400 mt-0.5">Streaming atomic deployment status.</p>
        </div>
      </div>

      <div className="mt-3 font-mono text-xs sm:text-sm bg-black/40 border border-white/[0.06] rounded-xl p-3 sm:p-4 space-y-1.5 min-w-0 max-w-full overflow-x-auto">
        {logs.length === 0 && isDeploying && (
          <p className="text-zinc-500 animate-pulse">Initializing pipeline...</p>
        )}
        
        {logs.map((log, i) => {
          // Subtle highlighting mapping dependent on bracket type
          let colorClass = "text-zinc-300";
          if (log.includes("[STEP")) colorClass = "text-blue-400";
          if (log.includes("[SUCCESS]")) colorClass = "text-emerald-400 font-semibold";
          if (log.includes("[ROLLBACK]")) colorClass = "text-orange-400 font-semibold";
          if (log.includes("[ERROR]")) colorClass = "text-red-400 font-semibold";

          return (
             <div 
               key={i} 
               className={`transition-all duration-300 opacity-100 translate-y-0 ${colorClass} break-all sm:break-normal`}
             >
               {log}
             </div>
          );
        })}

        {error && (
          <div className="flex items-center gap-2 text-red-400 mt-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span className="break-words">{error.message}</span>
          </div>
        )}
      </div>
    </Card>
  );
}
