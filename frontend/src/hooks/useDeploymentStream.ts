import { useState, useEffect } from 'react';

export type DeploymentStreamStatus = 'idle' | 'deploying' | 'success' | 'rollback' | 'error';

export function useDeploymentStream(appName: string, initiateDeployment: boolean) {
  const [logs, setLogs] = useState<string[]>([]);
  const [isDeploying, setIsDeploying] = useState<boolean>(false);
  const [status, setStatus] = useState<DeploymentStreamStatus>('idle');
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!initiateDeployment) {
        return;
    }

    setTimeout(() => {
      setIsDeploying(true);
      setStatus('deploying');
      setError(null);
      setLogs([]);
    }, 0);

    // Connect to authenticated deployment stream
    const eventSource = new EventSource(`/api/v1/auth/deploy/stream?appName=${encodeURIComponent(appName)}`, { withCredentials: true });

    eventSource.onmessage = (event) => {
      const message = typeof event.data === 'string' ? event.data : String(event.data ?? '');
      setLogs((prev) => [...prev, message]);

      // Handle orchestrator terminal signals
      if (message.includes('[ERROR]')) {
        setStatus('error');
        setError(new Error(message));
        eventSource.close();
        setIsDeploying(false);
      } else if (message.includes('[ROLLBACK]')) {
        setStatus('rollback');
        eventSource.close();
        setIsDeploying(false);
      } else if (message.includes('[SUCCESS]')) {
        setStatus('success');
        eventSource.close();
        setIsDeploying(false);
      }
    };

    eventSource.onerror = (err) => {
      console.error('SSE Connection Error:', err);
      setStatus('error');
      setError(new Error('Connection to deployment sequence lost.'));
      eventSource.close();
      setIsDeploying(false);
    };

    // Cleanup hook on dismount
    return () => {
      eventSource.close();
    };
  }, [appName, initiateDeployment]);

  return { logs, isDeploying, status, error };
}
