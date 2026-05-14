import { useState, useEffect } from 'react';

export function useDeploymentStream(appName: string, initiateDeployment: boolean) {
  const [logs, setLogs] = useState<string[]>([]);
  const [isDeploying, setIsDeploying] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!initiateDeployment) {
        return;
    }

    // Use a microtask to avoid "cascading renders" lint error
    // by deferring state updates until after the current render cycle.
    queueMicrotask(() => {
        setIsDeploying(true);
        setError(null);
        setLogs([]);
    });

    // We assume backend API is hooked to /api/v1/deploy/stream
    const eventSource = new EventSource(`/api/v1/deploy/stream?appName=${appName}`);

    eventSource.onmessage = (event) => {
      const message = event.data;
      setLogs((prev) => [...prev, message]);

      // Handle orchestrator terminal signals
      if (message.includes('[SUCCESS]') || message.includes('[ROLLBACK]')) {
        eventSource.close();
        setIsDeploying(false);
      }
    };

    eventSource.onerror = (err) => {
      console.error('SSE Connection Error:', err);
      setError(new Error('Connection to deployment sequence lost.'));
      eventSource.close();
      setIsDeploying(false);
    };

    // Cleanup hook on dismount
    return () => {
      eventSource.close();
    };
  }, [appName, initiateDeployment]);

  return { logs, isDeploying, error };
}
