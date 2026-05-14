import { useState, useEffect } from 'react';

export function useDeploymentStream(appName: string, initiateDeployment: boolean) {
  const [logs, setLogs] = useState<string[]>([]);
  const [isDeploying, setIsDeploying] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!initiateDeployment) {
        return;
    }

    // Move state resetting out of the synchronous part to avoid cascading renders
    setTimeout(() => {
        setIsDeploying(true);
        setError(null);
        setLogs([]);
    }, 0);

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
