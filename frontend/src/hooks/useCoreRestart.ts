import { useCallback, useEffect, useState } from 'react';
import { apiFetch } from '@/lib/fetcher';

export const CORE_RESTART_TIMEOUT_MS = 180000;
interface RestartReceipt { job_unit: string; deadline: number }

export function useCoreRestart(notify: (message: string, type: 'info' | 'success' | 'error') => void) {
    const [restarts, setRestarts] = useState<Map<string, RestartReceipt>>(new Map());
    const trackRestart = useCallback((name: string, receipt: { job_unit?: unknown }) => {
        if (typeof receipt.job_unit !== 'string' || !receipt.job_unit.startsWith('aetherflow-self-update-restart-')) {
            throw new Error('Restart was accepted without a valid receipt identity. Check service logs before retrying.');
        }
        setRestarts(current => new Map(current).set(name, { job_unit: receipt.job_unit as string, deadline: Date.now() + CORE_RESTART_TIMEOUT_MS }));
        notify(`${name}: restart scheduled; waiting for its receipt and API readiness.`, 'info');
    }, [notify]);

    useEffect(() => {
        const cleanups: Array<() => void> = [];
        restarts.forEach((receipt, name) => {
            const controller = new AbortController();
            let pollTimer: ReturnType<typeof setTimeout>;
            let requestTimer: ReturnType<typeof setTimeout> | undefined;
            let currentRequest: AbortController | undefined;
            const finish = (message: string, type: 'success' | 'error') => {
                if (controller.signal.aborted) return;
                controller.abort();
                currentRequest?.abort();
                clearTimeout(pollTimer);
                if (requestTimer) clearTimeout(requestTimer);
                notify(message, type);
                setRestarts(current => {
                    if (current.get(name)?.job_unit !== receipt.job_unit) return current;
                    const next = new Map(current); next.delete(name); return next;
                });
            };
            const deadlineTimer = setTimeout(() => finish(`${name}: restart outcome or readiness could not be confirmed. Check service state and logs before retrying.`, 'error'), Math.max(0, receipt.deadline - Date.now()));
            const request = async (url: string) => {
                currentRequest = new AbortController();
                requestTimer = setTimeout(() => currentRequest?.abort(), 8000);
                try {
                    const response = await apiFetch(url, { signal: currentRequest.signal, cache: 'no-store' });
                    return response.ok ? await response.json() : null;
                }
                finally { if (requestTimer) clearTimeout(requestTimer); }
            };
            const poll = async () => {
                try {
                    const status = await request(`/api/v1/admin/services/restart/status?job_unit=${encodeURIComponent(receipt.job_unit)}`);
                    if (status && !controller.signal.aborted) {
                        if (status.job_unit === receipt.job_unit && status.completed === true) {
                            if (status.success === false && status.status === 'failed') {
                                finish(`${name}: restart failed. ${status.error || 'Check service logs.'}`, 'error');
                                return;
                            }
                            if (status.success === true && status.status === 'succeeded') {
                                const readiness = await request('/api/v1/auth/ready');
                                if (readiness?.service === 'aetherflow-api' && readiness.status === 'ready' && readiness.database === 'ok') {
                                    finish(`${name}: restart completed; service activation and API readiness confirmed.`, 'success');
                                    return;
                                }
                            }
                        }
                    }
                } catch { }
                if (!controller.signal.aborted) pollTimer = setTimeout(() => { void poll(); }, 1500);
            };
            pollTimer = setTimeout(() => { void poll(); }, 2000);
            cleanups.push(() => {
                controller.abort(); currentRequest?.abort(); clearTimeout(pollTimer); clearTimeout(deadlineTimer);
                if (requestTimer) clearTimeout(requestTimer);
            });
        });
        return () => cleanups.forEach(cleanup => cleanup());
    }, [restarts, notify]);

    return { restarts, trackRestart };
}
