import { expect, type Page } from '@playwright/test';

type Attempt = { url: string; outcome: 'pending' | 'aborted' | 'finished' | 'failed' };
type Probe = { attempts: Attempt[]; active: number; maximum: number };


export async function trackReads(page: Page, paths: string[]) {
  await page.addInitScript((paths) => {
    const probes: Record<string, Probe> = {};
    for (const path of paths) probes[path] = { attempts: [], active: 0, maximum: 0 };
    (window as Window & { __customReads?: Record<string, Probe> }).__customReads = probes;
    const originalFetch = window.fetch.bind(window);
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input), location.href);
      const probe = probes[url.pathname];
      if (!probe) return originalFetch(input, init);
      const attempt: Attempt = { url: url.pathname + url.search, outcome: 'pending' };
      probe.attempts.push(attempt);
      probe.active += 1;
      probe.maximum = Math.max(probe.maximum, probe.active);
      const settle = (outcome: Attempt['outcome']) => {
        if (attempt.outcome !== 'pending') return;
        attempt.outcome = outcome;
        probe.active -= 1;
      };
      const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
      if (signal?.aborted) settle('aborted');
      else signal?.addEventListener('abort', () => settle('aborted'), { once: true });
      return originalFetch(input, init).then(response => {
        settle('finished');
        return response;
      }, (error: unknown) => {
        settle('failed');
        throw error;
      });
    };
  }, paths);
}

export async function reads(page: Page, path: string): Promise<Probe> {
  return page.evaluate(path => {
    const probe = (window as Window & { __customReads?: Record<string, Probe> }).__customReads?.[path];
    if (!probe) throw new Error(`Missing read probe for ${path}`);
    return probe;
  }, path);
}

export async function resetSettledReads(page: Page, path: string) {
  await expect.poll(async () => (await reads(page, path)).active).toBe(0);
  await page.evaluate(path => {
    const probe = (window as Window & { __customReads?: Record<string, Probe> }).__customReads?.[path];
    if (!probe || probe.active !== 0) throw new Error(`Read probe is not settled: ${path}`);
    probe.attempts = [];
    probe.maximum = 0;
  }, path);
}
