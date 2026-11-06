import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { SWRConfig } from 'swr';
import ServiceLogsModal from './ServiceLogsModal';
import { apiFetch } from '@/lib/fetcher';

const mockAddToast = jest.fn();
jest.mock('@/contexts/ToastContext', () => ({ useToast: () => ({ addToast: mockAddToast }) }));
jest.mock('@/lib/fetcher', () => ({ apiFetch: jest.fn() }));
jest.mock('@/components/ui/FlowAiMarkdown', () => ({ __esModule: true, default: ({ content }: { content: string }) => <p>{content}</p> }));

const mockApiFetch = apiFetch as jest.MockedFunction<typeof apiFetch>;
const alpha = 'alpha.service';
const beta = 'beta.service';
const lines = (message: string) => ({ logs: [{ message }] });
const deferred = <T,>() => {
    let resolve!: (value: T) => void;
    let reject!: (reason?: unknown) => void;
    const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
};
function mount(fetcher: (key: string) => Promise<ReturnType<typeof lines>>) {
    return render(<SWRConfig value={{ provider: () => new Map(), fetcher, dedupingInterval: 0, shouldRetryOnError: false }}>
        <ServiceLogsModal serviceName={alpha} units={[alpha, beta]} onClose={jest.fn()} />
    </SWRConfig>);
}

beforeEach(() => {
    Element.prototype.scrollIntoView = jest.fn();
    mockApiFetch.mockReset();
    mockAddToast.mockReset();
});

it('keeps previous companion logs out of display, diagnostic prompts and exports while the next unit loads', async () => {
    const pendingBeta = deferred<ReturnType<typeof lines>>();
    const view = mount(async key => key.includes('beta') ? pendingBeta.promise : lines('alpha-only-log'));
    await screen.findByText('alpha-only-log');
    fireEvent.click(screen.getByRole('tab', { name: beta }));
    expect(screen.queryByText('alpha-only-log')).not.toBeInTheDocument();
    expect(screen.getByTitle('Run FlowAI Log Diagnostic')).toBeDisabled();
    expect(screen.getByTitle('Export Matrix')).toBeDisabled();
    await act(async () => { pendingBeta.resolve(lines('beta-only-log')); });
    await screen.findByText('beta-only-log');
    mockApiFetch.mockResolvedValue({ ok: true, json: async () => ({ reply: 'beta-diagnosis' }) } as Response);
    fireEvent.click(screen.getByTitle('Run FlowAI Log Diagnostic'));
    await screen.findByText('beta-diagnosis');
    const prompt = JSON.parse(String(mockApiFetch.mock.calls[0][1]?.body)).message;
    expect(prompt).toContain(beta);
    expect(prompt).toContain('beta-only-log');
    expect(prompt).not.toContain('alpha-only-log');
    view.unmount();
});

it('aborts and discards a diagnosis when switching companions, even if the transport completes late', async () => {
    const pendingDiagnosis = deferred<Response>();
    mockApiFetch.mockReturnValue(pendingDiagnosis.promise);
    const view = mount(async key => lines(key.includes('beta') ? 'beta-log' : 'alpha-log'));
    await screen.findByText('alpha-log');
    fireEvent.click(screen.getByTitle('Run FlowAI Log Diagnostic'));
    expect(mockApiFetch).toHaveBeenCalledTimes(1);
    const signal = mockApiFetch.mock.calls[0][1]?.signal;
    fireEvent.click(screen.getByRole('tab', { name: beta }));
    await screen.findByText('beta-log');
    expect(signal?.aborted).toBe(true);
    await act(async () => { pendingDiagnosis.resolve({ ok: true, json: async () => ({ reply: 'stale-alpha-diagnosis' }) } as Response); });
    expect(screen.queryByText('stale-alpha-diagnosis')).not.toBeInTheDocument();
    expect(screen.getByTitle('Run FlowAI Log Diagnostic')).toBeEnabled();
    expect(mockAddToast).not.toHaveBeenCalled();
    view.unmount();
});

it('does not show a failure from a closed or superseded diagnosis', async () => {
    const pendingDiagnosis = deferred<Response>();
    mockApiFetch.mockReturnValue(pendingDiagnosis.promise);
    const view = mount(async () => lines('ready-log'));
    await screen.findByText('ready-log');
    fireEvent.click(screen.getByTitle('Run FlowAI Log Diagnostic'));
    view.unmount();
    await act(async () => { pendingDiagnosis.reject(new Error('late offline response')); });
    expect(mockAddToast).not.toHaveBeenCalled();
});
