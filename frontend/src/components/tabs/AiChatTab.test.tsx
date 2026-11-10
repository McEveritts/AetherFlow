import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import useSWR from 'swr';
import AiChatTab from '@/components/tabs/AiChatTab';
import { useSystemStore } from '@/store/useSystemStore';
import { useMetrics } from '@/hooks/useMetrics';
import { apiFetch } from '@/lib/fetcher';

const mockAddToast = jest.fn();
const mockSetActiveTab = jest.fn();
const mockSetActiveSettingsTab = jest.fn();

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({
        addToast: mockAddToast,
        toasts: [],
    }),
}));

jest.mock('@/store/useSystemStore', () => ({
    useSystemStore: () => ({
        setActiveTab: mockSetActiveTab,
        setActiveSettingsTab: mockSetActiveSettingsTab,
    }),
}));

jest.mock('@/hooks/useMetrics', () => ({
    useMetrics: () => ({
        metrics: {
            cpu_usage: 12,
            memory: { used_bytes: 1024, total_bytes: 4096 },
        },
    }),
}));

jest.mock('swr', () => jest.fn());

jest.mock('@/lib/fetcher', () => ({
    apiFetch: jest.fn(),
    fetcher: jest.fn(),
}));

jest.mock('@/components/ui/FlowAiMarkdown', () => {
    return function MockMarkdown({ content }: { content: string }) {
        return <div data-testid="flow-ai-markdown">{content}</div>;
    };
});

const mockedUseSWR = useSWR as jest.Mock;
const mockedApiFetch = apiFetch as jest.Mock;

describe('AiChatTab Embedded Canvas & Conversation Contract', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        mockedUseSWR.mockReturnValue({
            data: {
                ai_provider: 'gemini',
                ai_model: 'gemini-4-argon',
            },
        });
    });

    it('renders architectural top toolbar and suggested prompts', () => {
        render(<AiChatTab />);

        expect(screen.getByText('FlowAI Assistant')).toBeInTheDocument();
        expect(screen.getByText('Suggested Infrastructure Prompts')).toBeInTheDocument();
        expect(screen.getByText('Analyze resource telemetry')).toBeInTheDocument();
        expect(screen.getByText('Check service health')).toBeInTheDocument();
    });

    it('keeps the initial welcome at the top and follows new conversation messages', async () => {
        const scrollHeightGetter = jest.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockReturnValue(1000);
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({ reply: 'Conversation continues here.' }),
        });

        try {
            const { container } = render(<AiChatTab />);
            const conversation = container.querySelector('.custom-scrollbar');

            expect(conversation).not.toBeNull();
            expect(conversation?.scrollTop).toBe(0);

            fireEvent.change(screen.getByLabelText(/Message /i), { target: { value: 'Check my services' } });
            fireEvent.click(screen.getByLabelText('Send message'));

            await screen.findByText('Conversation continues here.');
            expect(conversation?.scrollTop).toBe(1000);
        } finally {
            scrollHeightGetter.mockRestore();
        }
    });

    it('sends user message to /api/v1/auth/ai/chat and displays assistant reply', async () => {
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                reply: 'CPU utilization is healthy across all cores.',
            }),
        });

        render(<AiChatTab />);

        const input = screen.getByLabelText(/Message /i);
        fireEvent.change(input, { target: { value: 'How is CPU load?' } });

        const sendButton = screen.getByLabelText('Send message');
        fireEvent.click(sendButton);

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledWith(
                '/api/v1/auth/ai/chat',
                expect.objectContaining({
                    method: 'POST',
                    body: expect.stringContaining('"message":"How is CPU load?"'),
                })
            );
        });

        await waitFor(() => {
            expect(screen.getByText('CPU utilization is healthy across all cores.')).toBeInTheDocument();
        });
    });

    it('renders system action payload and routes to approval inbox on click', async () => {
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                reply: 'I recommend restarting qbittorrent.',
                proposed_action: {
                    type: 'system_action',
                    title: 'Restart qbittorrent daemon',
                    danger_level: 'warn',
                    description: 'Reclaim socket descriptors',
                    action_id: '42',
                },
            }),
        });

        render(<AiChatTab />);

        const promptChip = screen.getByText('Analyze resource telemetry');
        fireEvent.click(promptChip);

        await waitFor(() => {
            expect(screen.getByText('Restart qbittorrent daemon')).toBeInTheDocument();
        });

        const reviewButton = screen.getByText('Review in Inbox');
        fireEvent.click(reviewButton);

        expect(mockSetActiveTab).toHaveBeenCalledWith('inbox');
        expect(mockAddToast).toHaveBeenCalledWith(
            'Action #42 is waiting in your Approval Inbox.',
            'success'
        );
    });

    it('toggles Support Mode and directs queries to /api/v1/auth/ai/support', async () => {
        mockedApiFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                reply: 'Support diagnostics complete: no anomalies.',
            }),
        });

        render(<AiChatTab />);

        const supportToggle = screen.getByRole('button', { name: /Support Mode/i });
        fireEvent.click(supportToggle);

        expect(screen.getByText('FlowAI Support')).toBeInTheDocument();

        const input = screen.getByLabelText(/Describe the issue/i);
        fireEvent.change(input, { target: { value: 'Investigate dropped connections' } });

        const sendButton = screen.getByLabelText('Send message');
        fireEvent.click(sendButton);

        await waitFor(() => {
            expect(mockedApiFetch).toHaveBeenCalledWith(
                '/api/v1/auth/ai/support',
                expect.objectContaining({
                    method: 'POST',
                    body: expect.stringContaining('"context_mode":"full"'),
                })
            );
        });
    });

    it('renders complete approval warning message allowing wrapping without truncation', () => {
        render(<AiChatTab />);

        const warningParagraph = screen.getByText('FlowAI can make mistakes. Critical actions require sign-off in Approval Inbox.');
        expect(warningParagraph).toBeInTheDocument();
        expect(warningParagraph).not.toHaveClass('truncate');
    });
});
