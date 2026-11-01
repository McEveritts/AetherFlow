import React from 'react';
import { readFileSync } from 'node:fs';
import { render, screen } from '@testing-library/react';
import StreamingTab, { StreamingDashboardData } from '@/components/tabs/StreamingTab';

// Generate with the Rust contract test's AF_STREAMING_CONTRACT_FIXTURE option.
// This separate suite deliberately uses serialized backend output as its input.
const fixturePath = process.env.AF_STREAMING_CONTRACT_FIXTURE;
const fixtures: Record<string, StreamingDashboardData> = fixturePath
    ? JSON.parse(readFileSync(fixturePath, 'utf8'))
    : {};
let mockDashboardData: StreamingDashboardData;

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({ addToast: jest.fn() }),
}));
jest.mock('@/contexts/AuthContext', () => ({
    useAuth: () => ({ user: { id: 1, username: 'admin', role: 'admin' } }),
}));
jest.mock('recharts', () => ({
    ...jest.requireActual('recharts'),
    ResponsiveContainer: ({ children }: { children: React.ReactNode }) => (
        <div style={{ width: 800, height: 300 }}>{children}</div>
    ),
}));
jest.mock('swr', () => jest.fn(() => ({
    data: mockDashboardData,
    error: null,
    isLoading: false,
    mutate: jest.fn(),
})));

const contractTest = fixturePath ? it : it.skip;

contractTest('renders populated history and analytics serialized by Rust', () => {
    mockDashboardData = fixtures.populated;
    expect(mockDashboardData.analytics.recentHistory).toHaveLength(2);
    render(<StreamingTab />);
    expect(screen.getAllByText('Oppenheimer').length).toBeGreaterThan(0);
    expect(screen.getByText('24.5 Mbps')).toBeInTheDocument();
    expect(screen.getByText('8.4 Mbps')).toBeInTheDocument();
});

contractTest('renders the empty Rust dashboard response', () => {
    mockDashboardData = fixtures.empty;
    expect(mockDashboardData.analytics.recentHistory).toHaveLength(0);
    render(<StreamingTab />);
    expect(screen.getByText(/Streaming Dashboard/i)).toBeInTheDocument();
});

contractTest('renders active sessions serialized by Rust', () => {
    mockDashboardData = fixtures.sessions;
    expect(mockDashboardData.activeSessions.length).toBeGreaterThan(0);
    render(<StreamingTab />);
    const firstSession = mockDashboardData.activeSessions[0];
    const title = firstSession.seriesName || firstSession.itemName;
    expect(screen.getAllByText(new RegExp(title, 'i')).length).toBeGreaterThan(0);
});
