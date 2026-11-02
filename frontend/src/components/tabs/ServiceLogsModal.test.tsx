import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import useSWR from 'swr';
import ServiceLogsModal from './ServiceLogsModal';

jest.mock('swr', () => ({
    __esModule: true,
    default: jest.fn(),
}));

jest.mock('@/contexts/ToastContext', () => ({
    useToast: () => ({ addToast: jest.fn() }),
}));

const mockUseSWR = useSWR as jest.Mock;

describe('ServiceLogsModal', () => {
    beforeEach(() => {
        Element.prototype.scrollIntoView = jest.fn();
        mockUseSWR.mockReset();
        mockUseSWR.mockImplementation((key: string | null) => ({
            data: {
                logs: [{ message: `log line for ${key}` }],
            },
            error: undefined,
            isLoading: false,
            mutate: jest.fn(),
        }));
    });

    it('exposes unit selection tabs when multiple units are provided and switches log query target', () => {
        render(
            <ServiceLogsModal
                onClose={jest.fn()}
                serviceName="wireguard"
                units={['wg-quick@wg0.service', 'wg-dashboard.service']}
            />
        );

        expect(mockUseSWR).toHaveBeenCalledWith(
            '/api/v1/admin/logs?unit=wg-quick%40wg0.service',
            expect.any(Object)
        );

        const secondTab = screen.getByRole('tab', { name: 'wg-dashboard.service' });
        fireEvent.click(secondTab);

        expect(mockUseSWR).toHaveBeenLastCalledWith(
            '/api/v1/admin/logs?unit=wg-dashboard.service',
            expect.any(Object)
        );
    });
});
