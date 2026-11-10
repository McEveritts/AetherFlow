import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import ResponsiveSummary from './ResponsiveSummary';

it('defers mobile summaries without removing metrics or changing desktop visibility', async () => {
    const user = userEvent.setup();
    render(<ResponsiveSummary label="Directory summary · 4 accounts"><p>Account metrics</p></ResponsiveSummary>);
    const trigger = screen.getByRole('button', { name: 'Directory summary · 4 accounts' });
    const content = document.getElementById(trigger.getAttribute('aria-controls')!);
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(trigger).toHaveClass('md:hidden', 'min-h-[44px]');
    expect(content).toHaveClass('hidden', 'md:block');
    expect(content).toHaveTextContent('Account metrics');
    await user.click(trigger);
    expect(trigger).toHaveAttribute('aria-expanded', 'true');
    expect(content).toHaveClass('block', 'md:block');
    await user.keyboard(' ');
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(content).toHaveClass('hidden', 'md:block');
});

it('keeps multiple summary controls independently associated and expanded', async () => {
    const user = userEvent.setup();
    render(<><ResponsiveSummary label="Directory summary"><p>Directory metrics</p></ResponsiveSummary><ResponsiveSummary label="Storage summary"><p>Storage metrics</p></ResponsiveSummary></>);
    const directory = screen.getByRole('button', { name: 'Directory summary' });
    const storage = screen.getByRole('button', { name: 'Storage summary' });
    expect(directory.getAttribute('aria-controls')).not.toBe(storage.getAttribute('aria-controls'));
    await user.click(storage);
    expect(directory).toHaveAttribute('aria-expanded', 'false');
    expect(storage).toHaveAttribute('aria-expanded', 'true');
});
