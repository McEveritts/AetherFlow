import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import GlassSelect, { type GlassSelectOption } from './GlassSelect';

const CHANNEL_OPTIONS: GlassSelectOption[] = [
    {
        value: 'stable',
        label: 'Stable',
        description: 'Verified production releases with atomic rollback protection',
        badge: 'Recommended',
        badgeVariant: 'emerald',
        dotColor: 'bg-emerald-400',
    },
    {
        value: 'nightly',
        label: 'Nightly',
        description: 'Bleeding-edge builds directly from the nightly branch',
        badge: 'Unstable',
        badgeVariant: 'amber',
        dotColor: 'bg-amber-400',
    },
];

describe('GlassSelect', () => {
    it('renders selected option with badge and opens listbox with only Stable and Nightly', () => {
        const handleChange = jest.fn();
        render(
            <GlassSelect
                value="stable"
                onChange={handleChange}
                options={CHANNEL_OPTIONS}
                ariaLabel="Update Channel"
            />
        );

        const trigger = screen.getByRole('button', { name: 'Update Channel' });
        expect(trigger).toHaveAttribute('aria-expanded', 'false');
        expect(screen.getByText('Stable')).toBeInTheDocument();
        expect(screen.getByText('Recommended')).toBeInTheDocument();

        fireEvent.click(trigger);
        expect(trigger).toHaveAttribute('aria-expanded', 'true');

        const options = screen.getAllByRole('option');
        expect(options).toHaveLength(2);
        expect(screen.queryByText(/Beta/i)).not.toBeInTheDocument();
        expect(screen.getByText('Nightly')).toBeInTheDocument();
        expect(screen.getByText('Unstable')).toBeInTheDocument();

        fireEvent.click(options[1]);
        expect(handleChange).toHaveBeenCalledWith('nightly');
        expect(trigger).toHaveAttribute('aria-expanded', 'false');
    });
});
