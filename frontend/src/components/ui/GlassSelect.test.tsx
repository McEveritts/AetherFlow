import React from 'react';
import { render, screen, fireEvent, within, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Modal } from './Modal';
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

function makeRectangle(topCoordinate: number, bottomCoordinate: number): DOMRect {
    const rectangleObject = {
        top: topCoordinate,
        bottom: bottomCoordinate,
        left: 16,
        right: 186,
        width: 170,
        height: bottomCoordinate - topCoordinate,
        ['x']: 16,
        ['y']: topCoordinate,
        toJSON: () => ({}),
    };
    return rectangleObject as unknown as DOMRect;
}

describe('GlassSelect', () => {
    afterEach(() => {
        jest.restoreAllMocks();
    });

    it('renders selected option with badge and opens listbox with Stable and Nightly only', () => {
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
        expect(screen.queryByText('Beta')).not.toBeInTheDocument();
        expect(screen.getByText('Nightly')).toBeInTheDocument();
        expect(screen.getByText('Unstable')).toBeInTheDocument();
        expect(screen.queryByText('Experimental')).not.toBeInTheDocument();

        fireEvent.click(options[1]);
        expect(handleChange).toHaveBeenCalledWith('nightly');
        expect(trigger).toHaveAttribute('aria-expanded', 'false');
    });

    it('flips above the trigger near mobile dock and caps maxHeight', () => {
        const handleChange = jest.fn();
        jest.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
            if (this.tagName === 'HEADER') return makeRectangle(0, 64);
            if (this.tagName === 'NAV') return makeRectangle(780, 844);
            return makeRectangle(642, 686);
        });
        jest.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockReturnValue(108);

        render(
            <div>
                <header />
                <nav aria-label="Mobile Bottom Navigation" />
                <GlassSelect
                    value="stable"
                    onChange={handleChange}
                    options={CHANNEL_OPTIONS}
                    ariaLabel="Update Channel"
                />
            </div>
        );

        const trigger = screen.getByRole('button', { name: 'Update Channel' });
        fireEvent.click(trigger);

        const listbox = screen.getByRole('listbox', { name: 'Update Channel' });
        expect(listbox).toHaveAttribute('data-placement', 'top');
        expect(listbox).toHaveClass('fixed');
        expect(listbox.style.maxHeight).toBe('288px');
        expect(listbox).toHaveStyle({ top: '524px', left: '16px', width: '280px' });

        screen.getByRole('navigation').getBoundingClientRect = () => makeRectangle(900, 964);
        jest.replaceProperty(window, 'innerHeight', 964);
        fireEvent(window, new Event('resize'));

        expect(listbox).toHaveAttribute('data-placement', 'bottom');
        expect(listbox.style.maxHeight).toBe('198px');
        expect(listbox).toHaveStyle({ top: '694px' });
    });

    it('gives narrow triggers a readable menu and clamps the menu to the viewport', () => {
        jest.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(() => makeRectangle(100, 144));
        jest.spyOn(document.documentElement, 'clientWidth', 'get').mockReturnValue(240);
        render(<GlassSelect value="stable" onChange={jest.fn()} options={CHANNEL_OPTIONS} ariaLabel="Update Channel" />);

        fireEvent.click(screen.getByRole('button', { name: 'Update Channel' }));
        const listbox = screen.getByRole('listbox', { name: 'Update Channel' });
        expect(listbox).toHaveStyle({ left: '8px', width: '224px' });
        expect(listbox).toHaveClass('obs-select-listbox');
        expect(within(listbox).getByText('2 options · ↕')).toBeInTheDocument();
        expect(within(listbox).getAllByRole('option')).toHaveLength(2);
    });

    it('covers the full scrollport width with a non-negative sticky header inset', () => {
        render(<GlassSelect value="stable" onChange={jest.fn()} options={CHANNEL_OPTIONS} ariaLabel="Update Channel" />);
        fireEvent.click(screen.getByRole('button', { name: 'Update Channel' }));
        const listbox = screen.getByRole('listbox', { name: 'Update Channel' });
        const header = within(listbox).getByText('2 options · ↕').parentElement;
        expect(header).toHaveClass('sticky', '-top-1.5', '-mx-1.5', '-mt-1.5');
        expect(header).not.toHaveClass('top-0');
    });

    it('remeasures an upward menu after a narrower committed width wraps its options', () => {
        let viewportWidth = 640;
        jest.spyOn(document.documentElement, 'clientWidth', 'get').mockImplementation(() => viewportWidth);
        jest.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
            if (this.tagName === 'HEADER') return makeRectangle(0, 64);
            if (this.tagName === 'NAV') return makeRectangle(780, 844);
            return { ...makeRectangle(642, 686), width: viewportWidth < 400 ? 170 : 500 } as DOMRect;
        });
        jest.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockImplementation(function (this: HTMLElement) {
            return this.getAttribute('role') === 'listbox' && this.style.width === '280px' ? 260 : 120;
        });
        render(
            <div>
                <header />
                <nav aria-label="Mobile Bottom Navigation" />
                <GlassSelect value="stable" onChange={jest.fn()} options={CHANNEL_OPTIONS} ariaLabel="Update Channel" />
            </div>
        );
        fireEvent.click(screen.getByRole('button', { name: 'Update Channel' }));
        const listbox = screen.getByRole('listbox', { name: 'Update Channel' });
        expect(listbox).toHaveAttribute('data-placement', 'top');
        expect(listbox).toHaveStyle({ width: '500px', top: '512px' });
        viewportWidth = 320;
        fireEvent(window, new Event('resize'));
        expect(listbox).toHaveAttribute('data-placement', 'top');
        expect(listbox).toHaveStyle({ width: '280px', top: '372px' });
    });

    it('portals above local stacking contexts and keeps option pointer activation inside', () => {
        const handleChange = jest.fn();
        const { container } = render(
            <div style={{ position: 'relative', zIndex: 10 }}>
                <GlassSelect value="stable" onChange={handleChange} options={CHANNEL_OPTIONS} ariaLabel="Update Channel" />
            </div>
        );
        const trigger = screen.getByRole('button', { name: 'Update Channel' });
        fireEvent.click(trigger);
        const listbox = screen.getByRole('listbox', { name: 'Update Channel' });
        expect(container.contains(listbox)).toBe(false);
        expect(listbox.parentElement).toBe(document.body);
        expect(trigger).toHaveAttribute('aria-controls', listbox.id);
        const nightlyOption = within(listbox).getByRole('option', { name: /Nightly/ });
        fireEvent.pointerDown(nightlyOption);
        expect(listbox).toBeInTheDocument();
        fireEvent.click(nightlyOption);
        expect(handleChange).toHaveBeenCalledWith('nightly');
        expect(trigger).toHaveFocus();
    });

    it('keeps portaled options in the modal focus boundary and Escape dismisses only the select', async () => {
        const handleClose = jest.fn();
        const user = userEvent.setup();
        render(
            <Modal isOpen onClose={handleClose} title="Preferences">
                <GlassSelect value="stable" onChange={jest.fn()} options={CHANNEL_OPTIONS} ariaLabel="Update Channel" />
                <button type="button">After select</button>
            </Modal>
        );
        const trigger = screen.getByRole('button', { name: 'Update Channel' });
        await user.click(trigger);
        const listbox = screen.getByRole('listbox');
        const boundary = screen.getByRole('dialog').closest('[data-overlay-boundary]');
        expect(listbox.parentElement).toBe(boundary);
        expect(within(listbox).getByRole('option', { name: /Stable/ })).toHaveFocus();
        await user.keyboard('{Escape}');
        expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
        expect(handleClose).not.toHaveBeenCalled();
        expect(trigger).toHaveFocus();
        await user.click(trigger);
        const activeOption = within(screen.getByRole('listbox')).getByRole('option', { name: /Stable/ });
        expect(fireEvent.keyDown(activeOption, { key: 'Tab' })).toBe(true);
        expect(trigger).toHaveFocus();
        await user.tab();
        expect(screen.getByRole('button', { name: 'After select' })).toHaveFocus();
        expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    });

    it('supports arrow navigation and Home/End without selecting until Enter activation', () => {
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
        trigger.focus();

        fireEvent.keyDown(trigger, { key: 'ArrowDown' });
        expect(trigger).toHaveAttribute('aria-expanded', 'true');
        expect(handleChange).not.toHaveBeenCalled();

        const options = screen.getAllByRole('option');
        expect(options[0]).toHaveFocus();

        fireEvent.keyDown(options[0], { key: 'ArrowDown' });
        expect(options[1]).toHaveFocus();
        expect(handleChange).not.toHaveBeenCalled();

        fireEvent.keyDown(options[1], { key: 'ArrowDown' });
        expect(options[0]).toHaveFocus();
        expect(handleChange).not.toHaveBeenCalled();

        fireEvent.keyDown(options[0], { key: 'ArrowUp' });
        expect(options[1]).toHaveFocus();
        expect(handleChange).not.toHaveBeenCalled();

        fireEvent.keyDown(options[1], { key: 'Home' });
        expect(options[0]).toHaveFocus();
        expect(handleChange).not.toHaveBeenCalled();

        fireEvent.keyDown(options[0], { key: 'End' });
        expect(options[1]).toHaveFocus();
        expect(handleChange).not.toHaveBeenCalled();

        fireEvent.keyDown(options[1], { key: 'Enter' });
        expect(handleChange).toHaveBeenCalledWith('nightly');
        expect(trigger).toHaveAttribute('aria-expanded', 'false');
    });

    it('retains enabled option focus when the option set changes while open', () => {
        const { rerender } = render(<GlassSelect value="stable" onChange={jest.fn()} options={CHANNEL_OPTIONS} ariaLabel="Update Channel" />);
        fireEvent.click(screen.getByRole('button', { name: 'Update Channel' }));
        const nightly = screen.getByRole('option', { name: /Nightly/ });
        fireEvent.keyDown(screen.getByRole('option', { name: /Stable/ }), { key: 'ArrowDown' });
        expect(nightly).toHaveFocus();
        rerender(<GlassSelect value="stable" onChange={jest.fn()} options={[CHANNEL_OPTIONS[0]]} ariaLabel="Update Channel" />);
        expect(screen.getByRole('option', { name: /Stable/ })).toHaveFocus();
        rerender(<GlassSelect value="stable" onChange={jest.fn()} options={[{ ...CHANNEL_OPTIONS[0], disabled: true }]} ariaLabel="Update Channel" />);
        expect(screen.getByRole('listbox')).toHaveFocus();
    });

    it('closes and restores focus to trigger on Escape', () => {
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
        fireEvent.click(trigger);
        expect(trigger).toHaveAttribute('aria-expanded', 'true');

        const options = screen.getAllByRole('option');
        expect(options[0]).toHaveFocus();

        fireEvent.keyDown(options[0], { key: 'Escape' });
        expect(trigger).toHaveAttribute('aria-expanded', 'false');
        expect(trigger).toHaveFocus();
        expect(handleChange).not.toHaveBeenCalled();
    });

    it('attaches scroll and resize listeners when open and cleans them up when closed', () => {
        const addEventListenerSpy = jest.spyOn(window, 'addEventListener');
        const removeEventListenerSpy = jest.spyOn(window, 'removeEventListener');

        const { unmount } = render(
            <GlassSelect
                value="stable"
                onChange={jest.fn()}
                options={CHANNEL_OPTIONS}
                ariaLabel="Update Channel"
            />
        );

        const trigger = screen.getByRole('button', { name: 'Update Channel' });
        fireEvent.click(trigger);

        expect(addEventListenerSpy).toHaveBeenCalledWith('resize', expect.any(Function));
        expect(addEventListenerSpy).toHaveBeenCalledWith('scroll', expect.any(Function), true);

        fireEvent.keyDown(screen.getAllByRole('option')[0], { key: 'Escape' });

        expect(removeEventListenerSpy).toHaveBeenCalledWith('resize', expect.any(Function));
        expect(removeEventListenerSpy).toHaveBeenCalledWith('scroll', expect.any(Function), true);

        unmount();
    });

    it('honors select-level disabled prop and option-level disabled state', () => {
        const handleChange = jest.fn();
        const optionsWithDisabled: GlassSelectOption[] = [
            {
                value: 'stable',
                label: 'Stable',
            },
            {
                value: 'beta',
                label: 'Beta',
                disabled: true,
            },
            {
                value: 'nightly',
                label: 'Nightly',
            },
        ];

        const { rerender } = render(
            <GlassSelect
                value="stable"
                onChange={handleChange}
                options={optionsWithDisabled}
                ariaLabel="Update Channel"
                disabled={true}
            />
        );

        const disabledTrigger = screen.getByRole('button', { name: 'Update Channel' });
        expect(disabledTrigger).toBeDisabled();

        fireEvent.click(disabledTrigger);
        expect(disabledTrigger).toHaveAttribute('aria-expanded', 'false');

        fireEvent.keyDown(disabledTrigger, { key: 'ArrowDown' });
        expect(disabledTrigger).toHaveAttribute('aria-expanded', 'false');

        rerender(
            <GlassSelect
                value="stable"
                onChange={handleChange}
                options={optionsWithDisabled}
                ariaLabel="Update Channel"
                disabled={false}
            />
        );

        const enabledTrigger = screen.getByRole('button', { name: 'Update Channel' });
        fireEvent.click(enabledTrigger);

        const options = screen.getAllByRole('option');
        expect(options[1]).toBeDisabled();

        fireEvent.click(options[1]);
        expect(handleChange).not.toHaveBeenCalled();

        expect(options[0]).toHaveFocus();
        fireEvent.keyDown(options[0], { key: 'ArrowDown' });
        expect(options[2]).toHaveFocus();
    });

    it('dismisses an all-disabled modal listbox from its trigger without closing the modal', () => {
        const handleClose = jest.fn();
        render(
            <Modal isOpen onClose={handleClose} title="Preferences">
                <GlassSelect value="stable" onChange={jest.fn()} options={CHANNEL_OPTIONS.map(option => ({ ...option, disabled: true }))} ariaLabel="Update Channel" />
            </Modal>
        );
        const trigger = screen.getByRole('button', { name: 'Update Channel' });
        fireEvent.click(trigger);
        trigger.focus();
        fireEvent.keyDown(trigger, { key: 'Escape' });
        expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
        expect(handleClose).not.toHaveBeenCalled();
        expect(trigger).toHaveFocus();
    });

    it('dismisses listbox on Tab without preventing default navigation', () => {
        render(
            <GlassSelect
                value="stable"
                onChange={jest.fn()}
                options={CHANNEL_OPTIONS}
                ariaLabel="Update Channel"
            />
        );

        const trigger = screen.getByRole('button', { name: 'Update Channel' });
        fireEvent.click(trigger);
        expect(trigger).toHaveAttribute('aria-expanded', 'true');

        const options = screen.getAllByRole('option');
        const continueNavigation = fireEvent.keyDown(options[0], { key: 'Tab' });

        expect(continueNavigation).toBe(true);
        expect(trigger).toHaveAttribute('aria-expanded', 'false');
        expect(trigger).toHaveFocus();
    });
    it('supports Space invocation on trigger and Space activation on options', () => {
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
        trigger.focus();

        fireEvent.keyDown(trigger, { key: ' ' });
        expect(trigger).toHaveAttribute('aria-expanded', 'true');

        const options = screen.getAllByRole('option');
        expect(options[0]).toHaveFocus();

        fireEvent.keyDown(options[0], { key: 'ArrowDown' });
        expect(options[1]).toHaveFocus();

        fireEvent.keyDown(options[1], { key: ' ' });
        expect(handleChange).toHaveBeenCalledWith('nightly');
        expect(trigger).toHaveAttribute('aria-expanded', 'false');
    });

    it('observes trigger and containing main geometry with ResizeObserver and updates bounds on anchor movement', () => {
        const observedElements: Element[] = [];
        let observerCallback: (() => void) | null = null;
        const disconnectSpy = jest.fn();

        class MockResizeObserver {
            constructor(callback: () => void) {
                observerCallback = callback;
            }
            observe(targetElement: Element) {
                observedElements.push(targetElement);
            }
            unobserve() {}
            disconnect() {
                disconnectSpy();
            }
        }

        const originalResizeObserver = window.ResizeObserver;
        (window as unknown as { ResizeObserver: unknown }).ResizeObserver = MockResizeObserver;

        let mockAnchorRect = makeRectangle(100, 140);
        jest.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
            if (this.tagName === 'HEADER') return makeRectangle(0, 64);
            if (this.tagName === 'NAV') return makeRectangle(780, 844);
            return mockAnchorRect;
        });

        try {
            const { unmount } = render(
                <main data-scroller="main">
                    <GlassSelect
                        value="stable"
                        onChange={jest.fn()}
                        options={CHANNEL_OPTIONS}
                        ariaLabel="Update Channel"
                    />
                </main>
            );

            const trigger = screen.getByRole('button', { name: 'Update Channel' });
            fireEvent.click(trigger);

            const listbox = screen.getByRole('listbox', { name: 'Update Channel' });
            expect(listbox).toBeInTheDocument();
            expect(observedElements).toHaveLength(2);
            expect(observedElements).toContain(trigger);
            expect(observedElements).toContain(trigger.closest('main'));

            mockAnchorRect = {
                ...mockAnchorRect,
                left: 200,
                right: 370,
                x: 200,
            } as DOMRect;

            act(() => {
                observerCallback?.();
            });

            expect(listbox).toHaveStyle({ left: '200px' });

            fireEvent.click(trigger);
            expect(disconnectSpy).toHaveBeenCalled();

            unmount();
        } finally {
            (window as unknown as { ResizeObserver: unknown }).ResizeObserver = originalResizeObserver;
        }
    });
});
