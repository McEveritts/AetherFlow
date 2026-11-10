import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { ViewportMenu } from './ViewportMenu';

function rectangle(top: number, bottom: number): DOMRect {
    return { top, bottom, left: 16, right: 186, width: 170, height: bottom - top, x: 16, y: top, toJSON: () => ({}) };
}

describe('ViewportMenu', () => {
    afterEach(() => jest.restoreAllMocks());

    it('flips above the trigger instead of covering the fixed mobile dock and repositions on resize', () => {
        jest.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
            if (this.tagName === 'HEADER') return rectangle(0, 64);
            if (this.tagName === 'NAV') return rectangle(780, 844);
            if (this.dataset.anchor === 'true') return rectangle(642, 686);
            return rectangle(692, 800);
        });
        jest.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockReturnValue(108);
        render(
            <>
                <header />
                <nav aria-label="Mobile Bottom Navigation" />
                <div data-anchor="true">
                    <button aria-haspopup="menu">Manage</button>
                    <ViewportMenu role="menu" onDismiss={jest.fn()}>
                        <button role="menuitem">Restart</button>
                        <button role="menuitem">Stop</button>
                    </ViewportMenu>
                </div>
            </>
        );
        const menu = screen.getByRole('menu');
        expect(menu).toHaveClass('bottom-full');
        expect(menu).toHaveStyle({ maxHeight: '570px' });
        screen.getByRole('navigation').getBoundingClientRect = () => rectangle(900, 964);
        jest.replaceProperty(window, 'innerHeight', 964);
        fireEvent(window, new Event('resize'));
        expect(menu).toHaveClass('top-full');
        expect(menu).toHaveStyle({ maxHeight: '206px' });
    });

    it.each([false, true])('dismisses on Tab with shift=%s without trapping or dropping focus', (shiftKey) => {
        const dismiss = jest.fn();
        render(
            <div>
                <button aria-haspopup="menu">Manage</button>
                <ViewportMenu role="menu" onDismiss={dismiss}>
                    <button role="menuitem">Restart</button>
                </ViewportMenu>
            </div>
        );
        const item = screen.getByRole('menuitem');
        item.focus();
        const continuesNavigation = fireEvent.keyDown(item, { key: 'Tab', shiftKey });
        expect(continuesNavigation).toBe(true);
        expect(dismiss).toHaveBeenCalledTimes(1);
        expect(screen.getByRole('button', { name: 'Manage' })).toHaveFocus();
    });

    it('supports neutral initial focus, safe Enter, arrow navigation and Escape return without invoking an action', () => {
        const dismiss = jest.fn();
        const action = jest.fn();
        render(
            <div>
                <button aria-haspopup="menu">Manage</button>
                <ViewportMenu role="menu" onDismiss={dismiss}>
                    <button role="menuitem" onClick={action}>Restart</button>
                    <button role="menuitem" disabled>Unavailable</button>
                    <button role="menuitem" onClick={action}>Stop</button>
                </ViewportMenu>
            </div>
        );
        const menu = screen.getByRole('menu');
        const first = screen.getByRole('menuitem', { name: 'Restart' });
        const last = screen.getByRole('menuitem', { name: 'Stop' });
        expect(menu).toHaveFocus();
        fireEvent.keyDown(menu, { key: 'Enter' });
        expect(action).not.toHaveBeenCalled();
        fireEvent.keyDown(menu, { key: 'ArrowDown' });
        expect(first).toHaveFocus();
        fireEvent.keyDown(first, { key: 'ArrowDown' });
        expect(last).toHaveFocus();
        fireEvent.keyDown(last, { key: 'Home' });
        expect(first).toHaveFocus();
        fireEvent.keyDown(last, { key: 'End' });
        expect(last).toHaveFocus();
        fireEvent.keyDown(last, { key: 'Escape' });
        expect(dismiss).toHaveBeenCalledTimes(1);
        expect(screen.getByRole('button', { name: 'Manage' })).toHaveFocus();
        expect(action).not.toHaveBeenCalled();
    });

    it('supports ArrowUp from neutral focus and respects left alignment', () => {
        const dismiss = jest.fn();
        render(
            <div>
                <button aria-haspopup="menu" aria-controls="bounded-menu">Connection</button>
                <ViewportMenu id="bounded-menu" role="menu" align="left" onDismiss={dismiss}>
                    <button role="menuitem">Endpoint One</button>
                    <button role="menuitem">Endpoint Two</button>
                </ViewportMenu>
            </div>
        );
        const menu = screen.getByRole('menu');
        expect(menu).toHaveClass('left-0');
        expect(menu).toHaveFocus();
        const last = screen.getByRole('menuitem', { name: 'Endpoint Two' });
        fireEvent.keyDown(menu, { key: 'ArrowUp' });
        expect(last).toHaveFocus();
    });

    it('supports opt-in firstItem initial focus when configured', () => {
        render(
            <div>
                <button aria-haspopup="menu">Actions</button>
                <ViewportMenu role="menu" initialFocus="firstItem" onDismiss={jest.fn()}>
                    <button role="menuitem">Direct Action</button>
                </ViewportMenu>
            </div>
        );
        expect(screen.getByRole('menuitem', { name: 'Direct Action' })).toHaveFocus();
    });
});
