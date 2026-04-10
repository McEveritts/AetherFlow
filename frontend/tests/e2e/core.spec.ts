import { test, expect } from '@playwright/test';

// Test-Priority Matrix Path: Authentication & Authorization Bounds
test.describe('AetherFlow Auth & Consent Boundary Tests', () => {
    
    test('Unauthenticated user is immediately redirected to login', async ({ page }) => {
        // Clear storage to emulate fresh user
        await page.context().clearCookies();
        
        // Attempt to load the nexus
        await page.goto('/');
        
        // Assert hard redirect to the authentication gate
        await expect(page).toHaveURL(/.*\/login/);
    });

    test('OIDC Consent loops enforce visual scope mapping warnings', async ({ page }) => {
        // Direct jump to a mocked consent flow
        await page.goto('/oauth/consent?client_id=test&redirect_uri=/callback&response_type=code&scope=openid%20profile%20system:reboot');
        
        // Assure the Danger Banner mounts for destructive scopes
        await expect(page.locator('text=system:reboot')).toBeVisible();
        await expect(page.locator('text=CRITICAL')).toBeVisible();
        
        // Ensure "Deny Access" is fundamentally accessible
        const denyBtn = page.locator('button', { hasText: 'Deny Access' });
        await expect(denyBtn).toBeVisible();
        await expect(denyBtn).toBeEnabled();
    });
});

// Test-Priority Matrix Path: Platform Diagnostics
test.describe('AetherFlow Operational Visibility Tests', () => {

    test('Navigating Nexus renders Global Banner hooks', async ({ page }) => {
        // Mount overview (assuming backend mock resolves)
        await page.goto('/');
        
        // Validate Nexus sidebar
        await expect(page.locator('text=AetherFlow')).toBeVisible();
        
        // Check for presence of notification hooks
        await expect(page.locator('header')).toBeVisible();
    });

});
