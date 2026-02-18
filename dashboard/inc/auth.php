<?php
/**
 * Authentication Middleware
 *
 * Replaces the legacy rutorrent-dependent auth (getUser() / master.txt)
 * with session-based authentication powered by Google OAuth2.
 *
 * Include this file at the top of config.php. It will:
 * - Start/resume the session
 * - Redirect unauthenticated users to login.php
 * - Provide helper functions for user identity and role checks
 *
 * @package AetherFlow\Inc
 */

/**
 * Get the currently logged-in username.
 * Drop-in replacement for the old getUser() from rutorrent.
 *
 * @return string The username of the current user
 */
function getCurrentUser(): string
{
    return $_SESSION['user']['username'] ?? 'unknown';
}

/**
 * Get the current user's database ID.
 *
 * @return int|null The user's database ID, or null if not found
 */
function getCurrentUserId(): ?int
{
    return $_SESSION['user']['id'] ?? null;
}

/**
 * Get the current user's email address.
 *
 * @return string The user's email
 */
function getCurrentUserEmail(): string
{
    return $_SESSION['user']['email'] ?? '';
}

/**
 * Get the current user's avatar URL from Google.
 *
 * @return string URL to the user's Google profile picture
 */
function getCurrentUserAvatar(): string
{
    return $_SESSION['user']['avatar_url'] ?? '';
}

/**
 * Check if the current user has the admin role.
 *
 * @return bool True if the user is an admin
 */
function isAdmin(): bool
{
    return ($_SESSION['user']['role'] ?? 'user') === 'admin';
}

/**
 * Require admin access. Redirects to index if not admin.
 *
 * @return void
 */
function requireAdmin(): void
{
    if (!isAdmin()) {
        header('Location: /');
        exit;
    }
}

/**
 * Check if a user is currently authenticated.
 *
 * @return bool True if user session exists
 */
function isAuthenticated(): bool
{
    return isset($_SESSION['user']) && !empty($_SESSION['user']['id']);
}

/**
 * Enforce authentication.
 * Redirects to login.php if the user is not logged in.
 * Skips redirect for the login page and auth callback to avoid loops.
 *
 * @return void
 */
function requireAuth(): void
{
    $currentPage = basename($_SERVER['PHP_SELF']);
    $publicPages = ['login.php', 'callback.php'];

    if (in_array($currentPage, $publicPages)) {
        return;
    }

    if (!isAuthenticated()) {
        header('Location: /login.php');
        exit;
    }
}

/**
 * Get the stored Google OAuth access token (if available).
 * Useful for making authenticated Gemini API calls.
 *
 * @return string|null The access token, or null if unavailable
 */
function getGoogleAccessToken(): ?string
{
    return $_SESSION['user']['google_access_token'] ?? null;
}
