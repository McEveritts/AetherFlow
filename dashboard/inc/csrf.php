<?php
/**
 * CSRF Token Protection
 *
 * Provides token generation, validation, and output helpers for
 * protecting state-changing actions against cross-site request forgery.
 *
 * Usage:
 *   - In forms:   echo csrfField();
 *   - In <head>:  echo csrfMeta();  (for AJAX via $.ajaxSetup)
 *   - Validate:   validateCsrfToken($_POST['_csrf_token'] ?? '')
 *
 * @package AetherFlow\Security
 */

/**
 * Generate or retrieve the current session CSRF token.
 *
 * @return string The CSRF token (64-char hex string)
 */
function generateCsrfToken(): string
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if (empty($_SESSION['_csrf_token'])) {
        $_SESSION['_csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['_csrf_token'];
}

/**
 * Validate a CSRF token against the session token.
 *
 * @param string $token The token submitted with the request
 * @return bool True if valid
 */
function validateCsrfToken(string $token): bool
{
    if (empty($token) || empty($_SESSION['_csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['_csrf_token'], $token);
}

/**
 * Validate CSRF or die with 403.
 * Checks both POST body and X-CSRF-Token header (for AJAX).
 */
function requireCsrfToken(): void
{
    $token = $_POST['_csrf_token']
        ?? $_SERVER['HTTP_X_CSRF_TOKEN']
        ?? $_SERVER['X_CSRF_TOKEN']
        ?? '';

    if (!validateCsrfToken($token)) {
        http_response_code(403);
        if (isAjaxRequest()) {
            header('Content-Type: application/json');
            die(json_encode(['error' => 'Invalid or missing CSRF token']));
        }
        die('403 Forbidden — Invalid CSRF token');
    }
}

/**
 * Output a hidden form field with the CSRF token.
 *
 * @return string HTML hidden input
 */
function csrfField(): string
{
    $token = htmlspecialchars(generateCsrfToken(), ENT_QUOTES, 'UTF-8');
    return '<input type="hidden" name="_csrf_token" value="' . $token . '">';
}

/**
 * Output a <meta> tag for use with AJAX requests.
 * JS can read this via: $('meta[name="csrf-token"]').attr('content')
 *
 * @return string HTML meta tag
 */
function csrfMeta(): string
{
    $token = htmlspecialchars(generateCsrfToken(), ENT_QUOTES, 'UTF-8');
    return '<meta name="csrf-token" content="' . $token . '">';
}

/**
 * Check if the current request is an AJAX/XHR request.
 *
 * @return bool
 */
function isAjaxRequest(): bool
{
    return !empty($_SERVER['HTTP_X_REQUESTED_WITH'])
        && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}
