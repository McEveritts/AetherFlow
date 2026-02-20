<?php
/**
 * System Data Actions (Admin Only)
 *
 * Handles administrative system operations: clear memory cache,
 * clean logs, and system upgrades.
 *
 * Security:
 *   - Requires admin role
 *   - Requires valid CSRF token
 *   - POST-only requests
 *
 * @package AetherFlow\Widgets
 */

// All actions require admin privileges
if (!isAdmin()) {
        return;
}

require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/SystemInterface.php');
$sys = \AetherFlow\Inc\SystemInterface::getInstance();

// Clean memory cache
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['clean_mem'])) {
        requireCsrfToken();
        $sys->execute_admin_action('sudo /usr/local/bin/aetherflow/system/clean_mem');
        header('Location: /');
        exit;
}

// Clean system logs
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['clean_log'])) {
        requireCsrfToken();
        $sys->execute_admin_action('sudo /usr/local/bin/aetherflow/system/clean_log');
        header('Location: /');
        exit;
}

// System upgrade — disabled, will be replaced with custom release system
// if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['updateAetherFlow'])) {
//     requireCsrfToken();
//     $sys->execute_admin_action('sudo /usr/local/bin/aetherflow/system/af upgrade');
//     header('Location: /');
//     exit;
// }
?>