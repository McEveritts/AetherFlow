<?php
/**
 * Package Management Data Actions (Admin Only)
 *
 * Handles package install/remove operations via system scripts.
 * Reads the valid package list from config/packages.json.
 *
 * Security:
 *   - Requires admin role
 *   - Requires valid CSRF token
 *   - POST-only requests
 *   - Package names validated against packages.json whitelist
 *
 * @package AetherFlow\Widgets
 * @author McEveritts <armyworkbs@gmail.com>
 */

// All actions require admin privileges
if (!isAdmin()) {
        return;
}

// Load valid package names from packages.json
$packagesJson = file_get_contents($_SERVER['DOCUMENT_ROOT'] . '/config/packages.json');
$packagesDef = json_decode($packagesJson, true) ?: [];
$validPackages = array_column($packagesDef, 'name');

// Handle package installation (POST only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['install_package'])) {
        requireCsrfToken();
        $pkg = $_POST['install_package'];

        // Validate against whitelist — never trust user input for shell commands
        if (!in_array($pkg, $validPackages, true)) {
                http_response_code(400);
                die('Invalid package name');
        }

        // Find the install script from packages.json
        $pkgDef = array_values(array_filter($packagesDef, fn($p) => $p['name'] === $pkg));
        if (empty($pkgDef) || empty($pkgDef[0]['installScript'])) {
                http_response_code(400);
                die('Package cannot be installed via web interface');
        }

        $script = basename($pkgDef[0]['installScript']); // Extra safety
        shell_exec("sudo /usr/local/bin/aetherflow/package/install/{$script}");
        header('Location: /');
        exit;
}

// Handle package removal (POST only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['remove_package'])) {
        requireCsrfToken();
        $pkg = $_POST['remove_package'];

        if (!in_array($pkg, $validPackages, true)) {
                http_response_code(400);
                die('Invalid package name');
        }

        $pkgDef = array_values(array_filter($packagesDef, fn($p) => $p['name'] === $pkg));
        if (empty($pkgDef) || empty($pkgDef[0]['removeScript'])) {
                http_response_code(400);
                die('Package cannot be removed via web interface');
        }

        $script = basename($pkgDef[0]['removeScript']);
        shell_exec("sudo /usr/local/bin/aetherflow/package/remove/{$script}");
        header('Location: /');
        exit;
}
?>