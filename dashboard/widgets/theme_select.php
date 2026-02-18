<?php
/**
 * Theme Selection Handler (Admin Only)
 *
 * @package AetherFlow\Widgets
 * @author McEveritts <armyworkbs@gmail.com>
 */

if (!isAdmin()) {
        return;
}

$validThemes = ['defaulted', 'smoked', 'glass', 'aetherflow'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['theme_select'])) {
        requireCsrfToken();
        $theme = $_POST['theme_select'];

        if (!in_array($theme, $validThemes, true)) {
                http_response_code(400);
                die('Invalid theme');
        }

        // Set cookie for persistence (30 days)
        setcookie('theme', $theme, time() + (86400 * 30), "/");
        $_SESSION['theme'] = $theme;

        // shell_exec("sudo /usr/local/bin/aetherflow/system/theme/themeSelect-{$theme}");
        header('Location: /');
        exit;
}
?>