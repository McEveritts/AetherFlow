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

$validThemes = ['defaulted', 'smoked'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['theme_select'])) {
        requireCsrfToken();
        $theme = $_POST['theme_select'];

        if (!in_array($theme, $validThemes, true)) {
                http_response_code(400);
                die('Invalid theme');
        }

        shell_exec("sudo /usr/local/bin/aetherflow/system/theme/themeSelect-{$theme}");
        header('Location: /');
        exit;
}
?>