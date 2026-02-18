<?php
/**
 * Language Selection Handler (Admin Only)
 *
 * @package AetherFlow\Widgets
 * @author McEveritts <armyworkbs@gmail.com>
 */

if (!isAdmin()) {
        return;
}

$validLanguages = ['lang_de', 'lang_dk', 'lang_en', 'lang_fr', 'lang_es', 'lang_zh'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['lang_select'])) {
        requireCsrfToken();
        $lang = $_POST['lang_select'];

        if (!in_array($lang, $validLanguages, true)) {
                http_response_code(400);
                die('Invalid language');
        }

        shell_exec("sudo /usr/local/bin/aetherflow/system/lang/langSelect-{$lang}");
        header('Location: /');
        exit;
}
?>