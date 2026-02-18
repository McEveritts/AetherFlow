<?php
/**
 * Plugin Management Data Actions (Admin Only)
 *
 * Handles ruTorrent plugin install/remove operations.
 * Requires POST + CSRF + admin privileges.
 *
 * @package AetherFlow\Widgets
 * @author McEveritts <armyworkbs@gmail.com>
 */

if (!isAdmin()) {
        return;
}

$plugins = [
        '_getdir',
        '_noty',
        '_noty2',
        '_task',
        'autodl-irssi',
        'autotools',
        'check_port',
        'chunks',
        'cookies',
        'cpuload',
        'create',
        'data',
        'datadir',
        'diskspace',
        'diskspaceh',
        'edit',
        'erasedata',
        'extratio',
        'extsearch',
        'feeds',
        'filedrop',
        'filemanager',
        'fileshare',
        'fileupload',
        'geoip',
        'history',
        'httprpc',
        'ipad',
        'loginmgr',
        'logoff',
        'lookat',
        'mediainfo',
        'mobile',
        'pausewebui',
        'ratio',
        'ratiocolor',
        'retrackers',
        'rpc',
        'rss',
        'rssurlrewrite',
        'rutracker_check',
        'scheduler',
        'screenshots',
        'seedingtime',
        'show_peers_like_wtorrent',
        'source',
        'spectrogram',
        'stream',
        'theme',
        'throttle',
        'tracklabels',
        'trafic',
        'unpack',
        'xmpp',
];

// Handle plugin installation (POST only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['install_plugin'])) {
        requireCsrfToken();
        $plugin = $_POST['install_plugin'];

        if (!in_array($plugin, $plugins, true)) {
                http_response_code(400);
                die('Invalid plugin name');
        }

        $safePlugin = basename($plugin);
        shell_exec("sudo /usr/local/bin/aetherflow/plugin/install/installplugin-{$safePlugin}");
        header('Location: /');
        exit;
}

// Handle plugin removal (POST only)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['remove_plugin'])) {
        requireCsrfToken();
        $plugin = $_POST['remove_plugin'];

        if (!in_array($plugin, $plugins, true)) {
                http_response_code(400);
                die('Invalid plugin name');
        }

        $safePlugin = basename($plugin);
        shell_exec("sudo /usr/local/bin/aetherflow/plugin/remove/removeplugin-{$safePlugin}");
        header('Location: /');
        exit;
}
?>