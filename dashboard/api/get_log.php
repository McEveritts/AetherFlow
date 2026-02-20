<?php
header('Content-Type: application/json');
require_once('../inc/config.php');

// Security Check
if (!isAdmin()) {
    echo json_encode(['error' => T('ERROR_UNAUTHORIZED')]);
    exit;
}

$service = $_GET['service'] ?? '';
if (empty($service)) {
    echo json_encode(['error' => T('ERROR_NO_SERVICE')]);
    exit;
}

// Find log path from config.php $appName
$logPath = '';
foreach ($appName as $app) {
    // $app = ['short', 'Title', 'process', 'log_path']
    // Service might match short name OR process name? 
    // widgets/service_control.php uses short name in viewLogs('shortname').
    if ($app[0] === $service || $app[2] === $service) {
        $logPath = $app[3] ?? '';
        break;
    }
    // Handle special cases not in appName or slightly different?
    // rtorrent is in appName.
    // deluged vs deluge (short vs process).
}

// Special case for shellinabox/webconsole if needed?
if ($service == 'delugeweb') {
    $logPath = "/home/$username/.config/deluge/web.log";
}

if (empty($logPath)) {
    echo json_encode(['error' => T('ERROR_LOG_PATH_NOT_DEFINED') . ": $service"]);
    exit;
}

// Security: Prevent path traversal if someone injected weird service name
// But we match against $appName, so it's safe-ish.
// $logPath is trusted from config.

// Replace $username variable if literally present in string (though config.php interpolates it)
// config.php uses double quotes: "/home/$username/..." so it IS interpolated at config load time.
// So $logPath already has the correct username.

if (!file_exists($logPath)) {
    echo json_encode(['error' => T('ERROR_LOG_FILE_NOT_FOUND') . ": $logPath"]);
    exit;
}

if (!is_readable($logPath)) {
    echo json_encode(['error' => T('ERROR_LOG_FILE_NOT_READABLE') . ": $logPath"]);
    exit;
}

// Use native OS tail for safety and performance
$safePath = escapeshellarg($logPath);
$output = shell_exec("tail -n 100 $safePath 2>&1");

if ($output === null) {
    echo json_encode(['error' => T('ERROR_OPEN_LOG')]);
    exit;
}

$lines = explode("\n", trim($output));

// Strip ansi codes if any?
// Use array_map utf8_encode just in case
$lines = array_map(function ($l) {
    return trim($l);
}, $lines);

echo json_encode(['logs' => $lines]);