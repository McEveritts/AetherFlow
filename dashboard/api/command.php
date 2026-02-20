<?php
// AetherFlow Command Center API (Phase 28)
header('Content-Type: application/json');
include_once '../inc/config.php';

if (!isAdmin()) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$input = strtolower(trim($_POST['command'] ?? ''));
$response = ['success' => false, 'message' => 'Command not understood'];

$allowedCommands = [
    'restart web' => ['cmd' => "sudo systemctl restart nginx php8.1-fpm", 'msg' => 'Restarting Web Services...'],
    'restart plex' => ['cmd' => "sudo systemctl restart plexmediaserver", 'msg' => 'Restarting Plex...'],
    'clean logs' => ['cmd' => "sudo /usr/local/bin/aetherflow/system/clean_log", 'msg' => 'System logs and cache cleaned.']
];

if (array_key_exists($input, $allowedCommands)) {
    shell_exec($allowedCommands[$input]['cmd']);
    $response = ['success' => true, 'message' => $allowedCommands[$input]['msg']];
} elseif (strpos($input, 'disk space') !== false || strpos($input, 'status disk') !== false) {
    if (PHP_OS === 'Linux') {
        $df = shell_exec("df -h / | awk 'NR==2 {print $5}'") ?? '';
        $response = ['success' => true, 'message' => 'Disk usage is at ' . trim($df)];
    } else {
        $response = ['success' => true, 'message' => 'Disk usage check not supported on this OS.'];
    }
}

echo json_encode($response);
?>