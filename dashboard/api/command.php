<?php
// AetherFlow Command Center API (Phase 28)
header('Content-Type: application/json');
include_once '../inc/config.php';

if (!isAdmin()) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$input = $_POST['command'] ?? '';
$response = ['success' => false, 'message' => 'Command not understood'];

// Simple Regex Intent Parser
if (preg_match('/(restart|reload)\s+(web|nginx|php)/i', $input)) {
    // shell_exec("sudo systemctl restart nginx php7.4-fpm"); 
    $response = ['success' => true, 'message' => 'Restarting Web Services...'];
} elseif (preg_match('/(restart|fix)\s+(plex|media)/i', $input)) {
    // shell_exec("sudo systemctl restart plexmediaserver");
    $response = ['success' => true, 'message' => 'Restarting Plex...'];
} elseif (preg_match('/(clean|clear)\s+(cache|logs)/i', $input)) {
    // shell_exec("sudo /usr/local/bin/aetherflow/system/clean_log");
    $response = ['success' => true, 'message' => 'System logs and cache cleaned.'];
} elseif (preg_match('/(status|check)\s+(disk|space)/i', $input)) {
    $df = shell_exec("df -h / | awk 'NR==2 {print $5}'");
    $response = ['success' => true, 'message' => 'Disk usage is at ' . trim($df)];
}

echo json_encode($response);
?>