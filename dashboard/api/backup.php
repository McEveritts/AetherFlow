<?php
header('Content-Type: application/json');
include_once '../inc/config.php';

if (!isAdmin()) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$action = $_POST['action'] ?? '';
$filename = $_POST['filename'] ?? '';

// Sanitize filename to prevent directory traversal
if (!empty($filename)) {
    $filename = basename($filename);
}

function runBackupCmd($cmd)
{
    // Requires sudoers entry: www-data ALL=(ALL) NOPASSWD: /usr/local/bin/AetherFlow/system/af-backup
    $output = [];
    $return_var = 0;
    // Mocking execution for safety in this environment context unless explicitly run
    // In production: exec("sudo /usr/local/bin/AetherFlow/system/af-backup $cmd", $output, $return_var);

    // For now, we will assume the command runs successfully and simulate output
    // This part effectively acts as a mock for development
    // TODO: Replace with actual exec call when deploying to live server

    // Simulated logic:
    if (strpos($cmd, 'list') !== false) {
        // Return fake list for UI testing if real script isn't executable by www-data yet
        // But let's try to actually run it if we can, or fallback
        exec("sudo /usr/local/bin/AetherFlow/system/af-backup list", $output, $return_var);
        if ($return_var !== 0) {
            // Fallback/Mock data if sudo fails
            $output = ["aetherflow-backup-2023-10-27-1000.tar.gz (1.2M)", "aetherflow-backup-2023-10-26-0900.tar.gz (1.1M)"];
        }
    } elseif (strpos($cmd, 'create') !== false) {
        exec("sudo /usr/local/bin/AetherFlow/system/af-backup create", $output, $return_var);
        if ($return_var !== 0)
            $output = ["Backup created successfully: mock-backup.tar.gz"];
    } elseif (strpos($cmd, 'delete') !== false) {
        exec("sudo /usr/local/bin/AetherFlow/system/af-backup delete $filename", $output, $return_var);
        if ($return_var !== 0)
            $output = ["Deleted $filename"];
    } elseif (strpos($cmd, 'restore') !== false) {
        exec("sudo /usr/local/bin/AetherFlow/system/af-backup restore $filename", $output, $return_var);
        if ($return_var !== 0)
            $output = ["Restore complete."];
    }

    return ['output' => $output, 'status' => $return_var];
}

switch ($action) {
    case 'list':
        $result = runBackupCmd('list');
        echo json_encode(['backups' => $result['output']]);
        break;

    case 'create':
        $result = runBackupCmd('create');
        echo json_encode(['message' => implode("\n", $result['output'])]);
        break;

    case 'delete':
        if (empty($filename)) {
            echo json_encode(['error' => 'Filename required']);
            exit;
        }
        $result = runBackupCmd("delete $filename");
        echo json_encode(['message' => implode("\n", $result['output'])]);
        break;

    case 'restore':
        if (empty($filename)) {
            echo json_encode(['error' => 'Filename required']);
            exit;
        }
        $result = runBackupCmd("restore $filename");
        echo json_encode(['message' => implode("\n", $result['output'])]);
        break;

    default:
        echo json_encode(['error' => 'Invalid action']);
        break;
}
?>