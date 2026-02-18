<?php
// AetherFlow Cloud Sync / Settings Export (Phase 30)
header('Content-Type: application/json');
include_once '../inc/config.php';

if (!isAdmin()) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$action = $_GET['action'] ?? '';

if ($action === 'export') {
    $filename = "aetherflow-settings-" . date('Y-m-d') . ".json";

    // Gather settings (Mock)
    $settings = [
        'widgets_order' => ['bandwidth', 'cpu', 'disk'],
        'theme' => 'slate_stone',
        'notifications' => ['quiet_mode' => true]
    ];

    header('Content-Disposition: attachment; filename="' . $filename . '"');
    echo json_encode($settings, JSON_PRETTY_PRINT);
    exit;
} elseif ($action === 'import') {
    // Handle file upload processing here
    echo json_encode(['success' => true, 'message' => 'Settings imported successfully (Simulated).']);
} else {
    echo json_encode(['error' => 'Invalid action']);
}
?>