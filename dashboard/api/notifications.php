<?php
require_once __DIR__ . '/../inc/config.php';
use AetherFlow\Inc\Notifications;

header('Content-Type: application/json');

// Ensure user is logged in
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$notifs = new Notifications();
$action = $_REQUEST['action'] ?? 'get';
$user_id = $_SESSION['user_id'];

if ($action === 'get') {
    $unread = $notifs->getUnread($user_id);
    $count = $notifs->getUnreadCount($user_id);
    echo json_encode(['notifications' => $unread, 'count' => $count]);
    exit;
}

// CSRF Check for state-changing actions
require_once __DIR__ . '/../inc/csrf.php';

if ($action === 'mark_read' || $action === 'mark_all_read') {
    requireCsrfToken();
}

if ($action === 'mark_read') {
    $id = $_POST['id'];
    if ($notifs->markAsRead($id, $user_id)) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['error' => 'Failed to mark as read']);
    }
} elseif ($action === 'mark_all_read') {
    if ($notifs->markAllAsRead($user_id)) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['error' => 'Failed to mark all as read']);
    }
} else {
    echo json_encode(['error' => 'Invalid action']);
}
