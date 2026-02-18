<?php
include_once($_SERVER['DOCUMENT_ROOT'] . '/inc/config.php');

if (!isset($_SESSION['user'])) {
    header('HTTP/1.1 403 Forbidden');
    die("Unauthorized");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    requireCsrfToken();
    global $db, $username;

    if (!isset($db)) {
        die("Database connection unavailable.");
    }

    try {
        // Fetch user_id
        $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user_id = $stmt->fetchColumn();

        if (!$user_id) {
            // Create if missing
            $insert = $db->prepare("INSERT INTO users (username) VALUES (?)");
            $insert->execute([$username]);
            $user_id = $db->lastInsertId();
        }

        // Get all widgets
        $stmt = $db->query("SELECT id, name FROM widgets");
        $all_widgets = $stmt->fetchAll(PDO::FETCH_KEY_PAIR); // id => name

        // POST['widgets'] should be an array of enabled widget names
        $enabled_widgets = $_POST['widgets'] ?? [];

        $db->beginTransaction();

        foreach ($all_widgets as $w_id => $w_name) {
            $is_visible = in_array($w_name, $enabled_widgets) ? 1 : 0;

            // Upsert
            $stmt = $db->prepare("
                INSERT INTO user_widgets (user_id, widget_id, is_visible) 
                VALUES (?, ?, ?)
                ON CONFLICT(user_id, widget_id) DO UPDATE SET is_visible = excluded.is_visible
            ");
            $stmt->execute([$user_id, $w_id, $is_visible]);
        }

        $db->commit();
        header("Location: /profile.php?success=widgets");
        exit;

    } catch (Exception $e) {
        if ($db->inTransaction())
            $db->rollBack();
        die("Error saving preferences: " . $e->getMessage());
    }
} else {
    header("Location: /profile.php");
}
?>