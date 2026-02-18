<?php
require_once __DIR__ . '/../inc/config.php';
use AetherFlow\Inc\Database;

$db = Database::getInstance();
$pdo = $db->getConnection();

echo "Updating database schema...\n";

$query = "
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    type TEXT DEFAULT 'info', -- info, success, warning, error
    message TEXT NOT NULL,
    link TEXT,
    is_read INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
";

try {
    $pdo->exec($query);
    echo "Notifications table created successfully.\n";
} catch (PDOException $e) {
    echo "Error creating table: " . $e->getMessage() . "\n";
}
