<?php
namespace AetherFlow\Inc;

use PDO;

class Notifications
{
    private $pdo;

    public function __construct()
    {
        $this->pdo = Database::getInstance()->getConnection();
    }

    /**
     * Add a new notification
     * 
     * @param int $user_id
     * @param string $type (info, success, warning, error)
     * @param string $message
     * @param string|null $link
     * @return bool
     */
    public function add($user_id, $type, $message, $link = null)
    {
        $stmt = $this->pdo->prepare("INSERT INTO notifications (user_id, type, message, link) VALUES (?, ?, ?, ?)");
        $result = $stmt->execute([$user_id, $type, $message, $link]);

        if ($result) {
            $this->sendWebhookIfConfigured($user_id, $type, $message, $link);
        }

        return $result;
    }

    private function sendWebhookIfConfigured($user_id, $type, $message, $link)
    {
        // Fetch webhook URL
        $stmt = $this->pdo->prepare("SELECT setting_value FROM user_settings WHERE user_id = ? AND setting_key = 'discord_webhook'");
        $stmt->execute([$user_id]);
        $webhookUrl = $stmt->fetchColumn();

        if ($webhookUrl) {
            $color = 3447003; // Blue (Info)
            if ($type === 'success')
                $color = 3066993; // Green
            if ($type === 'warning')
                $color = 16776960; // Yellow
            if ($type === 'error')
                $color = 15158332; // Red

            $payload = json_encode([
                "embeds" => [
                    [
                        "title" => "AetherFlow Notification: " . ucfirst($type),
                        "description" => $message,
                        "color" => $color,
                        "url" => $link ?? "https://aetherflow.io", // Default to site/dashboard if null
                        "timestamp" => date("c")
                    ]
                ]
            ]);

            $ch = curl_init($webhookUrl);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-type: application/json'));
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_exec($ch);
            curl_close($ch);
        }
    }

    /**
     * Get unread notifications for a user
     * 
     * @param int $user_id
     * @param int $limit
     * @return array
     */
    public function getUnread($user_id, $limit = 10)
    {
        $stmt = $this->pdo->prepare("SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY created_at DESC LIMIT ?");
        $stmt->execute([$user_id, $limit]);
        return $stmt->fetchAll();
    }

    /**
     * Get unread count
     * 
     * @param int $user_id
     * @return int
     */
    public function getUnreadCount($user_id)
    {
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
        $stmt->execute([$user_id]);
        return (int) $stmt->fetchColumn();
    }

    /**
     * Mark a notification as read
     * 
     * @param int $id
     * @param int $user_id
     * @return bool
     */
    public function markAsRead($id, $user_id)
    {
        $stmt = $this->pdo->prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?");
        return $stmt->execute([$id, $user_id]);
    }

    /**
     * Mark all notifications as read
     * 
     * @param int $user_id
     * @return bool
     */
    public function markAllAsRead($user_id)
    {
        $stmt = $this->pdo->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ?");
        return $stmt->execute([$user_id]);
    }
}
