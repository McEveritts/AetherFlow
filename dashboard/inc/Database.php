<?php
namespace AetherFlow\Inc;

use PDO;
use PDOException;

/**
 * Database Handler
 * 
 * Provides a singleton PDO connection to the AetherFlow SQLite database.
 * Handles user preferences, widget states, and system logs.
 * 
 * @package AetherFlow\Inc
 */
class Database
{
    private static $instance = null;
    private $pdo;
    private $dbPath;

    /**
     * Private constructor to prevent direct instantiation.
     */
    private function __construct()
    {
        $this->dbPath = $_SERVER['DOCUMENT_ROOT'] . '/db/aetherflow.sqlite';

        try {
            // Check if directory exists, if not create it (though /db should exist)
            if (!is_dir(dirname($this->dbPath))) {
                mkdir(dirname($this->dbPath), 0755, true);
            }

            $this->pdo = new PDO('sqlite:' . $this->dbPath);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

            // Create tables if they don't exist
            $this->initializeSchema();

        } catch (PDOException $e) {
            error_log("AetherFlow Database Error: " . $e->getMessage());
            // In production we might not want to die here, but for now it's critical
            throw new \Exception("Database connection failed. Check error logs.");
        }
    }

    /**
     * Get the singleton instance.
     * 
     * @return Database
     */
    public static function getInstance()
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Get the PDO connection.
     * 
     * @return PDO
     */
    public function getConnection()
    {
        return $this->pdo;
    }

    /**
     * Initialize the database schema if needed.
     */
    private function initializeSchema()
    {
        // Check for users table
        $query = "SELECT name FROM sqlite_master WHERE type='table' AND name='users'";
        $result = $this->pdo->query($query)->fetch();

        if (!$result) {
            $this->runSchema();
        }

        // Check for notifications table (migration)
        $query = "SELECT name FROM sqlite_master WHERE type='table' AND name='notifications'";
        $result = $this->pdo->query($query)->fetch();

        if (!$result) {
            $this->pdo->exec("
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
            ");
        }

        // Check for user_settings table (migration)
        $query = "SELECT name FROM sqlite_master WHERE type='table' AND name='user_settings'";
        $result = $this->pdo->query($query)->fetch();

        if (!$result) {
            $this->pdo->exec("
                CREATE TABLE IF NOT EXISTS user_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    setting_key TEXT NOT NULL,
                    setting_value TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id),
                    UNIQUE(user_id, setting_key)
                );
            ");
        }
    }

    private function runSchema()
    {
        $schema = file_get_contents($_SERVER['DOCUMENT_ROOT'] . '/db/schema.sql');
        if ($schema) {
            $statements = explode(';', $schema);
            foreach ($statements as $statement) {
                if (trim($statement)) {
                    $this->pdo->exec($statement);
                }
            }
        }
    }

    /**
     * Prevent cloning.
     */
    private function __clone()
    {
    }

    /**
     * Prevent unserializing.
     */
    public function __wakeup()
    {
    }
}
