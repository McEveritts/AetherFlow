<?php
include_once($_SERVER['DOCUMENT_ROOT'] . '/inc/config.php');

// Security Check
if (!isset($_SESSION['user'])) {
    header('HTTP/1.1 403 Forbidden');
    die("Unauthorized");
}

// Require admin privileges for viewing service logs
if (!isAdmin()) {
    header('HTTP/1.1 403 Forbidden');
    die(json_encode(['error' => 'Admin access required']));
}

$service = $_GET['service'] ?? '';

// Whitelist or validation
// We can use the 'apps' array from config.php if available, or just check 'processExists'.
// But processExists checks if running. We want logs even if stopped.
// We should have a whitelist of allowed services to prevent `journalctl -u sshd` etc if not desired.
// For now, minimal validation: alphanumeric + dashes.

if (!preg_match('/^[a-zA-Z0-9-]+$/', $service)) {
    die(json_encode(['error' => 'Invalid service name']));
}

// Check if user is master or owns the service?
// Most services are system services (running as user or root).
// Detailed permission check is complex. Assuming logged in user can view logs of dashboard-managed services.
// Ideally, check if service is in our known list.

$known_services = [
    'rtorrent',
    'irssi',
    'deluged',
    'delugeweb',
    'transmission-daemon',
    'qbittorrent-nox',
    'shellinabox',
    'btsync',
    'couchpotato',
    'emby-server',
    'headphones',
    'jackett',
    'lidarr',
    'medusa',
    'nzbget',
    'nzbhydra',
    'ombi',
    'plexmediaserver',
    'tautulli',
    'pyload',
    'radarr',
    'sabnzbdplus',
    'sickgear',
    'sickrage',
    'sonarr',
    'subsonic',
    'syncthing',
    'znc'
];

// Map common names to systemd service names if needed
$service_map = [
    'transmission' => 'transmission-daemon',
    'qbittorrent' => 'qbittorrent-nox',
    'emby' => 'emby-server',
    'plex' => 'plexmediaserver',
    'sabnzbd' => 'sabnzbdplus',
    // Add others as needed
];

$systemd_service = $service_map[$service] ?? $service;

// Append @username for user services if applicable? 
// Most AetherFlow services are `service@username`.
// We should check if we need to append `$username`.

$cmd = "sudo journalctl -u " . escapeshellarg($systemd_service . "@" . $username) . " -n 50 --no-pager";
// Try generic if user specific fails or if it's a system-wide service like nginx (but we probably don't want to show nginx logs).
// Let's try executing.

$output = shell_exec($cmd);

// If empty, maybe it's a global service?
if (trim($output) === "" && in_array($service, ['plex', 'emby'])) { // Example of global/root services
    $cmd = "sudo journalctl -u " . escapeshellarg($systemd_service) . " -n 50 --no-pager";
    $output = shell_exec($cmd);
}

header('Content-Type: application/json');
echo json_encode(['logs' => explode("\n", $output)]);
?>