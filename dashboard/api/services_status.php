<?php
// API Endpoint for Dynamic Service Status Polling
// Returns JSON array of service statuses (running & enabled)

header('Content-Type: application/json');

// Prevent HTML output from config.php
ob_start();
require_once('../inc/config.php');
ob_end_clean();

// Check auth (config.php handles this usually, but double check)
if (!isset($username)) {
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$status_data = [];

// $appName is defined in config.php: [['shortname', 'Fancy Name', 'processname'], ...]
// format: [0] => id/name, [1] => Label, [2] => process/service name

foreach ($appName as $app) {
    $service_id = $app[0];       // e.g. 'rtorrent'
    $service_name = $app[2];     // e.g. 'rtorrent' (process name) OR 'libtorrent...'

    // 1. Check if RUNNING (Process check)
    // processExists is defined in config.php
    $is_running = processExists($service_name, $username) ? true : false;

    // Special handling for multi-process apps if needed, but config.php handles most via processExists
    // Some apps in config.php use specific usernames or ports, processExists handles that if logic is consistent.
    // Wait, config.php hardcodes some vars like $rtorrent = processExists(...)
    // I should check if I can just output those variables directly?
    // The variables $rtorrent, $deluged etc are defined in config.php lines 402+.
    // But they are simple booleans (or "1"/"")? processExists returns true/false.
    // Let's rely on calling processExists again or accessing the vars if they are in scope.
    // They are in global scope.

    // Better: use the dynamic check loop to be sure.
    // Does processExists handle the specific args used in config.php lines 402+?
    // config.php calls: $plex = processExists("Plex", 'plex');
    // My loop uses $app[2] as process name and $username as user.
    // I need to handle exceptions where user is different (e.g. plex, debian-transmission, etc).

    // Let's refine the loop to handle specific users if defined in a mapping, 
    // or better yet, look at how config.php maps them.
    // config.php defines variables like $plex, $sonarr etc.
    // I can dynamically access $$service_id if it exists?
    // $service_id for plex is 'plex'. $plex variable exists.
    // $service_id for sonarr is 'sonarr'. $sonarr variable exists.

    // Let's try to capture the variable $$service_id
    // But $appName has 'sonarr' mapped to 'nzbdrone'.
    // The variable name in config.php is $sonarr.
    // So $$service_id should work for most.

    $running = false;
    if (isset(${$service_id}) && ${$service_id} == true) {
        $running = true;
    } else {
        // Fallback or explicit check if variable missing
        // This handles cases where variable name matches service ID
    }

    // 2. Check if ENABLED (Systemd check)
    // Helper function to check systemd status similar to isEnabled but returning bool
    $is_enabled = (
        file_exists('/etc/systemd/system/multi-user.target.wants/' . $service_name . '@' . $username . '.service') ||
        file_exists('/etc/systemd/system/multi-user.target.wants/' . $service_name . '.service') ||
        file_exists('/etc/systemd/system/' . $service_name . '.service') // Sometimes they are just in system
    );

    $status_data[$service_id] = [
        'running' => $running,
        'enabled' => $is_enabled
    ];
}

echo json_encode($status_data);
?>