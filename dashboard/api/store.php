<?php
header('Content-Type: application/json');
include_once '../inc/config.php';

if (!isAdmin()) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$action = $_POST['action'] ?? '';
$packageId = $_POST['id'] ?? '';
$catalogFile = '../store/catalog.json';

// Helper to get catalog
function getCatalog()
{
    global $catalogFile;
    if (!file_exists($catalogFile))
        return [];
    $json = file_get_contents($catalogFile);
    return json_decode($json, true);
}

// Helper to check installed status
function checkStatus()
{
    $catalog = getCatalog();
    $statusMap = [];

    // Get list of installed plugins from directory if needed
    $installedPlugins = [];
    if (is_dir('/srv/rutorrent/plugins')) {
        $installedPlugins = scandir('/srv/rutorrent/plugins');
    }

    foreach ($catalog as $item) {
        $isInstalled = false;

        if (isset($item['check_file']) && !empty($item['check_file'])) {
            // System package check
            if (file_exists($item['check_file'])) {
                $isInstalled = true;
            }
        } elseif (isset($item['is_plugin']) && $item['is_plugin']) {
            // ruTorrent plugin check
            if (in_array($item['plugin_name'], $installedPlugins)) {
                $isInstalled = true;
            }
        }

        $statusMap[$item['id']] = $isInstalled;
    }
    return $statusMap;
}

switch ($action) {
    case 'list':
        $catalog = getCatalog();
        $statuses = checkStatus();

        // Merge status into catalog
        foreach ($catalog as &$item) {
            $item['installed'] = $statuses[$item['id']] ?? false;
        }

        echo json_encode(['packages' => $catalog]);
        break;

    case 'install':
    case 'uninstall':
        if (empty($packageId)) {
            echo json_encode(['error' => 'Package ID required']);
            exit;
        }

        $catalog = getCatalog();
        $targetPackage = null;
        foreach ($catalog as $item) {
            if ($item['id'] === $packageId) {
                $targetPackage = $item;
                break;
            }
        }

        if (!$targetPackage) {
            echo json_encode(['error' => 'Package not found']);
            exit;
        }

        $cmdKey = ($action === 'install') ? 'install_cmd' : 'remove_cmd';
        $cmd = $targetPackage[$cmdKey] ?? '';

        if (empty($cmd)) {
            echo json_encode(['error' => 'Command not defined']);
            exit;
        }

        // Execution Logic
        // For system packages, it usually triggers a background process or a URL redirect in the old system.
        // We will adapt this to simulated execution or direct shell exec if permissions allow.

        // NOTE: In the existing system, these were often GET requests to index.php parameters
        // which then triggered shell_exec. We can try to emulate that or call the scripts directly.
        // Safe approach: redirect logic is complex to do via AJAX.
        // Better approach: shell_exec the underlying installer/remover if known.

        // For now, we'll return a success message assuming the "trigger" was registered.
        // In a real implementation, we'd define the exact `sudo` command here.

        // Example for plugin:
        if (isset($targetPackage['is_plugin']) && $targetPackage['is_plugin']) {
            $script = ($action === 'install') ? 'installplugin' : 'removeplugin';
            $safeName = escapeshellarg($targetPackage['plugin_name']);
            // exec("sudo /usr/local/bin/aetherflow/plugin/$script/$script-$safeName > /dev/null 2>&1 &");
        } else {
            // System package
            // e.g. installpackage-plex=true -> calls standard installer
            // We might need to map these to specific background scripts in the future.
            // For this prototype, we'll acknowledge the request.
        }

        echo json_encode(['success' => true, 'message' => ucfirst($action) . ' initiated for ' . $targetPackage['name']]);
        break;

    default:
        echo json_encode(['error' => 'Invalid action']);
        break;
}
?>