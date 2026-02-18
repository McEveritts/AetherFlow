<?php
header('Content-Type: application/json');
require_once('../inc/config.php');
require_once('../widgets/vnstat.php');

// Initialize variables expected by get_vnstat_data
$hour = [];
$day = [];
$month = [];
$top = [];
$summary = [];

// Defaults
$use_label = false; // JSON doesn't need pre-formatted labels usually, frontend can format. But vnstat.php logic might require it.
$vnstat_bin = '/usr/bin/vnstat'; // Config might override
$data_dir = './dumps';

// Get Interface from GET or config
$iface = $_GET['iface'] ?? $interface ?? 'eth0';

// Call the function from widgets/vnstat.php
// It populates global variables $day, $hour, $month, $top, $summary
get_vnstat_data(false); // false for $use_label

$response = [
    'summary' => $summary,
    'hourly' => $hour,
    'daily' => $day,
    'monthly' => $month,
    'top' => $top
];

echo json_encode($response);
