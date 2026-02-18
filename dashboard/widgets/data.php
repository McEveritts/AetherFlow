<?php
$interface = INETFACE;
session_start();
$current_rx = file_get_contents("/sys/class/net/$interface/statistics/rx_bytes");
$current_tx = file_get_contents("/sys/class/net/$interface/statistics/tx_bytes");
$current_time = microtime(true);

if (isset($_SESSION['last_rx']) && isset($_SESSION['last_tx']) && isset($_SESSION['last_time'])) {
    $time_diff = $current_time - $_SESSION['last_time'];
    if ($time_diff > 0) {
        $rbps = ($current_rx - $_SESSION['last_rx']) / $time_diff;
        $tbps = ($current_tx - $_SESSION['last_tx']) / $time_diff;
    } else {
        $rbps = 0;
        $tbps = 0;
    }
} else {
    $rbps = 0;
    $tbps = 0;
}

$_SESSION['last_rx'] = $current_rx;
$_SESSION['last_tx'] = $current_tx;
$_SESSION['last_time'] = $current_time;

$round_rx = round(($rbps * 8) / 10000000, 3);
$round_tx = round(($tbps * 8) / 10000000, 3);

$time = date("U") . "000";
$_SESSION['rx'][] = "[$time, $round_rx]";
$_SESSION['tx'][] = "[$time, $round_tx]";
# to make sure that the graph shows only the
# last minute (saves some bandwitch to)
if (count($_SESSION['rx']) > 60) {
    $x = min(array_keys($_SESSION['rx']));
    unset($_SESSION['rx'][$x]);

    $x2 = min(array_keys($_SESSION['tx']));
    unset($_SESSION['tx'][$x2]);
}

// # json_encode didnt work, if you found a workarround pls write m
//echo json_encode($data, JSON_FORCE_OBJECT);

echo '[ { "data":[' . implode(",", $_SESSION['rx']) . '],"label": "Download"}, ';
echo '{ "data":[' . implode(",", $_SESSION['tx']) . '],"label": "Upload"} ';
echo ']';
?>