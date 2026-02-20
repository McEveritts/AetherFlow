<?php

$username = $_SESSION['user'] ?? '';

require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/SystemInterface.php');
function processExists($processName, $username) {
  $sys = \AetherFlow\Inc\SystemInterface::getInstance();
  return $sys->is_process_running($processName, $username);
}

$sonarr = processExists("nzbdrone",$username);

if ($sonarr == "1") { $sval = "<span class=\"badge badge-service-running-dot\"></span><span class=\"badge badge-service-running-pulse\"></span>";
} else { $sval = "<span class=\"badge badge-service-disabled-dot\"></span><span class=\"badge badge-service-disabled-pulse\"></span>";
}

echo "$sval";

?>