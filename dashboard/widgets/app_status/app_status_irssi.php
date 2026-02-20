<?php

$username = $_SESSION['user'] ?? '';

require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/SystemInterface.php');
function processExists($processName, $username) {
  $sys = \\AetherFlow\\Inc\\SystemInterface::getInstance();
  return $sys->is_process_running($processName, $username);
}

$irssi = processExists("irssi",$username);

if ($irssi == "1") { $ival = "<span class=\"badge badge-service-running-dot\"></span><span class=\"badge badge-service-running-pulse\"></span>";
} else { $ival = "<span class=\"badge badge-service-disabled-dot\"></span><span class=\"badge badge-service-disabled-pulse\"></span>";
}

echo "$ival";

?>