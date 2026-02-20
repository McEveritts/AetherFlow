<?php

$username = $_SESSION['user'] ?? '';

require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/SystemInterface.php');
function processExists($processName, $username) {
  $sys = \AetherFlow\Inc\SystemInterface::getInstance();
  return $sys->is_process_running($processName, $username);
}

$Tautulli = processExists("Tautulli",Tautulli);

if ($Tautulli == "1") { $ppval = "<span class=\"badge badge-service-running-dot\"></span><span class=\"badge badge-service-running-pulse\"></span>";
} else { $ppval = "<span class=\"badge badge-service-disabled-dot\"></span><span class=\"badge badge-service-disabled-pulse\"></span>";
}

echo "$ppval";

?>
