<?php

include("../inc/localize.php");

define('HTTP_HOST', preg_replace('~^www\.~i', '', $_SERVER['HTTP_HOST']));

$time_start = microtime_float();

function memory_usage()
{
  $memory = (!function_exists('memory_get_usage')) ? '0' : round(memory_get_usage() / 1024 / 1024, 2) . 'MB';
  return $memory;
}

// Timing
function microtime_float()
{
  $mtime = microtime();
  $mtime = explode(' ', $mtime);
  return $mtime[1] + $mtime[0];
}

use AetherFlow\Inc\SystemInterface;
require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/SystemInterface.php');

$sys = SystemInterface::getInstance();
$load = $sys->get_cpu_usage();

?>

{"cpu":<?php echo "$load"; ?>}