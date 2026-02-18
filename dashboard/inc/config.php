<?php
// Load Composer autoloader & environment variables
require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable($_SERVER['DOCUMENT_ROOT']);
$dotenv->safeLoad();

include($_SERVER['DOCUMENT_ROOT'] . '/widgets/class.php');
$version = "v3.0.1";
error_reporting(E_ERROR);

// Auth: start session and load auth middleware
require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/auth.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/csrf.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/Cache.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/localize.php');

// Theme Selection Logic
$theme_options = ['slate_stone', 'glass', 'aetherflow'];
// Check session or cookie for theme, default to 'slate_stone'
$user_theme = $_SESSION['theme'] ?? $_COOKIE['theme'] ?? 'slate_stone';
if (!in_array($user_theme, $theme_options)) {
  $user_theme = 'slate_stone';
}
$theme_css = "skins/{$user_theme}.css";

// Start session with custom timeout (must be before requireAuth)
// Session is started in session_start_timeout() below, so auth check happens after.

// Database Connection
try {
  $db_path = $_SERVER['DOCUMENT_ROOT'] . '/db/aetherflow.sqlite';
  $db = new PDO('sqlite:' . $db_path);
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  // Auto-create tables if DB file is new/empty (naive check)
  if (filesize($db_path) == 0) {
    $schema = file_get_contents($_SERVER['DOCUMENT_ROOT'] . '/db/schema.sql');
    $queries = explode(';', $schema);
    foreach ($queries as $query) {
      $query = trim($query);
      if (!empty($query))
        $db->exec($query);
    }
    // Seed default user if needed, or rely on registration/first login logic
  }
} catch (PDOException $e) {
  error_log("Database Error: " . $e->getMessage());
  // Fallback or exit? For now, continue but features might break.
}

// Network Interface
$interface = 'INETFACE';
$iface_list = array('INETFACE');
$iface_title['INETFACE'] = 'External';
$vnstat_bin = '/usr/bin/vnstat';
$data_dir = './dumps';
$byte_notation = null;

$dconf = '/home/' . $username . '/.config/deluge/web.conf';
if (file_exists($dconf)) {
  $dconf_data = file_get_contents($dconf);
  $dwport = search($dconf_data, '"port": ', ',');
  $dwssl = search($dconf_data, '"https": ', ',');
}

$szconf = '/home/' . $username . '/.sabnzbd/sabnzbd.ini';
if (file_exists($szconf)) {
  $szconf_data = file_get_contents($szconf);
  $szport = search($szconf_data, 'port = ', "\n");
  $szssl = search($szconf_data, 'https_port = ', "\n");
}

$zconf = '/srv/rutorrent/home/db/znc.txt';
if (file_exists($zconf)) {
  $zconf_data = file_get_contents($zconf);
  $zport = search($zconf_data, 'Port = ', "\n");
  $zssl = search($zconf_data, 'SSL = ', "\n");
}


function search($data, $find, $end)
{
  $pos1 = strpos($data, $find) + strlen($find);
  $pos2 = strpos($data, $end, $pos1);
  return substr($data, $pos1, $pos2 - $pos1);
}

define('HTTP_HOST', preg_replace('~^www\.~i', '', $_SERVER['HTTP_HOST']));

$panel = array(
  'name' => 'AetherFlow Seedbox',
  'author' => 'Everyone that contributes to the open AetherFlow project!',
  'robots' => 'noindex, nofollow',
  'title' => 'AetherFlow Dashboard',
  'description' => 'AetherFlow is an open-source seedbox project. Only for personal use.',
  'active_page' => basename($_SERVER['PHP_SELF']),
);

// Gemini AI Configuration (loaded from .env)
// Auth is handled by GeminiAuth.php (Service Account OAuth — no API key needed)
define('GEMINI_MODEL', $_ENV['GEMINI_MODEL'] ?? 'gemini-2.0-flash');

$time_start = microtime_float();

// Timing
// Timing
/**
 * Calculate the current microtime float.
 * Used for measuring script execution time.
 * 
 * @return float
 */
function microtime_float()
{
  $mtime = microtime();
  $mtime = explode(' ', $mtime);
  return $mtime[1] + $mtime[0];
}

//Unit Conversion
/**
 * Format bytes into human-readable strings (KB, MB, GB, TB).
 * 
 * @param int $size Size in bytes
 * @return string Formatted string (e.g. "1.5 GB")
 */
function formatsize($size)
{
  $danwei = array(' B ', ' KB ', ' MB ', ' GB ', ' TB ');
  $allsize = array();
  $i = 0;
  for ($i = 0; $i < 5; $i++) {
    if (floor($size / pow(1024, $i)) == 0) {
      break;
    }
  }
  for ($l = $i - 1; $l >= 0; $l--) {
    $allsize1[$l] = floor($size / pow(1024, $l));
    $allsize[$l] = $allsize1[$l] - $allsize1[$l + 1] * 1024;
  }
  $len = count($allsize);
  $fsize = "";
  for ($j = $len - 1; $j >= 0; $j--) {
    $fsize = $fsize . $allsize[$j] . $danwei[$j];
  }
  return $fsize;
}

/**
 * Retrieve CPU Core usage statistics from /proc/stat.
 * 
 * @return array Array of core usage data
 */
function GetCoreInformation()
{
  $data = file('/proc/stat');
  $cores = array();
  foreach ($data as $line) {
    if (preg_match('/^cpu[0-9]/', $line)) {
      $info = explode(' ', $line);
      $cores[] = array('user' => $info[1], 'nice' => $info[2], 'sys' => $info[3], 'idle' => $info[4], 'iowait' => $info[5], 'irq' => $info[6], 'softirq' => $info[7]);
    }
  }
  return $cores;
}

/**
 * Calculate CPU percentage based on two snapshots of core info.
 * 
 * @param array $stat1 Snapshot 1
 * @param array $stat2 Snapshot 2
 * @return array|void
 */
function GetCpuPercentages($stat1, $stat2)
{
  if (count($stat1) !== count($stat2)) {
    return;
  }
  $cpus = array();
  for ($i = 0, $l = count($stat1); $i < $l; $i++) {
    $dif = array();
    $dif['user'] = $stat2[$i]['user'] - $stat1[$i]['user'];
    $dif['nice'] = $stat2[$i]['nice'] - $stat1[$i]['nice'];
    $dif['sys'] = $stat2[$i]['sys'] - $stat1[$i]['sys'];
    $dif['idle'] = $stat2[$i]['idle'] - $stat1[$i]['idle'];
    $dif['iowait'] = $stat2[$i]['iowait'] - $stat1[$i]['iowait'];
    $dif['irq'] = $stat2[$i]['irq'] - $stat1[$i]['irq'];
    $dif['softirq'] = $stat2[$i]['softirq'] - $stat1[$i]['softirq'];
    $total = array_sum($dif);
    $cpu = array();
    foreach ($dif as $x => $y)
      $cpu[$x] = round($y / $total * 100, 2);
    $cpus['cpu' . $i] = $cpu;
  }
  return $cpus;
}
// $stat1 = GetCoreInformation();
// sleep(1);
// $stat2 = GetCoreInformation();
// $data = GetCpuPercentages($stat1, $stat2);
// $cpu_show = $data['cpu0']['user'] . "%us,  " . $data['cpu0']['idle'] . "%id,  ";

// Information obtained depending on the system CPU
switch (PHP_OS) {
  case "Linux":
    $sysReShow = (false !== ($sysInfo = sys_linux())) ? "show" : "none";
    break;

  case "FreeBSD":
    $sysReShow = (false !== ($sysInfo = sys_freebsd())) ? "show" : "none";
    break;

  default:
    break;
}

//linux system detects
function sys_linux()
{
  // CPU
  if (false === ($str = file("/proc/cpuinfo")))
    return false;
  $str = implode("", $str);
  preg_match_all("/model\s+name\s{0,}\:+\s{0,}([^\:]+)([\r\n]+)/s", $str, $model);
  preg_match_all("/cpu\s+MHz\s{0,}\:+\s{0,}([\d\.]+)[\r\n]+/", $str, $mhz);
  preg_match_all("/cache\s+size\s{0,}\:+\s{0,}([\d\.]+\s{0,}[A-Z]+[\r\n]+)/", $str, $cache);
  if (false !== is_array($model[1])) {
    $res['cpu']['num'] = sizeof($model[1]);

    if ($res['cpu']['num'] == 1)
      $x1 = '';
    else
      $x1 = ' ×' . $res['cpu']['num'];
    $mhz[1][0] = ' <span style="color:#999;font-weight:600">Frequency:</span> ' . $mhz[1][0];
    $cache[1][0] = ' <br /> <span style="color:#999;font-weight:600">Secondary cache:</span> ' . $cache[1][0];
    $res['cpu']['model'][] = '<h4>' . $model[1][0] . '</h4>' . $mhz[1][0] . $cache[1][0] . $x1;
    if (false !== is_array($res['cpu']['model']))
      $res['cpu']['model'] = implode("<br />", $res['cpu']['model']);
    if (false !== is_array($res['cpu']['mhz']))
      $res['cpu']['mhz'] = implode("<br />", $res['cpu']['mhz']);
    if (false !== is_array($res['cpu']['cache']))
      $res['cpu']['cache'] = implode("<br />", $res['cpu']['cache']);
  }

  return $res;
}

//FreeBSD system detects
function sys_freebsd()
{
  //CPU
  if (false === ($res['cpu']['num'] = get_key("hw.ncpu")))
    return false;
  $res['cpu']['model'] = get_key("hw.model");
  return $res;
}

//Obtain the parameter values FreeBSD
function get_key($keyName)
{
  return do_command('sysctl', "-n $keyName");
}

//Determining the location of the executable file FreeBSD
function find_command($commandName)
{
  $path = array('/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin');
  foreach ($path as $p) {
    if (is_executable("$p/$commandName"))
      return "$p/$commandName";
  }
  return false;
}

//Order Execution System FreeBSD
function do_command($commandName, $args)
{
  $buffer = "";
  if (false === ($command = find_command($commandName)))
    return false;
  if ($fp = popen("$command $args", 'r')) {
    while (!feof($fp)) {
      $buffer .= fgets($fp, 4096);
    }
    return trim($buffer);
  }
  return false;
}


function GetWMI($wmi, $strClass, $strValue = array())
{
  $arrData = array();

  $objWEBM = $wmi->Get($strClass);
  $arrProp = $objWEBM->Properties_;
  $arrWEBMCol = $objWEBM->Instances_();
  foreach ($arrWEBMCol as $objItem) {
    $arrInstance = array();
    foreach ($arrProp as $propItem) {
      $propName = $propItem->Name;
      $value = $objItem->$propName;
      if (empty($strValue)) {
        $arrInstance[$propItem->Name] = trim($value);
      } else {
        if (in_array($propItem->Name, $strValue)) {
          $arrInstance[$propItem->Name] = trim($value);
        }
      }
    }
    $arrData[] = $arrInstance;
  }
  return $arrData;
}

//NIC flow
$strs = file("/proc/net/dev");

for ($i = 2; $i < count($strs); $i++) {
  preg_match_all("/([^\s]+):[\s]{0,}(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/", $strs[$i], $info);
  $NetOutSpeed[$i] = $info[10][0];
  $NetInputSpeed[$i] = $info[2][0];
  $NetInput[$i] = formatsize($info[2][0]);
  $NetOut[$i] = formatsize($info[10][0]);
}

//Real-time refresh ajax calls
if ($_GET['act'] == "rt") {
  $arr = array('NetOut2' => "$NetOut[2]", 'NetOut3' => "$NetOut[3]", 'NetOut4' => "$NetOut[4]", 'NetOut5' => "$NetOut[5]", 'NetOut6' => "$NetOut[6]", 'NetOut7' => "$NetOut[7]", 'NetOut8' => "$NetOut[8]", 'NetOut9' => "$NetOut[9]", 'NetOut10' => "$NetOut[10]", 'NetInput2' => "$NetInput[2]", 'NetInput3' => "$NetInput[3]", 'NetInput4' => "$NetInput[4]", 'NetInput5' => "$NetInput[5]", 'NetInput6' => "$NetInput[6]", 'NetInput7' => "$NetInput[7]", 'NetInput8' => "$NetInput[8]", 'NetInput9' => "$NetInput[9]", 'NetInput10' => "$NetInput[10]", 'NetOutSpeed2' => "$NetOutSpeed[2]", 'NetOutSpeed3' => "$NetOutSpeed[3]", 'NetOutSpeed4' => "$NetOutSpeed[4]", 'NetOutSpeed5' => "$NetOutSpeed[5]", 'NetInputSpeed2' => "$NetInputSpeed[2]", 'NetInputSpeed3' => "$NetInputSpeed[3]", 'NetInputSpeed4' => "$NetInputSpeed[4]", 'NetInputSpeed5' => "$NetInputSpeed[5]");
  $jarr = json_encode($arr);
  $_GET['callback'] = htmlspecialchars($_GET['callback']);
  echo $_GET['callback'], '(', $jarr, ')';
  exit;
}

/**
 * Start a session with a custom timeout.
 * 
 * @param int $timeout Session lifetime in seconds
 * @param int $probability GC Probability
 * @param string $cookie_domain Custom cookie domain
 */
function session_start_timeout($timeout = 5, $probability = 100, $cookie_domain = '/')
{
  ini_set("session.gc_maxlifetime", $timeout);
  ini_set("session.cookie_lifetime", $timeout);
  $seperator = strstr(strtoupper(substr(PHP_OS, 0, 3)), "WIN") ? "\\" : "/";
  $path = ini_get("session.save_path") . $seperator . "session_" . $timeout . "sec";
  if (!file_exists($path)) {
    if (!mkdir($path, 600)) {
      trigger_error("Failed to create session save path directory '$path'. Check permissions.", E_USER_ERROR);
    }
  }
  ini_set("session.save_path", $path);
  ini_set("session.gc_probability", $probability);
  ini_set("session.gc_divisor", 100);
  session_start();
  if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), $_COOKIE[session_name()], time() + $timeout, $cookie_domain);
  }
}

session_start_timeout(3600);
$MSGFILE = session_id();

// If user has a "Remember Me" session, re-extend GC lifetime and cookie
if (isset($_SESSION['remembered']) && $_SESSION['remembered'] && isset($_SESSION['session_lifetime'])) {
  $lifetime = (int) $_SESSION['session_lifetime'];
  ini_set('session.gc_maxlifetime', $lifetime);
  $params = session_get_cookie_params();
  setcookie(session_name(), session_id(), time() + $lifetime, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
}

// Enforce authentication after session is started
requireAuth();

// Set username from OAuth session (replaces getUser() from rutorrent)
$username = getCurrentUser();
// Admin check replaces $master = file_get_contents('/srv/rutorrent/home/db/master.txt')
$master = isAdmin() ? $username : '__admin__';

// Optimization: Fetch process list once per request
$processList = shell_exec("ps axo user,pid,comm,cmd");

/**
 * Check if a specific process is running for a user.
 * 
 * Uses the cached global $processList to avoid repeated shell execution.
 * 
 * Regex Logic:
 * - Matches the start of a line ('m' modifier).
 * - Matches the username followed by whitespace.
 * - Matches any characters until the process name is found.
 * - Case-insensitive matching ('i' modifier).
 * 
 * @param string $processName Name of the process/command to search for
 * @param string $username User who owns the process
 * @return bool True if running, false otherwise
 */
function processExists($processName, $username)
{
  global $processList;
  // Regex: Start of line -> username -> whitespace -> ... -> processName
  // 'm' modifier allows matching start of lines
  if (preg_match("/^$username\s+.*\s+$processName/mi", $processList)) {
    return true;
  }
  return false;
}


$btsync = processExists("resilio-sync", 'rslsync');
$deluged = processExists("deluged", $username);
$delugedweb = processExists("deluge-web", $username);
$emby = processExists("emby-server", $username);
$headphones = processExists("headphones", $username);
$irssi = processExists("irssi", $username);
$lidarr = processExists("lidarr", $username);
$nzbget = processExists("nzbget", $username);
$nzbhydra = processExists("nzbhydra", $username);
$ombi = processExists("ombi", $username);
$plex = processExists("Plex", 'plex');
$Tautulli = processExists("Tautulli", 'Tautulli');
$pyload = processExists("pyload", $username);
$radarr = processExists("radarr", $username);
$rtorrent = processExists("rtorrent", $username);
$sabnzbd = processExists("sabnzbd", $username);
$sickrage = processExists("sickrage", $username);
$medusa = processExists("medusa", $username);
$sonarr = processExists("nzbdrone", $username);
$subsonic = processExists("subsonic", $username);
$syncthing = processExists("syncthing", $username);
$jackett = processExists("jackett", $username);
$couchpotato = processExists("couchpotato", $username);
$quassel = processExists("quassel", $username);
$shellinabox = processExists("shellinabox", 'shellinabox');
$csf = processExists("lfd", 'root');
$sickgear = processExists("sickgear", 8088);
$transmission = processExists("transmission-daemon", $username);
$qbittorrent = processExists("qbittorrent-nox", $username);
// $nzbget = processExists("nzbget", $username); // Removed duplicate call
$znc = processExists("znc", $username);

if (file_exists('/srv/rutorrent/home/custom/url.override.php')) {
  // BEGIN CUSTOM URL OVERRIDES //
  include($_SERVER['DOCUMENT_ROOT'] . '/custom/url.override.php');
  // END CUSTOM URL OVERRIDES ////
} else {
  $btsyncURL = "http://" . $_SERVER['HTTP_HOST'] . ":8888/gui/";
  $cpURL = "https://" . $_SERVER['HTTP_HOST'] . "/couchpotato";
  $csfURL = "https://" . $_SERVER['HTTP_HOST'] . ":3443";
  if ($dwssl == "true") {
    $dwURL = "https://" . $_SERVER['HTTP_HOST'] . ":$dwport";
  }
  if ($dwssl == "false") {
    $dwURL = "http://" . $_SERVER['HTTP_HOST'] . ":$dwport";
  }
  $embyURL = "https://" . $_SERVER['HTTP_HOST'] . "/emby";
  $headphonesURL = "https://" . $_SERVER['HTTP_HOST'] . "/headphones/home";
  $jackettURL = "https://" . $_SERVER['HTTP_HOST'] . "/jackett/UI/Dashboard";
  $lidarrURL = "https://" . $_SERVER['HTTP_HOST'] . "/lidarr";
  $nextcloudURL = "https://" . $_SERVER['HTTP_HOST'] . "/nextcloud";
  $nzbgetURL = "https://" . $_SERVER['HTTP_HOST'] . "/nzbget";
  $nzbhydraURL = "https://" . $_SERVER['HTTP_HOST'] . "/nzbhydra";
  $plexURL = "http://" . $_SERVER['HTTP_HOST'] . ":31400/web/";
  $TautulliURL = "https://" . $_SERVER['HTTP_HOST'] . "/tautulli";
  $ombiURL = "https://" . $_SERVER['HTTP_HOST'] . "/ombi";
  $pyloadURL = "https://" . $_SERVER['HTTP_HOST'] . "/pyload/login";
  $radarrURL = "https://" . $_SERVER['HTTP_HOST'] . "/radarr";
  $rapidleechURL = "https://" . $_SERVER['HTTP_HOST'] . "/rapidleech";
  $sabnzbdURL = "https://" . $_SERVER['HTTP_HOST'] . "/sabnzbd";
  $sickgearURL = "https://" . $_SERVER['HTTP_HOST'] . "/sickgear";
  $sickrageURL = "https://" . $_SERVER['HTTP_HOST'] . "/sickrage";
  $medusaURL = "https://" . $_SERVER['HTTP_HOST'] . "/medusa";
  $sonarrURL = "https://" . $_SERVER['HTTP_HOST'] . "/sonarr";
  $subsonicURL = "https://" . $_SERVER['HTTP_HOST'] . "/subsonic";
  $syncthingURL = "https://" . $_SERVER['HTTP_HOST'] . "/syncthing/";
  $transmissionURL = "https://" . $_SERVER['HTTP_HOST'] . "/transmission";
  $qbittorrentURL = "https://" . $_SERVER['HTTP_HOST'] . "/qbittorrent/";
  if ($zssl == "true") {
    $zncURL = "https://" . $_SERVER['HTTP_HOST'] . ":$zport";
  }
  if ($zssl == "false") {
    $zncURL = "http://" . $_SERVER['HTTP_HOST'] . ":$zport";
  }
}

include($_SERVER['DOCUMENT_ROOT'] . '/widgets/lang_select.php');
include($_SERVER['DOCUMENT_ROOT'] . '/widgets/plugin_data.php');
include($_SERVER['DOCUMENT_ROOT'] . '/widgets/package_data.php');
include($_SERVER['DOCUMENT_ROOT'] . '/widgets/sys_data.php');
include($_SERVER['DOCUMENT_ROOT'] . '/widgets/theme_select.php');
$base = 1024;
$location = "/home";

function isWidgetVisible($widgetName)
{
  global $db, $username;
  if (!isset($db))
    return true; // Fallback if DB invalid

  // Check user_widgets
  // We need user_id. For now, assume username is unique and we can subquery or join.
  // Or fetch user_id. 
  // Optimization: Store user_id in session?

  try {
    $stmt = $db->prepare("
            SELECT uw.is_visible 
            FROM user_widgets uw
            JOIN users u ON uw.user_id = u.id
            JOIN widgets w ON uw.widget_id = w.id
            WHERE u.username = ? AND w.name = ?
        ");
    $stmt->execute([$username, $widgetName]);
    $res = $stmt->fetchColumn();

    if ($res !== false) {
      return (bool) $res;
    }

    // Fallback to widget default
    $stmt = $db->prepare("SELECT default_enabled FROM widgets WHERE name = ?");
    $stmt->execute([$widgetName]);
    $def = $stmt->fetchColumn();
    return ($def !== false) ? (bool) $def : true;

  } catch (PDOException $e) {
    return true; // Default to visible on error
  }
}

function isEnabled($process, $username)
{
  $service = $process;
  // Check if service is active/enabled
  // We check for .service file existence as a proxy for 'installed'
  // But strictly 'enabled/running' is what we want to toggle.
  // The original code checked file existence to decide if it CAN be toggled, 
  // and seemingly assumed if it's there, it's ON? 
  // No, the original logic returned a 'disable' button (green/toggle-en) if the service file exists in multi-user.target.wants (meaning enabled).
  // And a 'enable' button (red/toggle-dis) if it doesn't.

  $is_enabled = (
    file_exists('/etc/systemd/system/multi-user.target.wants/' . $process . '@' . $username . '.service') ||
    file_exists('/etc/systemd/system/multi-user.target.wants/' . $process . '.service')
  );

  if ($is_enabled) {
    // It is currently ENABLED. Toggle should show CHECKED. 
    // Action: Clicking it should sending servicedisable command.
    $action_url = "?id=77&servicedisable=$service";
    $checked = 'checked';
  } else {
    // It is currently DISABLED. Toggle should show UNCHECKED.
    // Action: Clicking it should sending serviceenable command.
    $action_url = "?id=66&serviceenable=$service";
    $checked = '';
  }

  return "
  <div class=\"toggle-wrapper text-right\">
    <label class=\"vp-toggle\">
      <input type=\"checkbox\" $checked onchange=\"location.href='$action_url'\">
      <span class=\"vp-slider\"></span>
    </label>
  </div>";
}
/* check for services */
switch (intval(isset($_GET['id']) ? $_GET['id'] : '')) {
  case 0:
    $rtorrent = isEnabled("rtorrent", $username);
    $cbodyr .= $rtorrent;
    $irssi = isEnabled("irssi", $username);
    $cbodyi .= $irssi;
    $deluged = isEnabled("deluged", $username);
    $cbodyd .= $deluged;
    $delugedweb = isEnabled("deluge-web", $username);
    $cbodydw .= $delugedweb;
    $shellinabox = isEnabled("shellinabox", 'shellinabox');
    $wcbodyb .= $shellinabox;
    $btsync = isEnabled("resilio-sync", 'rslsync');
    $cbodyb .= $btsync;
    $couchpotato = isEnabled("couchpotato", $username);
    $cbodycp .= $couchpotato;
    $emby = isEnabled("emby-server", $username);
    $cbodye .= $emby;
    $headphones = isEnabled("headphones", $username);
    $cbodyhp .= $headphones;
    $jackett = isEnabled("jackett", $username);
    $cbodyj .= $jackett;
    $lidarr = isEnabled("lidarr", $username);
    $cbodylid .= $lidarr;
    $nzbget = isEnabled("nzbget", $username);
    $cbodynzg .= $nzbget;
    $nzbhydra = isEnabled("nzbhydra", $username);
    $cbodynzb .= $nzbhydra;
    $ombi = isEnabled("ombi", $username);
    $cbodypr .= $ombi;
    $plex = isEnabled("plexmediaserver", 'plex');
    $cbodyp .= $plex;
    $Tautulli = isEnabled("Tautulli", 'Tautulli');
    $cbodypp .= $Tautulli;
    $pyload = isEnabled("pyload", $username);
    $cbodypl .= $pyload;
    $quassel = isEnabled("quassel", $username);
    $cbodyq .= $quassel;
    $radarr = isEnabled("radarr", $username);
    $cbodyrad .= $radarr;
    $rapidleech = isEnabled("rapidleech", $username);
    $cbodyrl .= $rapidleech;
    $sabnzbd = isEnabled("sabnzbd", $username);
    $cbodysz .= $sabnzbd;
    $sickgear = isEnabled("sickgear", 8088);
    $cbodysg .= $sickgear;
    $sickrage = isEnabled("sickrage", $username);
    $cbodysr .= $sickrage;
    $medusa = isEnabled("medusa", $username);
    $cbodym .= $medusa;
    $sonarr = isEnabled("sonarr", $username);
    $cbodys .= $sonarr;
    $subsonic = isEnabled("subsonic", 'root');
    $cbodyss .= $subsonic;
    $syncthing = isEnabled("syncthing", $username);
    $cbodyst .= $syncthing;
    $transmission = isEnabled("transmission", $username);
    $cbodytr .= $transmission;
    $qbittorrent = isEnabled("qbittorrent", $username);
    $cbodyqb .= $qbittorrent;
    $x2go = isEnabled("x2go", $username);
    $cbodyx .= $x2go;
    $znc = isEnabled("znc", $username);
    $cbodyz .= $znc;

    break;
}
$appName = [
  ['autodl', "AutoDL-IRSSI", 'irssi', "/home/$username/.irssi/log"],
  ['btsync', "Resilio-Sync BTSync", 'resilio-sync', "/home/$username/.config/resilio-sync/sync.log"],
  ['couchpotato', 'CouchPotato', 'couchpotato', "/home/$username/.couchpotato/logs/CouchPotato.log"],
  ['csf', "Config Server Firewall", 'csf', "/var/log/lfd.log"],
  ['deluge', "Deluge Daemon", 'deluged', "/home/$username/.config/deluge/deluged.log"],
  ['deluge', "Deluge Web Interface", "deluge-web", "/home/$username/.config/deluge/deluge-web.log"],
  ['emby', "Emby-Server", 'emby-server', "/var/lib/emby/logs/embyserver.txt"],
  ['headphones', 'Headphones', 'headphones', "/home/$username/.headphones/logs/headphones.log"],
  ['jackett', 'Jackett', 'jackett', "/home/$username/.config/Jackett/log.txt"],
  ['lidarr', 'Lidarr', 'lidarr', "/home/$username/.config/Lidarr/logs/lidarr.txt"],
  ['medusa', 'Medusa', 'medusa', "/home/$username/.medusa/Logs/medusa.log"],
  ['nextcloud', 'Nextcloud', 'nextcloud', "/var/www/nextcloud/data/nextcloud.log"],
  ['nzbget', 'NZBGet', 'nzbget', "/home/$username/.nzbget.log"],
  ['nzbhydra', 'NZBHydra', 'nzbhydra', "/home/$username/.nzbhydra/nzbhydra.log"],
  ['ombi', 'Ombi', 'ombi', "/home/$username/.config/Ombi/Logs/log-base.txt"],
  ['plex', 'Plex', 'plexmediaserver', "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Logs/Plex Media Server.log"],
  ['pyload', 'pyLoad', 'pyload', "/home/$username/.pyload/Logs/log.txt"],
  ['qbittorrent', 'qBittorrent', 'qbittorrent', "/home/$username/.local/share/data/qBittorrent/logs/qbittorrent.log"],
  ['quassel', 'Quassel', 'quassel', "/var/log/quassel.log"],
  ['radarr', 'Radarr', 'radarr', "/home/$username/.config/Radarr/logs/radarr.txt"],
  ['rapidleech', 'Rapidleech', 'nginx', "/var/log/nginx/rapidleech.error.log"],
  ['rtorrent', 'rTorrent', 'rtorrent', "/home/$username/.sessions/rtorrent.log"],
  ['sabnzbd', 'SABnzbd', 'sabnzbd', "/home/$username/.sabnzbd/logs/sabnzbd.log"],
  ['sickgear', 'SickGear', 'sickgear', "/home/$username/.sickgear/logs/sickgear.log"],
  ['sickrage', 'SickRage', 'sickrage', "/home/$username/.sickrage/Logs/sickrage.log"],
  ['sonarr', "Sonarr v2", 'nzbdrone', "/home/$username/.config/NzbDrone/logs/sonarr.txt"],
  ['subsonic', 'Subsonic', 'subsonic', "/var/subsonic/subsonic_sh.log"],
  ['syncthing', 'Syncthing', 'syncthing', "/home/$username/.config/syncthing/syncthing.log"],
  ['tautulli', 'Tautulli', 'tautulli', "/home/$username/.config/Tautulli/logs/tautulli.log"],
  ['transmission', 'Transmission', 'transmission', "/var/lib/transmission-daemon/info/transmission-daemon.log"],
  ['webconsole', "Web Console", 'shellinabox', ""],
  ['x2go', 'x2Go', 'x2go', "/var/log/syslog"],
  ['znc', 'ZNC', 'znc', "/home/$username/.znc/znc.log"],
];

// Service control — POST only with CSRF + admin validation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['id']) && isAdmin()) {
  requireCsrfToken();
  foreach ($appName as list($a, $b, $c)) {
    switch (intval($_POST['id'])) {
      /* enable & start services */
      case 66:
        $process = escapeshellarg($_POST['serviceenable'] ?? '');
        if ($process == "'$c'") {
          if (file_exists('/etc/systemd/system/' . $c . '@.service') || file_exists('/etc/systemd/system/' . $c . '@' . $username . '.service') || file_exists('/etc/systemd/system/multi-user.target.wants/' . $c . '@' . $username . '.service')) {
            shell_exec("sudo systemctl enable $c@$username");
            shell_exec("sudo systemctl start $c@$username");
          } elseif (file_exists('/etc/systemd/system/' . $c . '.service') || file_exists('/lib/systemd/system/' . $c . '.service')) {
            shell_exec("sudo systemctl enable $c");
            shell_exec("sudo systemctl start $c");
          }
          header("Location: /");
          exit;
        }
        break;
      /* disable & stop services */
      case 77:
        $process = escapeshellarg($_POST['servicedisable'] ?? '');
        if ($process == "'$c'") {
          if (file_exists('/etc/systemd/system/' . $c . '@.service') || file_exists('/etc/systemd/system/' . $c . '@' . $username . '.service') || file_exists('/etc/systemd/system/multi-user.target.wants/' . $c . '@' . $username . '.service')) {
            shell_exec("sudo systemctl stop $c@$username");
            shell_exec("sudo systemctl disable $c@$username");
          } elseif (file_exists('/etc/systemd/system/' . $c . '.service') || file_exists('/lib/systemd/system/' . $c . '.service')) {
            shell_exec("sudo systemctl stop $c");
            shell_exec("sudo systemctl disable $c");
          }
          header("Location: /");
          exit;
        }
        break;
      /* restart services */
      case 88:
        $process = escapeshellarg($_POST['servicestart'] ?? '');
        if ($process == "'$c'") {
          if (file_exists('/etc/systemd/system/' . $c . '@.service') || file_exists('/etc/systemd/system/' . $c . '@' . $username . '.service') || file_exists('/etc/systemd/system/multi-user.target.wants/' . $c . '@' . $username . '.service')) {
            shell_exec("sudo systemctl enable $c@$username");
            shell_exec("sudo systemctl restart $c@$username");
          } elseif (file_exists('/etc/systemd/system/' . $c . '.service') || file_exists('/lib/systemd/system/' . $c . '.service')) {
            shell_exec("sudo systemctl enable $c");
            shell_exec("sudo systemctl restart $c");
          }
          header("Location: /");
          exit;
        }
        break;
    }
  }
}

