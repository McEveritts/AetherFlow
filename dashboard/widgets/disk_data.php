<?php
/**
 * Disk Data Widget
 *
 * Displays disk usage, quota information, and active torrent counts.
 * Previously depended on rutorrent's util.php for getUser(), now uses
 * session-based auth instead.
 *
 * @package AetherFlow\Widgets
 * @author McEveritts <armyworkbs@gmail.com>
 */

include($_SERVER['DOCUMENT_ROOT'] . '/widgets/class.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/localize.php');

// Get username from session (replaces rutorrent getUser())
$username = $_SESSION['user'] ?? '';

/**
 * Check if a process is running for a given user.
 *
 * @param string $processName Process name to search for
 * @param string $username    System username
 * @return bool
 */
function processExists(string $processName, string $username): bool
{
  $safeUser = escapeshellarg($username);
  $safeProc = escapeshellarg($processName);
  $output = [];
  exec(
    "ps axo user:20,pid,pcpu,pmem,vsz,rss,tty,stat,start,time,comm | grep {$safeUser} | grep -iE {$safeProc} | grep -v grep",
    $output
  );
  return count($output) > 0;
}

/**
 * Count files matching a glob pattern safely.
 *
 * @param string $pattern Glob pattern
 * @return int
 */
function countFiles(string $pattern): int
{
  $files = glob($pattern);
  return $files === false ? 0 : count($files);
}

$safeUsername = basename($username); // Strip any path traversal

$deluged = processExists('deluged', $safeUsername);
$delugedweb = processExists('deluge-web', $safeUsername);
$rtorrent = processExists('rtorrent', $safeUsername);

// Unit Conversion
function formatsize(float $size): string
{
  $units = [' B ', ' KB ', ' MB ', ' GB ', ' TB '];
  $i = 0;
  for ($i = 0; $i < 5; $i++) {
    if (floor($size / pow(1024, $i)) == 0) {
      break;
    }
  }

  $allsize = [];
  $allsize1 = [];
  for ($l = $i - 1; $l >= 0; $l--) {
    $allsize1[$l] = floor($size / pow(1024, $l));
    $allsize[$l] = $allsize1[$l] - ($allsize1[$l + 1] ?? 0) * 1024;
  }

  $fsize = '';
  $len = count($allsize);
  for ($j = $len - 1; $j >= 0; $j--) {
    $fsize .= ($allsize[$j] ?? 0) . $units[$j];
  }
  return $fsize;
}

$location = '/home';
$base = 1024;
$si_prefix = ['b', 'k', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

// Count torrents using safe glob instead of shell_exec with user input
$torrents = countFiles("/home/{$safeUsername}/.sessions/*.torrent");
$dtorrents = countFiles("/home/{$safeUsername}/.config/deluge/state/*.torrent");
$transtorrents = countFiles("/home/{$safeUsername}/.config/transmission/torrents/*.torrent");
$qtorrents = countFiles("/home/{$safeUsername}/.local/share/data/qBittorrent/BT_backup/*.torrent");

$php_self = $_SERVER['PHP_SELF'];
$web_path = substr($php_self, 0, strrpos($php_self, '/') + 1);
$time = microtime(true);
$start = $time;

if (file_exists('/install/.quota.lock')) {
  $safeUser = escapeshellarg($safeUsername);
  $dftotal = shell_exec("sudo /usr/sbin/repquota / | /bin/grep ^{$safeUser} | /usr/bin/awk '{printf \$4/1024/1024}'");
  $dffree = shell_exec("sudo /usr/sbin/repquota / | /bin/grep ^{$safeUser} | /usr/bin/awk '{printf (\$4-\$3)/1024/1024}'");
  $dfused = shell_exec("sudo /usr/sbin/repquota / | /bin/grep ^{$safeUser} | /usr/bin/awk '{printf \$3/1024/1024}'");
  $perused = sprintf('%1.0f', $dfused / $dftotal * 100);
} else {
  $bytesfree = disk_free_space('/home');
  $bytestotal = disk_total_space($location);
  $bytesused = $bytestotal - $bytesfree;
  $class = min((int) log($bytesfree, $base), count($si_prefix) - 1);

  try {
    $diskStatus = new DiskStatus('/home');
    $freeSpace = $diskStatus->freeSpace();
    $totalSpace = $diskStatus->totalSpace();
    $barWidth = ($diskStatus->usedSpace() / 500) * 500;
  } catch (RuntimeException $e) {
    error_log('DiskStatus error: ' . $e->getMessage());
    $freeSpace = '0 B';
    $totalSpace = '0 B';
    $barWidth = 0;
  }

  // Disk space calculations — no @ suppression
  $rawTotal = disk_total_space('.');
  $rawFree = disk_free_space('.');

  if ($rawTotal !== false && $rawFree !== false) {
    $dftotal = number_format(round($rawTotal / (1024 * 1024 * 1024), 3));
    $dffree = number_format(round($rawFree / (1024 * 1024 * 1024), 3));
    $dfused = number_format(round(($rawTotal - $rawFree) / (1024 * 1024 * 1024), 3));

    $dptotal = round($rawTotal / (1024 * 1024 * 1024), 3);
    $dpfree = round($rawFree / (1024 * 1024 * 1024), 3);
    $dpused = $dptotal - $dpfree;
    $perused = ($dptotal != 0) ? round($dpused / $dptotal * 100, 2) : 0;
  } else {
    $dftotal = $dffree = $dfused = '0';
    $perused = 0;
  }
}

if (file_exists("/home/{$safeUsername}/.sessions/rtorrent.lock")) {
  $rtorrents = countFiles("/home/{$safeUsername}/.sessions/*.torrent");
}
?>

<p class="nomargin"><?php echo T('FREE'); ?>: <span
    style="font-weight: 700; position: absolute; left: 100px;"><?php echo "$dffree"; ?> <b>GB</b></span></p>
<p class="nomargin"><?php echo T('USED'); ?>: <span
    style="font-weight: 700; position: absolute; left: 100px;"><?php echo "$dfused"; ?> <b>GB</b></span></p>
<p class="nomargin"><?php echo T('SIZE'); ?>: <span
    style="font-weight: 700; position: absolute; left: 100px;"><?php echo "$dftotal"; ?> <b>GB</b></span></p>
<div class="row">
  <div class="col-sm-8">
    <!--h4 class="panel-title text-success">Disk Space</h4-->
    <h3><?php echo T('DISK_SPACE'); ?></h3>
    <div class="progress">
      <?php
      if ($perused < "70") {
        $diskcolor = "progress-bar-success";
      }
      if ($perused > "70") {
        $diskcolor = "progress-bar-warning";
      }
      if ($perused > "90") {
        $diskcolor = "progress-bar-danger";
      }
      ?>
      <div style="width:<?php echo "$perused"; ?>%" aria-valuemax="100" aria-valuemin="0"
        aria-valuenow="<?php echo "$perused"; ?>" role="progressbar" class="progress-bar <?php echo $diskcolor ?>">
        <span class="sr-only"><?php echo "$perused"; ?>% <?php echo T('USED'); ?></span>
      </div>
    </div>
    <p style="font-size:10px"><?php echo T('PERCENTAGE_TXT_1'); ?> <?php echo "$perused" ?>%
      <?php echo T('PERCENTAGE_TXT_2'); ?></p>
  </div>
  <div class="col-sm-4 text-right">
    <?php
    if ($perused < "70") {
      $diskcolor = "disk-good";
    }
    if ($perused > "70") {
      $diskcolor = "disk-warning";
    }
    if ($perused > "90") {
      $diskcolor = "disk-danger";
    }
    ?>
    <i class="fa fa-hdd-o <?php echo $diskcolor ?>" style="font-size: 90px;"></i>
  </div>
</div>
<hr />
<?php if (processExists("rtorrent", $safeUsername) && file_exists("/home/{$safeUsername}/.sessions/rtorrent.lock")) { ?>
  <h4><?php echo T('RTORRENTS_TITLE'); ?></h4>
  <p class="nomargin"><?php echo T('TORRENTS_LOADED_1'); ?> <b><?php echo "$rtorrents"; ?></b>
    <?php echo T('TORRENTS_LOADED_2'); ?></p>
<?php } ?>
<?php if (processExists("deluged", $safeUsername) && file_exists('/install/.deluge.lock')) { ?>
  <h4><?php echo T('DTORRENTS_TITLE'); ?></h4>
  <p class="nomargin"><?php echo T('TORRENTS_LOADED_1'); ?> <b><?php echo "$dtorrents"; ?></b>
    <?php echo T('TORRENTS_LOADED_2'); ?></p>
<?php } ?>
<?php if (processExists("transmission", $safeUsername) && file_exists('/install/.transmission.lock')) { ?>
  <h4><?php echo T('TRTORRENTS_TITLE'); ?></h4>
  <p class="nomargin"><?php echo T('TORRENTS_LOADED_1'); ?> <b><?php echo "$transtorrents"; ?></b>
    <?php echo T('TORRENTS_LOADED_2'); ?></p>
<?php } ?>
<?php if (processExists("qbittorrent-nox", $safeUsername) && file_exists('/install/.qbittorrent.lock')) { ?>
  <h4><?php echo T('QTORRENTS_TITLE'); ?></h4>
  <p class="nomargin"><?php echo T('TORRENTS_LOADED_1'); ?> <b><?php echo "$qtorrents"; ?></b>
    <?php echo T('TORRENTS_LOADED_2'); ?></p>
<?php } ?>


<script type="text/javascript">
  $(function () {

    // Knob
    $('.dial-success').knob({
      readOnly: true,
      width: '70px',
      bgColor: '#E7E9EE',
      fgColor: '#4daf7c',
      inputColor: '#262B36'
    });

    $('.dial-warning').knob({
      readOnly: true,
      width: '70px',
      bgColor: '#E7E9EE',
      fgColor: '#e6ad5c',
      inputColor: '#262B36'
    });

    $('.dial-danger').knob({
      readOnly: true,
      width: '70px',
      bgColor: '#E7E9EE',
      fgColor: '#D9534F',
      inputColor: '#262B36'
    });

    $('.dial-info').knob({
      readOnly: true,
      width: '70px',
      bgColor: '#66BAC4',
      fgColor: '#fff',
      inputColor: '#fff'
    });

  });
</script>