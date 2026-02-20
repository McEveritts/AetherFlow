<?php
namespace AetherFlow\Inc;

/**
 * Hardware Abstraction Layer
 * 
 * Provides a unified interface for retrieving system metrics (CPU, Disk, Processes)
 * across both Linux (production) and Windows (development/Docker) environments.
 * 
 * @package AetherFlow\Inc
 */
class SystemInterface
{
    private static $instance = null;
    private $isWindows = false;

    private function __construct()
    {
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $this->isWindows = true;
        }
    }

    public static function getInstance()
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Retrieve global disk space utilization for the root volume.
     * 
     * @return array ['total' => float, 'used' => float, 'free' => float] (In GB)
     */
    public function get_disk_space()
    {
        if ($this->isWindows) {
            // Mock data for Windows frontend development
            return [
                'total' => 500.0,
                'used' => 250.0,
                'free' => 250.0
            ];
        }

        // Production Linux behavior (df -h fallback since repquota is fragile user-to-user)
        $total = disk_total_space("/");
        $free = disk_free_space("/");

        if ($total && $free) {
            $gb = 1024 * 1024 * 1024;
            return [
                'total' => round($total / $gb, 2),
                'used' => round(($total - $free) / $gb, 2),
                'free' => round($free / $gb, 2)
            ];
        }

        return ['total' => 0, 'used' => 0, 'free' => 0];
    }

    /**
     * Retrieve approximate active CPU utilization percentage.
     * 
     * @return float CPU Percentage
     */
    public function get_cpu_usage()
    {
        if ($this->isWindows) {
            // Mock fluctuating CPU data for Windows
            return (float) rand(5, 45);
        }

        // Production Linux behavior (reads loads)
        $load = sys_getloadavg();
        if ($load) {
            $cores = (int) trim(shell_exec("nproc") ?? '1');
            $cores = $cores > 0 ? $cores : 1;
            // Approximate CPU usage based on 1-minute load average
            $usage = ($load[0] / $cores) * 100;
            return min(round($usage, 2), 100.0);
        }

        return 0.0;
    }

    /**
     * Check if a background process is active.
     * 
     * @param string $processName Name of the process to look for
     * @param string $username Owner of the process
     * @return bool True if running
     */
    public function is_process_running($processName, $username)
    {
        if ($this->isWindows) {
            // Mock active status on Windows
            return true;
        }

        // Production Linux behavior (ps axo grep)
        $pids = [];
        // Sanitize the process name to prevent Regex Denial of Service (ReDoS)
        $safeProcessName = escapeshellarg(preg_quote($processName, '/'));
        exec("ps axo user:20,pid,pcpu,pmem,vsz,rss,tty,stat,start,time,comm,cmd | grep " . escapeshellarg($username) . " | grep -iE " . $safeProcessName . " | grep -v grep", $pids);
        return count($pids) > 0;
    }

    /**
     * Safely execute a system-level admin action.
     * 
     * @param string $command The raw shell script command to run.
     * @return void
     */
    public function execute_admin_action($action)
    {
        if ($this->isWindows) {
            // Mock action
            error_log("Mock Admin Action Executed: " . $action);
            return;
        }

        // Hardcoded switch/allowlist to prevent arbitrary shell injection
        $allowed_actions = [
            'restart_plex' => 'systemctl restart plexmediaserver',
            'restart_rtorrent' => 'systemctl restart rtorrent',
            'restart_sonarr' => 'systemctl restart sonarr',
            'restart_radarr' => 'systemctl restart radarr',
            'reboot' => '/sbin/reboot',
            'update' => 'apt-get update && apt-get upgrade -y'
        ];

        if (isset($allowed_actions[$action])) {
            shell_exec($allowed_actions[$action]);
        } else {
            error_log("Attempted unauthorized or undefined admin action: " . $action);
        }
    }
}
