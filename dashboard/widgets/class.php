<?php
/**
 * DiskStatus - Disk space utility class
 *
 * Provides methods to query total, free, and used disk space
 * with automatic unit formatting.
 *
 * @package AetherFlow\Widgets
 * @author McEveritts <armyworkbs@gmail.com>
 */
class DiskStatus
{
	const RAW_OUTPUT = true;

	private string $diskPath;

	public function __construct(string $diskPath)
	{
		$this->diskPath = $diskPath;
	}

	/**
	 * Get total disk space.
	 *
	 * @param bool $rawOutput Return raw bytes if true
	 * @return float|string
	 * @throws RuntimeException If disk path is invalid or inaccessible
	 */
	public function totalSpace(bool $rawOutput = false): float|string
	{
		$diskTotalSpace = disk_total_space($this->diskPath);
		if ($diskTotalSpace === false) {
			throw new RuntimeException("totalSpace(): Cannot read disk path '{$this->diskPath}'");
		}
		return $rawOutput ? $diskTotalSpace : $this->addUnits($diskTotalSpace);
	}

	/**
	 * Get free disk space.
	 *
	 * @param bool $rawOutput Return raw bytes if true
	 * @return float|string
	 * @throws RuntimeException If disk path is invalid or inaccessible
	 */
	public function freeSpace(bool $rawOutput = false): float|string
	{
		$diskFreeSpace = disk_free_space($this->diskPath);
		if ($diskFreeSpace === false) {
			throw new RuntimeException("freeSpace(): Cannot read disk path '{$this->diskPath}'");
		}
		return $rawOutput ? $diskFreeSpace : $this->addUnits($diskFreeSpace);
	}

	/**
	 * Get used space as a percentage (0-100).
	 *
	 * @param int $precision Decimal places
	 * @return float
	 * @throws RuntimeException If disk is unreadable
	 */
	public function usedSpace(int $precision = 1): float
	{
		return round(
			100 - ($this->freeSpace(self::RAW_OUTPUT) / $this->totalSpace(self::RAW_OUTPUT)) * 100,
			$precision
		);
	}

	/**
	 * Get the configured disk path.
	 */
	public function getDiskPath(): string
	{
		return $this->diskPath;
	}

	/**
	 * Format bytes into human-readable units.
	 */
	private function addUnits(float $bytes): string
	{
		$units = ['B', 'KB', 'MB', 'GB', 'TB'];
		for ($i = 0; $bytes >= 1024 && $i < count($units) - 1; $i++) {
			$bytes /= 1024;
		}
		return round($bytes, 1) . ' ' . $units[$i];
	}
}
