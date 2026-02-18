<?php
/**
 * File-based Cache Utility
 *
 * Simple file-based caching for expensive system stats like
 * disk usage, memory info, and network data. Avoids hitting
 * the OS on every page load.
 *
 * @package AetherFlow\Inc
 * @author McEveritts <armyworkbs@gmail.com>
 */

class Cache
{
    private string $cacheDir;

    /**
     * @param string|null $cacheDir Directory for cache files (defaults to /tmp/aetherflow-cache)
     */
    public function __construct(?string $cacheDir = null)
    {
        $this->cacheDir = $cacheDir ?? sys_get_temp_dir() . '/aetherflow-cache';
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0750, true);
        }
    }

    /**
     * Get a cached value, or compute and store it.
     *
     * @param string   $key     Cache key (alphanumeric + dashes)
     * @param callable $compute Callback that returns the value to cache
     * @param int      $ttl     Time-to-live in seconds (default: 30)
     * @return mixed
     */
    public function remember(string $key, callable $compute, int $ttl = 30): mixed
    {
        $file = $this->getPath($key);

        if (file_exists($file)) {
            $data = json_decode(file_get_contents($file), true);
            if ($data && isset($data['expires']) && $data['expires'] > time()) {
                return $data['value'];
            }
        }

        $value = $compute();
        $this->set($key, $value, $ttl);
        return $value;
    }

    /**
     * Get a cached value.
     *
     * @param string $key     Cache key
     * @param mixed  $default Default value if not found or expired
     * @return mixed
     */
    public function get(string $key, mixed $default = null): mixed
    {
        $file = $this->getPath($key);

        if (!file_exists($file)) {
            return $default;
        }

        $data = json_decode(file_get_contents($file), true);
        if (!$data || !isset($data['expires']) || $data['expires'] <= time()) {
            unlink($file);
            return $default;
        }

        return $data['value'];
    }

    /**
     * Store a value in cache.
     *
     * @param string $key   Cache key
     * @param mixed  $value Value to cache (must be JSON-serializable)
     * @param int    $ttl   Time-to-live in seconds
     */
    public function set(string $key, mixed $value, int $ttl = 30): void
    {
        $file = $this->getPath($key);
        $data = [
            'expires' => time() + $ttl,
            'value' => $value,
        ];
        file_put_contents($file, json_encode($data), LOCK_EX);
    }

    /**
     * Remove a cached value.
     *
     * @param string $key Cache key
     */
    public function forget(string $key): void
    {
        $file = $this->getPath($key);
        if (file_exists($file)) {
            unlink($file);
        }
    }

    /**
     * Clear all cached values.
     */
    public function flush(): void
    {
        $files = glob($this->cacheDir . '/*.cache');
        if ($files) {
            foreach ($files as $file) {
                unlink($file);
            }
        }
    }

    /**
     * Get the file path for a cache key.
     */
    private function getPath(string $key): string
    {
        // Sanitize key to prevent path traversal
        $safeKey = preg_replace('/[^a-zA-Z0-9_-]/', '_', $key);
        return $this->cacheDir . '/' . $safeKey . '.cache';
    }
}
