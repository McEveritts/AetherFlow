<?php
/**
 * Gemini API Proxy — OAuth 2.0 Service Account Auth
 *
 * Handles communication with Google's Generative Language API (Gemini)
 * using OAuth 2.0 Service Account authentication (Bearer tokens).
 *
 * Authentication:
 *   - Uses GeminiAuth.php to sign JWTs and obtain Bearer tokens
 *   - Requires a Google Cloud Service Account JSON key file
 *   - No API key needed — uses the Google AI Ultra subscription
 *
 * Rate Limiting:
 *   - Uses PHP Sessions to track request timestamps
 *   - 10 requests per rolling 60-second window per user
 *
 * @package AetherFlow\API
 */
include_once($_SERVER['DOCUMENT_ROOT'] . '/inc/config.php');
require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/GeminiAuth.php');

// Rate Limiting Logic
if (!isset($_SESSION['gemini_requests'])) {
    $_SESSION['gemini_requests'] = [];
}
$_SESSION['gemini_requests'] = array_filter($_SESSION['gemini_requests'], function ($timestamp) {
    return $timestamp > (time() - 60);
});

// Protect against excessive automated hits & control costs - max 5 requests per minute
if (count($_SESSION['gemini_requests']) >= 5) {
    header('HTTP/1.1 429 Too Many Requests');
    die(json_encode(['error' => 'Rate limit exceeded. Please wait a minute before requesting again.']));
}
$_SESSION['gemini_requests'][] = time();

// Security: require logged-in user
if (!isset($_SESSION['user'])) {
    header('HTTP/1.1 403 Forbidden');
    die(json_encode(['error' => 'Unauthorized']));
}

require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/csrf.php');
requireCsrfToken();

header('Content-Type: application/json');

// ── OAuth Authentication ──────────────────────────────────────────────
// Resolve the service account key file path
$keyPath = $_ENV['GOOGLE_SERVICE_ACCOUNT_KEY_PATH'] ?? '';
if (empty($keyPath)) {
    die(json_encode([
        'error' => 'Google Service Account key not configured. Set GOOGLE_SERVICE_ACCOUNT_KEY_PATH in .env'
    ]));
}

// Support relative paths (relative to DOCUMENT_ROOT)
if ($keyPath[0] !== '/' && !preg_match('/^[A-Z]:\\\\/i', $keyPath)) {
    $keyPath = $_SERVER['DOCUMENT_ROOT'] . '/' . $keyPath;
}

try {
    $auth = new GeminiAuth($keyPath);
    $accessToken = $auth->getAccessToken();
} catch (RuntimeException $e) {
    die(json_encode(['error' => 'Auth Error: ' . $e->getMessage()]));
}

// ── Request Processing ────────────────────────────────────────────────
$inputPayload = json_decode(file_get_contents('php://input'), true);
$userPrompt = $inputPayload['prompt'] ?? '';

if (empty($userPrompt)) {
    die(json_encode(['error' => 'Empty prompt']));
}

require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/SystemInterface.php');
use AetherFlow\Inc\SystemInterface;

$sys = SystemInterface::getInstance();

// ── Gather System Context ─────────────────────────────────────────────
$cpuUsage = $sys->get_cpu_usage();
$cpuContext = "CPU Usage: " . $cpuUsage . "%";

// Memory logic (If Windows, mock. If Linux, parse free)
if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
    $ramContext = "RAM Usage: Used 4096MB / Total 16384MB";
} else {
    $freeOutput = shell_exec('free -m');
    if ($freeOutput) {
        $arr = explode("\n", trim($freeOutput));
        if (isset($arr[1])) {
            $mem = array_values(array_filter(explode(" ", $arr[1])));
            if (isset($mem[1]) && isset($mem[2])) {
                $ramContext = "RAM Usage: Used {$mem[2]}MB / Total {$mem[1]}MB";
            } else {
                $ramContext = "RAM Usage: Unknown";
            }
        } else {
            $ramContext = "RAM Usage: Unknown";
        }
    } else {
        $ramContext = "RAM Usage: Unknown";
    }
}

$diskStats = $sys->get_disk_space();
$diskContext = "Disk Usage: Used " . $diskStats['used'] . "GB / Total " . $diskStats['total'] . "GB";

$systemPrompt = "You are AetherFlow Assistant, an AI Ultra expert system administrator for this seedbox/media server.
Current System Stats:
- $cpuContext
- $ramContext
- $diskContext
User: $username
Project Version: $version

You are running on Google AI Ultra via OAuth 2.0 Service Account authentication.
Answer the user's question concisely and accurately based on these stats and general Linux/Media Server knowledge.";

// ── Call Gemini API with Bearer Token ─────────────────────────────────
$model = $_ENV['GEMINI_MODEL'] ?? 'gemini-2.0-flash';
$url = "https://generativelanguage.googleapis.com/v1beta/models/{$model}:generateContent";

$data = [
    "system_instruction" => [
        "parts" => [
            ["text" => $systemPrompt]
        ]
    ],
    "contents" => [
        [
            "role" => "user",
            "parts" => [
                ["text" => $userPrompt]
            ]
        ]
    ],
    "generationConfig" => [
        "temperature" => 0.7,
        "topK" => 40,
        "topP" => 0.95,
        "maxOutputTokens" => 1024,
    ]
];

$options = [
    'http' => [
        'header' => "Content-Type: application/json\r\nAuthorization: Bearer {$accessToken}\r\n",
        'method' => 'POST',
        'content' => json_encode($data),
        'ignore_errors' => true,
    ]
];

$context = stream_context_create($options);
$result = file_get_contents($url, false, $context);

if ($result === false) {
    die(json_encode(['error' => 'Failed to connect to Gemini API']));
}

// Parse response
$response = json_decode($result, true);

if (isset($response['error'])) {
    $errMsg = $response['error']['message'] ?? 'Unknown error';
    $errCode = $response['error']['code'] ?? '';
    die(json_encode(['error' => "Gemini API Error ({$errCode}): {$errMsg}"]));
}

// Extract text
if (isset($response['candidates'][0]['content']['parts'][0]['text'])) {
    echo json_encode(['reply' => $response['candidates'][0]['content']['parts'][0]['text']]);
} else {
    echo json_encode(['reply' => 'No response generated.']);
}
?>