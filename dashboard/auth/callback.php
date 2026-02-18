<?php
/**
 * Google OAuth2 Callback Handler
 *
 * Handles the redirect from Google after user authorization.
 * Exchanges the authorization code for an access token, fetches user info,
 * and creates/updates the user in the database.
 *
 * @package AetherFlow\Auth
 */

require_once dirname(__DIR__) . '/vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(dirname(__DIR__));
$dotenv->safeLoad();

// Start session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Database connection
$dbPath = dirname(__DIR__) . '/db/aetherflow.sqlite';
try {
    $db = new PDO('sqlite:' . $dbPath);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    error_log("Auth DB Error: " . $e->getMessage());
    die("Database connection failed.");
}

// Run migration to ensure google_id column exists
try {
    // Check if google_id column exists
    $columns = $db->query("PRAGMA table_info(users)")->fetchAll();
    $columnNames = array_column($columns, 'name');
    if (!in_array('google_id', $columnNames)) {
        $db->exec("ALTER TABLE users ADD COLUMN google_id TEXT UNIQUE");
        $db->exec("ALTER TABLE users ADD COLUMN email TEXT");
        $db->exec("ALTER TABLE users ADD COLUMN avatar_url TEXT");
    }
} catch (PDOException $e) {
    error_log("Migration error: " . $e->getMessage());
    // Non-fatal — columns may already exist
}

// ---- Validate the callback ----

// Check for errors from Google
if (isset($_GET['error'])) {
    error_log("Google OAuth Error: " . $_GET['error']);
    header('Location: /login.php?error=' . urlencode($_GET['error']));
    exit;
}

// Verify authorization code exists
if (!isset($_GET['code'])) {
    header('Location: /login.php?error=no_code');
    exit;
}

// Verify CSRF state token
if (!isset($_GET['state']) || !isset($_SESSION['oauth2_state']) || $_GET['state'] !== $_SESSION['oauth2_state']) {
    unset($_SESSION['oauth2_state']);
    header('Location: /login.php?error=invalid_state');
    exit;
}
unset($_SESSION['oauth2_state']);

$authCode = $_GET['code'];
$clientId = $_ENV['GOOGLE_CLIENT_ID'] ?? '';
$clientSecret = $_ENV['GOOGLE_CLIENT_SECRET'] ?? '';
$redirectUri = $_ENV['GOOGLE_REDIRECT_URI'] ?? '';

if (empty($clientId) || empty($clientSecret) || empty($redirectUri)) {
    die("OAuth credentials not configured. Check your .env file.");
}

// ---- Exchange code for access token ----

$tokenUrl = 'https://oauth2.googleapis.com/token';
$tokenData = [
    'code' => $authCode,
    'client_id' => $clientId,
    'client_secret' => $clientSecret,
    'redirect_uri' => $redirectUri,
    'grant_type' => 'authorization_code',
];

$ch = curl_init($tokenUrl);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => http_build_query($tokenData),
    CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
    CURLOPT_TIMEOUT => 15,
]);
$tokenResponse = curl_exec($ch);
$tokenHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($tokenHttpCode !== 200 || $tokenResponse === false) {
    error_log("Token exchange failed. HTTP $tokenHttpCode. Response: $tokenResponse");
    header('Location: /login.php?error=token_exchange_failed');
    exit;
}

$tokenResult = json_decode($tokenResponse, true);
$accessToken = $tokenResult['access_token'] ?? null;
$idToken = $tokenResult['id_token'] ?? null;

if (empty($accessToken)) {
    error_log("No access token received: " . $tokenResponse);
    header('Location: /login.php?error=no_access_token');
    exit;
}

// ---- Fetch user info from Google ----

$userInfoUrl = 'https://www.googleapis.com/oauth2/v2/userinfo';
$ch = curl_init($userInfoUrl);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => ["Authorization: Bearer $accessToken"],
    CURLOPT_TIMEOUT => 10,
]);
$userInfoResponse = curl_exec($ch);
$userInfoHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($userInfoHttpCode !== 200 || $userInfoResponse === false) {
    error_log("User info fetch failed. HTTP $userInfoHttpCode");
    header('Location: /login.php?error=userinfo_failed');
    exit;
}

$userInfo = json_decode($userInfoResponse, true);
$googleId = $userInfo['id'] ?? null;
$email = $userInfo['email'] ?? '';
$name = $userInfo['name'] ?? '';
$avatarUrl = $userInfo['picture'] ?? '';

if (empty($googleId)) {
    error_log("No Google ID in user info response.");
    header('Location: /login.php?error=no_google_id');
    exit;
}

// ---- Upsert user in database ----

try {
    // Derive username from email (before the @)
    $username = strstr($email, '@', true) ?: $name;
    // Clean username to be filesystem-safe (used for service management)
    $username = preg_replace('/[^a-zA-Z0-9_.-]/', '', $username);

    // Check if user exists by google_id
    $stmt = $db->prepare("SELECT * FROM users WHERE google_id = ?");
    $stmt->execute([$googleId]);
    $existingUser = $stmt->fetch();

    if ($existingUser) {
        // Update existing user
        $stmt = $db->prepare("UPDATE users SET email = ?, avatar_url = ? WHERE google_id = ?");
        $stmt->execute([$email, $avatarUrl, $googleId]);
        $userId = $existingUser['id'];
        $role = $existingUser['role'];
        $username = $existingUser['username'];
    } else {
        // Check if this is the first user — make them admin
        $userCount = $db->query("SELECT COUNT(*) FROM users")->fetchColumn();

        // Check for configured admin email
        $adminEmail = $_ENV['ADMIN_EMAIL'] ?? null;
        if ($adminEmail && $email === $adminEmail) {
            $role = 'admin';
        } elseif ($userCount == 0) {
            $role = 'admin';
        } else {
            $role = 'user';
        }

        $stmt = $db->prepare(
            "INSERT INTO users (username, google_id, email, avatar_url, role) VALUES (?, ?, ?, ?, ?)"
        );
        $stmt->execute([$username, $googleId, $email, $avatarUrl, $role]);
        $userId = $db->lastInsertId();
    }

    // ---- Set session ----
    $_SESSION['user'] = [
        'id' => (int) $userId,
        'username' => $username,
        'email' => $email,
        'role' => $role,
        'avatar_url' => $avatarUrl,
        'google_id' => $googleId,
        'google_access_token' => $accessToken,
    ];

    // ---- Remember Me: extend session to 30 days ----
    $rememberMe = $_SESSION['remember_me'] ?? false;
    unset($_SESSION['remember_me']); // Clean up the temp flag

    if ($rememberMe) {
        $thirtyDays = 60 * 60 * 24 * 30; // 2,592,000 seconds
        $_SESSION['remembered'] = true;
        $_SESSION['session_lifetime'] = $thirtyDays;

        // Extend session cookie
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            session_id(),
            time() + $thirtyDays,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );

        // Extend session GC lifetime
        ini_set('session.gc_maxlifetime', $thirtyDays);
    }

    // Redirect to dashboard
    header('Location: /');
    exit;

} catch (PDOException $e) {
    error_log("Database error during user upsert: " . $e->getMessage());
    header('Location: /login.php?error=db_error');
    exit;
}
