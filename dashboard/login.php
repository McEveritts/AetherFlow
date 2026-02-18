<?php
/**
 * Google OAuth2 Login Page
 *
 * Displays a branded "Sign in with Google" page and initiates the OAuth2 flow.
 * If the user is already authenticated, redirects to the dashboard.
 *
 * @package AetherFlow
 */

// Load environment variables
require_once __DIR__ . '/vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->safeLoad();

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// If already logged in, go to dashboard
if (isset($_SESSION['user']) && !empty($_SESSION['user']['id'])) {
    header('Location: /');
    exit;
}

// Handle "Remember Me" form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['google_login'])) {
    $_SESSION['remember_me'] = isset($_POST['remember_me']);
}

// Build Google OAuth URL
$clientId = $_ENV['GOOGLE_CLIENT_ID'] ?? '';
$redirectUri = $_ENV['GOOGLE_REDIRECT_URI'] ?? '';

if (empty($clientId) || empty($redirectUri)) {
    $configError = true;
} else {
    $configError = false;

    // Generate CSRF state token
    $state = bin2hex(random_bytes(32));
    $_SESSION['oauth2_state'] = $state;

    $scopes = [
        'openid',
        'email',
        'profile',
    ];

    $authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
        'client_id' => $clientId,
        'redirect_uri' => $redirectUri,
        'response_type' => 'code',
        'scope' => implode(' ', $scopes),
        'state' => $state,
        'access_type' => 'offline',
        'prompt' => 'consent',
    ]);

    // If form was submitted, redirect to Google immediately
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['google_login'])) {
        header('Location: ' . $authUrl);
        exit;
    }
}

$version = 'v3.0.1';
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>AetherFlow — Sign In</title>
    <link rel="stylesheet" href="lib/bootstrap/css/bootstrap.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css"
        crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Roboto', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0f0f1a;
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }

        /* Animated gradient background */
        body::before {
            content: '';
            position: fixed;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(ellipse at 20% 50%, rgba(88, 66, 255, 0.15) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 20%, rgba(0, 200, 200, 0.1) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 80%, rgba(255, 66, 146, 0.08) 0%, transparent 50%);
            animation: gradientShift 15s ease-in-out infinite;
            z-index: -1;
        }

        @keyframes gradientShift {

            0%,
            100% {
                transform: translate(0, 0) rotate(0deg);
            }

            33% {
                transform: translate(-2%, 1%) rotate(1deg);
            }

            66% {
                transform: translate(1%, -1%) rotate(-0.5deg);
            }
        }

        .login-container {
            width: 100%;
            max-width: 420px;
            padding: 20px;
        }

        .login-card {
            background: rgba(20, 20, 35, 0.85);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 48px 40px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4),
                0 0 0 1px rgba(255, 255, 255, 0.05) inset;
            text-align: center;
        }

        .login-logo {
            font-size: 42px;
            font-weight: 700;
            background: linear-gradient(135deg, #5842ff, #00c8c8, #ff4292);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }

        .login-subtitle {
            color: #888;
            font-size: 14px;
            margin-bottom: 40px;
            font-weight: 400;
        }

        .login-version {
            color: #555;
            font-size: 11px;
            margin-bottom: 32px;
        }

        .btn-google {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            width: 100%;
            padding: 14px 24px;
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 10px;
            color: #fff;
            font-size: 15px;
            font-weight: 500;
            text-decoration: none;
            transition: all 0.25s ease;
            cursor: pointer;
        }

        .btn-google:hover {
            background: rgba(255, 255, 255, 0.1);
            border-color: rgba(255, 255, 255, 0.2);
            transform: translateY(-1px);
            box-shadow: 0 4px 16px rgba(88, 66, 255, 0.2);
            color: #fff;
            text-decoration: none;
        }

        .btn-google:active {
            transform: translateY(0);
        }

        .btn-google svg {
            width: 20px;
            height: 20px;
            flex-shrink: 0;
        }

        .remember-me {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            margin-top: 16px;
            cursor: pointer;
            user-select: none;
        }

        .remember-me input[type="checkbox"] {
            appearance: none;
            -webkit-appearance: none;
            width: 18px;
            height: 18px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 4px;
            background: rgba(255, 255, 255, 0.05);
            cursor: pointer;
            position: relative;
            transition: all 0.2s ease;
            flex-shrink: 0;
        }

        .remember-me input[type="checkbox"]:checked {
            background: rgba(88, 66, 255, 0.4);
            border-color: rgba(88, 66, 255, 0.6);
        }

        .remember-me input[type="checkbox"]:checked::after {
            content: '\2713';
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 12px;
            color: #fff;
        }

        .remember-me input[type="checkbox"]:hover {
            border-color: rgba(255, 255, 255, 0.35);
        }

        .remember-me span {
            color: #888;
            font-size: 13px;
        }

        .error-box {
            background: rgba(255, 60, 60, 0.1);
            border: 1px solid rgba(255, 60, 60, 0.3);
            border-radius: 10px;
            padding: 16px;
            color: #ff8080;
            font-size: 13px;
            line-height: 1.5;
        }

        .error-box code {
            background: rgba(255, 255, 255, 0.08);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
        }

        .login-footer {
            margin-top: 32px;
            color: #444;
            font-size: 12px;
        }
    </style>
</head>

<body>
    <div class="login-container">
        <div class="login-card">
            <div class="login-logo">AetherFlow</div>
            <div class="login-subtitle">Seedbox Dashboard</div>
            <div class="login-version">
                <?php echo $version; ?>
            </div>

            <?php if ($configError): ?>
                <div class="error-box">
                    <strong>OAuth Not Configured</strong><br>
                    Copy <code>.env.example</code> to <code>.env</code> and set your
                    <code>GOOGLE_CLIENT_ID</code> and <code>GOOGLE_REDIRECT_URI</code>.
                </div>
            <?php else: ?>
                <form method="POST" action="login.php">
                    <button type="submit" name="google_login" value="1" class="btn-google">
                        <!-- Google "G" logo SVG -->
                        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path
                                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"
                                fill="#4285F4" />
                            <path
                                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                                fill="#34A853" />
                            <path
                                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                                fill="#FBBC05" />
                            <path
                                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                                fill="#EA4335" />
                        </svg>
                        Sign in with Google
                    </button>
                    <label class="remember-me">
                        <input type="checkbox" name="remember_me" checked>
                        <span>Remember me for 30 days</span>
                    </label>
                </form>
            <?php endif; ?>

            <div class="login-footer">
                Secured by Google OAuth 2.0
            </div>
        </div>
    </div>
</body>

</html>