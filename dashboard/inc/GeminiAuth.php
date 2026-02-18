<?php
/**
 * Google AI OAuth Service Account Authentication
 *
 * Handles OAuth 2.0 Service Account (JWT) authentication for Google's
 * Generative Language API (Gemini). Uses a service account JSON key file
 * to generate Bearer tokens — no API key needed.
 *
 * Setup:
 *   1. Create a Service Account in Google Cloud Console
 *   2. Enable the "Generative Language API"
 *   3. Download the JSON key file
 *   4. Set GOOGLE_SERVICE_ACCOUNT_KEY_PATH in .env
 *
 * @package AetherFlow\Inc
 */

class GeminiAuth
{
    private string $keyFilePath;
    private ?array $keyData = null;
    private ?string $cachedToken = null;
    private int $tokenExpiry = 0;

    /** OAuth scope for the Generative Language API */
    private const SCOPE = 'https://www.googleapis.com/auth/generative-language';

    /** Google OAuth token endpoint */
    private const TOKEN_URL = 'https://oauth2.googleapis.com/token';

    /**
     * @param string $keyFilePath Path to the service account JSON key file
     * @throws RuntimeException if key file is missing or invalid
     */
    public function __construct(string $keyFilePath)
    {
        $this->keyFilePath = $keyFilePath;
        $this->loadKeyFile();
    }

    /**
     * Get a valid OAuth Bearer token, refreshing if expired.
     *
     * @return string Bearer token
     * @throws RuntimeException on auth failure
     */
    public function getAccessToken(): string
    {
        // Return cached token if still valid (with 60s safety margin)
        if ($this->cachedToken && time() < ($this->tokenExpiry - 60)) {
            return $this->cachedToken;
        }

        $jwt = $this->createSignedJwt();
        $this->exchangeJwtForToken($jwt);

        return $this->cachedToken;
    }

    /**
     * Load and validate the service account JSON key file.
     */
    private function loadKeyFile(): void
    {
        if (!file_exists($this->keyFilePath)) {
            throw new RuntimeException(
                "Service account key file not found: {$this->keyFilePath}. " .
                "Download it from Google Cloud Console → IAM & Admin → Service Accounts."
            );
        }

        $json = file_get_contents($this->keyFilePath);
        $this->keyData = json_decode($json, true);

        if (!$this->keyData || !isset($this->keyData['client_email'], $this->keyData['private_key'])) {
            throw new RuntimeException(
                "Invalid service account key file. Ensure it contains 'client_email' and 'private_key'."
            );
        }
    }

    /**
     * Create a signed JWT (RS256) for the service account.
     *
     * @return string Signed JWT
     */
    private function createSignedJwt(): string
    {
        $now = time();
        $expiry = $now + 3600; // 1 hour validity

        // JWT Header
        $header = $this->base64UrlEncode(json_encode([
            'alg' => 'RS256',
            'typ' => 'JWT'
        ]));

        // JWT Claims
        $claims = $this->base64UrlEncode(json_encode([
            'iss' => $this->keyData['client_email'],
            'scope' => self::SCOPE,
            'aud' => self::TOKEN_URL,
            'iat' => $now,
            'exp' => $expiry,
        ]));

        // Sign with RSA-SHA256
        $signingInput = "{$header}.{$claims}";
        $privateKey = openssl_pkey_get_private($this->keyData['private_key']);

        if (!$privateKey) {
            throw new RuntimeException('Failed to parse private key from service account key file.');
        }

        $signature = '';
        if (!openssl_sign($signingInput, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Failed to sign JWT: ' . openssl_error_string());
        }

        return $signingInput . '.' . $this->base64UrlEncode($signature);
    }

    /**
     * Exchange the signed JWT for an OAuth access token.
     *
     * @param string $jwt Signed JWT
     * @throws RuntimeException on token exchange failure
     */
    private function exchangeJwtForToken(string $jwt): void
    {
        $postData = http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $jwt
        ]);

        $options = [
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
                'content' => $postData,
                'ignore_errors' => true,
            ]
        ];

        $context = stream_context_create($options);
        $result = file_get_contents(self::TOKEN_URL, false, $context);

        if ($result === false) {
            throw new RuntimeException('Failed to connect to Google OAuth token endpoint.');
        }

        $response = json_decode($result, true);

        if (isset($response['error'])) {
            throw new RuntimeException(
                "OAuth token exchange failed: {$response['error']} — {$response['error_description']}"
            );
        }

        if (!isset($response['access_token'])) {
            throw new RuntimeException('OAuth response missing access_token.');
        }

        $this->cachedToken = $response['access_token'];
        $this->tokenExpiry = time() + ($response['expires_in'] ?? 3600);
    }

    /**
     * Base64 URL-safe encoding (no padding).
     */
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
