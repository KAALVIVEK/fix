<?php
declare(strict_types=1);

// -----------------------------------------------------------------------------
// Core configuration and security helpers
// -----------------------------------------------------------------------------

// Environment helpers
function env(string $key, ?string $default = null): ?string {
    $val = getenv($key);
    return ($val === false || $val === '') ? $default : $val;
}

// Application secret for HMAC signing (tokens, cookies)
function getAppSecret(): string {
    $env = env('APP_SECRET');
    if ($env) { return $env; }
    $dir = __DIR__ . '/storage';
    if (!is_dir($dir)) { @mkdir($dir, 0775, true); }
    $path = $dir . '/app.key';
    if (is_readable($path)) {
        $key = trim((string)@file_get_contents($path));
        if ($key !== '') { return $key; }
    }
    try { $rand = bin2hex(random_bytes(32)); } catch (Throwable $e) { $rand = bin2hex(openssl_random_pseudo_bytes(32)); }
    @file_put_contents($path, $rand, LOCK_EX);
    return $rand;
}
define('APP_SECRET', getAppSecret());

// Minimal Payment Gateway Configuration (pay.t-g.xyz)
define('USER_TOKEN', env('USER_TOKEN', '0c9de1497ff5444283795008a1591a06'));
define('API_BASE_URL', env('API_BASE_URL', 'https://pay.t-g.xyz'));
define('DEFAULT_ROUTE', is_numeric(env('DEFAULT_ROUTE', '1')) ? (int)env('DEFAULT_ROUTE', '1') : 1);
// Default redirect URL used when not provided per request
define('REDIRECT_URL', env('REDIRECT_URL', 'https://ztrax.in/ztrax/dashboard.html'));

// Database configuration (prefer env; fall back to constants if previously defined)
if (!defined('DB_HOST')) { define('DB_HOST', env('DB_HOST', 'localhost')); }
if (!defined('DB_USER')) { define('DB_USER', env('DB_USER', 'u346622393_vivek')); }
if (!defined('DB_PASS')) { define('DB_PASS', env('DB_PASS', 'Seth#2009')); }
if (!defined('DB_NAME')) { define('DB_NAME', env('DB_NAME', 'u346622393_vivek')); }

// CORS allowlist (comma-separated); when empty, only same-origin is allowed
define('ALLOWED_ORIGINS', env('ALLOWED_ORIGINS', ''));

function currentOrigin(): string {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? '';
    return ($host !== '') ? ($scheme . '://' . $host) : '';
}

function isOriginAllowed(?string $origin): bool {
    if (!$origin) { return false; }
    $allowed = array_filter(array_map('trim', explode(',', (string)ALLOWED_ORIGINS)));
    if (empty($allowed)) {
        // Allow same-origin only when list is empty
        return $origin === currentOrigin();
    }
    return in_array($origin, $allowed, true);
}

function applySecurityHeaders(string $contentType = 'application/json'): void {
    // Basic hardening headers
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('X-XSS-Protection: 0'); // modern browsers ignore; CSP preferred
    // HSTS for HTTPS deployments (or force via env)
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    if ($isHttps || env('FORCE_HSTS')) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
    // Avoid caching of API responses
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    // Extra hardening
    header('X-Permitted-Cross-Domain-Policies: none');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
    header('Cross-Origin-Resource-Policy: same-origin');
    if ($contentType) {
        header('Content-Type: ' . $contentType . '; charset=UTF-8');
    }
    // Conservative CSP appropriate for JSON/HTML responses from PHP endpoints
    // Note: Avoid strict CSP on large HTML apps with inline scripts; set per-page if needed
    if (stripos($contentType, 'json') !== false) {
        header("Content-Security-Policy: default-src 'none'; base-uri 'self'; frame-ancestors 'none';");
    }
}

function applyCors(bool $allowCredentials = true): void {
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin && isOriginAllowed($origin)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        if ($allowCredentials) { header('Access-Control-Allow-Credentials: true'); }
    } else {
        // For same-origin requests without Origin header keep silent; for cross-origin disallow
        // You may set ALLOWED_ORIGINS to enable specific origins
    }
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    header('Access-Control-Max-Age: 600');
}

// Token utilities (HMAC-SHA256; Base64URL)
function b64u(string $data): string { return rtrim(strtr(base64_encode($data), '+/', '-_'), '='); }
function b64u_dec(string $data): string { return base64_decode(strtr($data, '-_', '+/')); }

function createAuthToken(string $userId, string $role, int $ttlSeconds = 1800): string {
    $header = b64u(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload = b64u(json_encode(['uid' => $userId, 'role' => $role, 'iat' => time(), 'exp' => time() + $ttlSeconds]));
    $sig = hash_hmac('sha256', $header . '.' . $payload, APP_SECRET, true);
    return $header . '.' . $payload . '.' . b64u($sig);
}

function verifyAuthToken(?string $token): ?array {
    if (!$token || !is_string($token)) { return null; }
    $parts = explode('.', $token);
    if (count($parts) !== 3) { return null; }
    [$h, $p, $s] = $parts;
    $calc = b64u(hash_hmac('sha256', $h . '.' . $p, APP_SECRET, true));
    if (!hash_equals($calc, $s)) { return null; }
    $data = json_decode(b64u_dec($p), true);
    if (!is_array($data) || !isset($data['uid'], $data['role'], $data['exp'])) { return null; }
    if ((int)$data['exp'] < time()) { return null; }
    return $data;
}

function setAuthCookie(string $token): void {
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    setcookie('ztrax_token', $token, [
        'expires' => time() + 1800,
        'path' => '/',
        'domain' => '',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function getTokenFromRequest(): ?string {
    $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if ($hdr && preg_match('/^Bearer\s+(.+)$/i', $hdr, $m)) { return trim($m[1]); }
    if (!empty($_COOKIE['ztrax_token'])) { return (string)$_COOKIE['ztrax_token']; }
    return null;
}

function apiUrl(string $path): string {
    return rtrim(API_BASE_URL, '/') . '/' . ltrim($path, '/');
}

function logPaymentEvent(string $event, array $data = []): void {
    $logFile = __DIR__ . '/storage/payment_logs.log';
    $dir = dirname($logFile);
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
    // Avoid logging highly sensitive values
    if (isset($data['remark1'])) {
        $data['remark1'] = substr((string)$data['remark1'], 0, 8) . '***';
    }
    $line = '[' . date('c') . '] ' . $event;
    if (!empty($data)) {
        $line .= ' ' . json_encode($data, JSON_UNESCAPED_SLASHES);
    }
    $line .= PHP_EOL;
    @file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
}

// -----------------------------------------------------------------------------
// Client response encryption helpers (AES-GCM with client-provided key)
// -----------------------------------------------------------------------------

function cryptoStorageDir(): string {
    $dir = __DIR__ . '/storage/crypto_keys';
    if (!is_dir($dir)) { @mkdir($dir, 0775, true); }
    return $dir;
}

function clientKeyPathForUid(string $uid): string {
    $safe = preg_replace('/[^A-Za-z0-9._\-]/', '_', $uid);
    return cryptoStorageDir() . "/" . $safe . '.key';
}

function setClientEncKeyForUid(string $uid, string $base64UrlKey): bool {
    // Validate base64url characters and reasonable length
    if (!preg_match('/^[A-Za-z0-9_\-]{16,128}$/', $base64UrlKey)) { return false; }
    $raw = b64u_dec($base64UrlKey);
    if ($raw === '' || $raw === false) { return false; }
    $len = strlen($raw);
    if (!in_array($len, [16,24,32], true)) { return false; } // AES-128/192/256
    $path = clientKeyPathForUid($uid);
    return @file_put_contents($path, $base64UrlKey, LOCK_EX) !== false;
}

function getClientEncKeyForUid(string $uid): ?string {
    $path = clientKeyPathForUid($uid);
    if (!is_readable($path)) { return null; }
    $b64 = trim((string)@file_get_contents($path));
    if ($b64 === '') { return null; }
    $raw = b64u_dec($b64);
    if ($raw === '' || $raw === false) { return null; }
    $len = strlen($raw);
    if (!in_array($len, [16,24,32], true)) { return null; }
    return $raw;
}

function deleteClientEncKeyForUid(string $uid): bool {
    $path = clientKeyPathForUid($uid);
    if (is_file($path)) { return @unlink($path); }
    return true;
}

function encryptJsonForClient(string $uid, string $json): ?string {
    $key = getClientEncKeyForUid($uid);
    if ($key === null) { return null; }
    try {
        $iv = random_bytes(12);
    } catch (Throwable $e) {
        $iv = openssl_random_pseudo_bytes(12);
    }
    $tag = '';
    $ciphertext = openssl_encrypt($json, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($ciphertext === false) {
        // Retry with AES-128/192 depending on key length
        $kl = strlen($key);
        $method = $kl === 16 ? 'aes-128-gcm' : ($kl === 24 ? 'aes-192-gcm' : 'aes-256-gcm');
        $ciphertext = openssl_encrypt($json, $method, $key, OPENSSL_RAW_DATA, $iv, $tag);
        if ($ciphertext === false) { return null; }
    }
    $env = [
        'enc' => 1,
        'v' => 1,
        'alg' => 'A' . (strlen($key)*8) . 'GCM',
        'iv' => b64u($iv),
        'ct' => b64u($ciphertext),
        'tag' => b64u($tag),
    ];
    return json_encode($env, JSON_UNESCAPED_SLASHES);
}

// -----------------------------------------------------------------------------
// Request signing (HMAC-SHA256) to resist tampering/replay
// Client must send headers: X-Client-TS, X-Client-Nonce, X-Client-Sign (base64url)
// Signature is HMAC over "{ts}|{nonce}|{rawBody}" using the stored client key
// -----------------------------------------------------------------------------

function getHeader(string $name): ?string {
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    return isset($_SERVER[$key]) ? (string)$_SERVER[$key] : null;
}

function noncesDir(): string {
    $dir = __DIR__ . '/storage/nonces';
    if (!is_dir($dir)) { @mkdir($dir, 0775, true); }
    return $dir;
}

function noncePath(string $uid): string {
    $safe = preg_replace('/[^A-Za-z0-9._\-]/', '_', $uid);
    return noncesDir() . '/' . $safe . '.json';
}

function checkAndStoreNonce(string $uid, string $nonce, int $ts, int $ttlSeconds = 600): bool {
    $path = noncePath($uid);
    $now = time();
    $list = [];
    if (is_file($path)) {
        $raw = @file_get_contents($path);
        $parsed = $raw ? json_decode($raw, true) : null;
        if (is_array($parsed)) { $list = $parsed; }
    }
    // Purge expired
    $new = [];
    foreach ($list as $n => $t) {
        if (($now - (int)$t) <= $ttlSeconds) { $new[$n] = (int)$t; }
    }
    if (isset($new[$nonce])) { return false; }
    $new[$nonce] = $ts;
    // Bound size to avoid unbounded growth
    if (count($new) > 500) { $new = array_slice($new, -400, null, true); }
    @file_put_contents($path, json_encode($new), LOCK_EX);
    return true;
}

function verifySignedRequest(string $uid, string $rawBody, int $skewSeconds = 180): bool {
    if ($uid === '') { return false; }
    $keyRaw = getClientEncKeyForUid($uid);
    if ($keyRaw === null) { return false; }
    $tsHeader = getHeader('X-Client-TS');
    $nonce = getHeader('X-Client-Nonce');
    $sigHeader = getHeader('X-Client-Sign');
    if ($tsHeader === null || $nonce === null || $sigHeader === null) { return false; }
    $ts = (int)$tsHeader;
    $now = time();
    if ($ts < $now - $skewSeconds || $ts > $now + $skewSeconds) { return false; }
    // Replay guard
    if (!checkAndStoreNonce($uid, $nonce, $ts, $skewSeconds * 2)) { return false; }
    $data = $ts . '|' . $nonce . '|' . $rawBody;
    $calc = hash_hmac('sha256', $data, $keyRaw, true);
    $calcB64u = b64u($calc);
    return hash_equals($calcB64u, $sigHeader);
}
