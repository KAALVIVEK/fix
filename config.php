<?php
declare(strict_types=1);

// Minimal Payment Gateway Configuration (pay.t-g.xyz)
// Override via environment variables where available

define('USER_TOKEN', getenv('USER_TOKEN') ?: '0c9de1497ff5444283795008a1591a06');
define('API_BASE_URL', getenv('API_BASE_URL') ?: 'https://pay.t-g.xyz');
define('DEFAULT_ROUTE', is_numeric(getenv('DEFAULT_ROUTE')) ? (int)getenv('DEFAULT_ROUTE') : 1);
// Default redirect URL used when not provided per request
define('REDIRECT_URL', getenv('REDIRECT_URL') ?: 'https://ztrax.in/ztrax/dashboard.html');

function apiUrl(string $path): string {
    return rtrim(API_BASE_URL, '/') . '/' . ltrim($path, '/');
}

function logPaymentEvent(string $event, array $data = []): void {
    $logFile = __DIR__ . '/storage/payment_logs.log';
    $dir = dirname($logFile);
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
    $line = '[' . date('c') . '] ' . $event;
    if (!empty($data)) {
        $line .= ' ' . json_encode($data, JSON_UNESCAPED_SLASHES);
    }
    $line .= PHP_EOL;
    @file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
}