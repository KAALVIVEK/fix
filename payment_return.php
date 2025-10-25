<?php
// Byte gateway redirect handler to credit user balance without webhook
// Hardened: validates HMAC token attached to redirect_url, no debug query echo

require_once __DIR__ . '/config.php';

// Minimal DB credentials sourced via config.php
if (!defined('DB_HOST')) { define('DB_HOST', DB_HOST); }
if (!defined('DB_USER')) { define('DB_USER', DB_USER); }
if (!defined('DB_PASS')) { define('DB_PASS', DB_PASS); }
if (!defined('DB_NAME')) { define('DB_NAME', DB_NAME); }

function connectDB() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($conn->connect_error) {
        throw new Exception('Database connection failed: ' . $conn->connect_error);
    }
    return $conn;
}

function ensurePaymentsTables($conn) {
    $conn->query("CREATE TABLE IF NOT EXISTS payments (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        order_id VARCHAR(64) UNIQUE,
        txn_id VARCHAR(64) NULL,
        user_id VARCHAR(36) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'INIT',
        raw_response MEDIUMTEXT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    // Add missing columns if table existed before
    $col = $conn->query("SHOW COLUMNS FROM payments LIKE 'raw_response'");
    if ($col && $col->num_rows === 0) { @$conn->query("ALTER TABLE payments ADD COLUMN raw_response MEDIUMTEXT NULL"); }
    $col2 = $conn->query("SHOW COLUMNS FROM payments LIKE 'updated_at'");
    if ($col2 && $col2->num_rows === 0) { @$conn->query("ALTER TABLE payments ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"); }
}

// Return HTML to the browser on GET; do not force JSON
header_remove('Content-Type');
header('Content-Type: text/html; charset=UTF-8');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');

function normalize($key, $arr) {
    $map = [
        'order_id' => ['order_id','orderId','ORDERID'],
        'status'   => ['status','STATUS','orderStatus'],
        'amount'   => ['amount','txn_amount','TXNAMOUNT','txnAmount','AMOUNT'],
        'remark1'  => ['remark1','REMARK1'],
        'remark2'  => ['remark2','REMARK2'],
    ];
    foreach ($map[$key] as $k) { if (isset($arr[$k])) return trim((string)$arr[$k]); }
    return '';
}

try {
    $q = $_GET;
    // Accept local hints embedded in redirect_url
    $orderId = normalize('order_id', $q);
    if ($orderId === '') {
        $lo = trim((string)($q['local_order_id'] ?? ''));
        // Strip accidental 'payload-' prefix if present
        if (stripos($lo, 'payload-') === 0) { $lo = trim(substr($lo, 8)); }
        $orderId = $lo;
    }
    $status  = strtoupper(normalize('status', $q));
    $amountV = normalize('amount', $q);
    if ($amountV === '' && isset($q['amt'])) { $amountV = (string)$q['amt']; }
    $amount  = is_numeric($amountV) ? (float)$amountV : 0.0;
    // user id is now stored in DB mapping created during order; do not trust query for uid
    $userId = '';

    // Verify HMAC signature if present (we will add it during create order)
    $sig = isset($q['sig']) ? (string)$q['sig'] : '';
    $toSign = $orderId . '|' . number_format($amount, 2, '.', '');
    $calc = b64u(hash_hmac('sha256', $toSign, APP_SECRET, true));
    if (!$sig || !hash_equals($calc, $sig)) {
        // If signature missing or invalid, do not credit; just redirect back with failure
        logPaymentEvent('payment_return.invalid_sig', ['order_id'=>$orderId]);
        $dest = '/ztrax/dashboard.html';
        $sep = (strpos($dest,'?')!==false?'&':'?');
        $qs = http_build_query(['pay_status'=>'failed','order_id'=>$orderId]);
        echo "<script>location.href='" . htmlspecialchars($dest . $sep . $qs, ENT_QUOTES) . "';</script>";
        exit;
    }

    if ($orderId === '') { throw new Exception('Missing order_id'); }

    // Only credit on success-equivalent statuses
    $success = in_array($status, ['SUCCESS','TXN_SUCCESS','COMPLETED'], true);

    // Record return event
    logPaymentEvent('payment_return.received', [
        'order_id'=>$orderId, 'status'=>$status
    ]);

    $msg = 'Payment failed or cancelled.';
    $ok  = false;
    if ($success) {
        try {
            $conn = connectDB();
            ensurePaymentsTables($conn);
            // Read existing amount if not provided
            $sel = $conn->prepare('SELECT user_id, amount, status FROM payments WHERE order_id = ? LIMIT 1');
            $sel->bind_param('s', $orderId);
            $sel->execute();
            $row = $sel->get_result()->fetch_assoc();
            $sel->close();
            $dbAmount = isset($row['amount']) ? (float)$row['amount'] : 0.0;
            $userId = isset($row['user_id']) ? (string)$row['user_id'] : '';
            $useAmount = ($amount > 0 ? $amount : $dbAmount);
            // Do not attempt to parse logs for amounts anymore (avoid query leakage)

            // Mark success and upsert mapping
            $ins = $conn->prepare("INSERT INTO payments (order_id, user_id, amount, status) VALUES (?, ?, ?, 'SUCCESS') ON DUPLICATE KEY UPDATE status='SUCCESS'");
            $ins->bind_param('ssd', $orderId, $userId, $useAmount);
            $ins->execute();
            $ins->close();

            if ($userId !== '' && $useAmount > 0) {
                $credit = $conn->prepare('UPDATE users SET balance = balance + ? WHERE user_id = ?');
                $credit->bind_param('ds', $useAmount, $userId);
                $credit->execute();
                $credit->close();
                $ok = true;
                $msg = 'Payment successful. Balance credited.';
            } else {
                $msg = 'Payment successful, but missing user/amount for credit.';
            }
            $conn->close();
        } catch (Throwable $e) {
            $msg = 'Payment processed, but DB error occurred.';
        }
    }

    // Redirect back to dashboard with status message
    $dest = '/ztrax/dashboard.html';
    $sep = (strpos($dest,'?')!==false?'&':'?');
    $qs = http_build_query([
        'pay_status'=>$success?'success':'failed',
        'order_id'=>$orderId,
        // hide details in URL; short status only
    ]);
    // Some free hosts block Location redirects for cross-site referrers; render minimal HTML fallback
    echo "<script>location.href='" . htmlspecialchars($dest . $sep . $qs, ENT_QUOTES) . "';</script>";
    exit;

} catch (Throwable $e) {
    // Fallback message
    echo "<script>location.href='dashboard.html?pay_status=error';</script>";
    exit;
}