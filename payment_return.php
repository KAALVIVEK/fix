<?php
// Byte gateway redirect handler to credit user balance without webhook
// Expected GET params appended by gateway on redirect (example):
// ?order_id=...&status=SUCCESS&amount=...&remark1=UID-... (names may vary)

// Use config logger, but avoid including dashboard.php to prevent JSON headers/400s
require_once __DIR__ . '/config.php';

// Minimal DB credentials (match dashboard.php)
if (!defined('DB_HOST')) { define('DB_HOST', 'localhost'); }
if (!defined('DB_USER')) { define('DB_USER', 'u346622393_vivek'); }
if (!defined('DB_PASS')) { define('DB_PASS', 'Seth#2009'); }
if (!defined('DB_NAME')) { define('DB_NAME', 'u346622393_vivek'); }

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
    $userId  = normalize('remark1', $q);
    if ($userId === '' && isset($q['uid'])) { $userId = trim((string)$q['uid']); }

    // Allow byte_order_status override to bypass status requirement when only order_id is present
    $byte = $_GET['byte_order_status'] ?? '';
    if ($orderId === '') { throw new Exception('Missing order_id'); }

    // Only credit on success-equivalent statuses (or when trusted byte token present)
    $success = ($byte === 'BYTE37091761364125') || in_array($status, ['SUCCESS','TXN_SUCCESS','COMPLETED'], true);

    // Record return event
    logPaymentEvent('payment_return.received', [
        'order_id'=>$orderId, 'status'=>$status, 'amount'=>$amount, 'user_id'=>$userId, 'query'=>$q
    ]);

    $msg = 'Payment failed or cancelled.';
    $ok  = false;
    if ($success) {
        try {
            $conn = connectDB();
            ensurePaymentsTables($conn);
            // Read existing amount if not provided
            $sel = $conn->prepare('SELECT amount,status FROM payments WHERE order_id = ? LIMIT 1');
            $sel->bind_param('s', $orderId);
            $sel->execute();
            $row = $sel->get_result()->fetch_assoc();
            $sel->close();
            $dbAmount = isset($row['amount']) ? (float)$row['amount'] : 0.0;
            $useAmount = ($amount > 0 ? $amount : $dbAmount);
            // As a last resort, try to read amount from payment logs when DB has no mapping
            if ($useAmount <= 0) {
                require_once __DIR__ . '/config.php';
                $logFile = __DIR__ . '/storage/payment_logs.log';
                if (is_readable($logFile)) {
                    $lines = @file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    if ($lines) {
                        for ($i = count($lines) - 1; $i >= 0; $i--) {
                            $line = $lines[$i];
                            if (strpos($line, 'create_order.requested') !== false && strpos($line, $orderId) !== false) {
                                // Extract amount":"XX.XX"
                                if (preg_match('/"amount"\s*:\s*"([0-9]+\.[0-9]{2})"/', $line, $m)) {
                                    $useAmount = (float)$m[1];
                                }
                                break;
                            }
                        }
                    }
                }
            }

            // Mark success and upsert mapping
            $ins = $conn->prepare("INSERT INTO payments (order_id, user_id, amount, status) VALUES (?, ?, ?, 'SUCCESS') ON DUPLICATE KEY UPDATE status='SUCCESS', user_id=IF(VALUES(user_id)<>'' AND user_id='', VALUES(user_id), user_id), amount=IF(VALUES(amount)>0 AND amount=0, VALUES(amount), amount)");
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
        'msg'=>$msg
    ]);
    // Some free hosts block Location redirects for cross-site referrers; render minimal HTML fallback
    echo "<script>location.href='" . htmlspecialchars($dest . $sep . $qs, ENT_QUOTES) . "';</script>";
    exit;

} catch (Throwable $e) {
    // Fallback message
    echo "<script>location.href='dashboard.html?pay_status=error&msg=" . urlencode('Payment processing error') . "';</script>";
    exit;
}