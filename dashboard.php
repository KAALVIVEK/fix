<?php
// =========================================================================
// ZTRAX DASHBOARD API - SECURE PHP BACKEND
// =========================================================================

// Set headers for CORS and JSON response
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json; charset=UTF-8");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// --- 1. DATABASE CONFIGURATION (LIVE CREDENTIALS) ---
define('DB_HOST', 'localhost');
define('DB_USER', 'u346622393_vivek');
define('DB_PASS', 'Seth#2009');
define('DB_NAME', 'u346622393_vivek');

// --- 2. CORE UTILITIES ---

/**
 * Connects to the database or throws an Exception on failure.
 */
function connectDB() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    ensureDashboardCoreTables($conn);
    return $conn;
}

/** Creates core tables used by dashboard APIs if missing */
function ensureDashboardCoreTables($conn) {
    // users
    $conn->query("CREATE TABLE IF NOT EXISTS users (
        user_id VARCHAR(36) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        name VARCHAR(100) NOT NULL DEFAULT 'Ztrax User',
        role ENUM('user','reseller','admin','owner') NOT NULL DEFAULT 'user',
        balance DECIMAL(10,2) NOT NULL DEFAULT 0.00,
        referred_by_id VARCHAR(36) NULL,
        status ENUM('Active','Blocked') NOT NULL DEFAULT 'Active',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id),
        UNIQUE KEY uniq_users_email (email),
        KEY idx_users_referred_by (referred_by_id),
        KEY idx_users_role (role)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // licenses
    $conn->query("CREATE TABLE IF NOT EXISTS licenses (
        license_id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        key_string VARCHAR(64) NOT NULL,
        game_package VARCHAR(100) NOT NULL,
        duration VARCHAR(16) NOT NULL,
        max_devices INT UNSIGNED NOT NULL DEFAULT 1,
        devices_used INT UNSIGNED NOT NULL DEFAULT 0,
        linked_device_id VARCHAR(64) NULL,
        status ENUM('Issued','Active','Banned','Deleted') NOT NULL DEFAULT 'Issued',
        creator_id VARCHAR(36) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires DATETIME NULL,
        PRIMARY KEY (license_id),
        UNIQUE KEY uniq_licenses_key_string (key_string),
        KEY idx_licenses_creator (creator_id),
        KEY idx_licenses_status (status),
        KEY idx_licenses_created_at (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // referrals
    $conn->query("CREATE TABLE IF NOT EXISTS referrals (
        code CHAR(8) NOT NULL,
        initial_balance DECIMAL(10,2) NOT NULL DEFAULT 0.00,
        max_role ENUM('user','reseller','admin') NOT NULL DEFAULT 'user',
        creator_id VARCHAR(36) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (code),
        KEY idx_referrals_creator (creator_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // service flags
    $conn->query("CREATE TABLE IF NOT EXISTS service_flags (
        flag VARCHAR(64) PRIMARY KEY,
        value VARCHAR(16) NOT NULL DEFAULT '0',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // system_keys
    $conn->query("CREATE TABLE IF NOT EXISTS system_keys (
        key_string VARCHAR(64) PRIMARY KEY,
        name VARCHAR(128) NOT NULL,
        created_by_id VARCHAR(36) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'Generated',
        duration VARCHAR(16) NULL,
        bucket VARCHAR(64) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // pricing
    $conn->query("CREATE TABLE IF NOT EXISTS pricing (
        duration_id VARCHAR(16) NOT NULL,
        bucket VARCHAR(64) NULL,
        price DECIMAL(10,2) NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_bucket_duration (bucket, duration_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // api_keys
    $conn->query("CREATE TABLE IF NOT EXISTS api_keys (
        api_key CHAR(40) PRIMARY KEY,
        amount DECIMAL(10,2) NOT NULL,
        created_by_id VARCHAR(36) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // products (owner-managed)
    $conn->query("CREATE TABLE IF NOT EXISTS products (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        name VARCHAR(64) NOT NULL,
        status ENUM('active','inactive') NOT NULL DEFAULT 'active',
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uniq_products_name (name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // durations per product
    $conn->query("CREATE TABLE IF NOT EXISTS durations (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        product_id INT UNSIGNED NOT NULL,
        duration_name VARCHAR(32) NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY uniq_product_duration (product_id, duration_name),
        KEY idx_durations_product (product_id),
        CONSTRAINT fk_durations_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    // keys pool per product
    $conn->query("CREATE TABLE IF NOT EXISTS keys_pool (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        product_id INT UNSIGNED NOT NULL,
        key_value VARCHAR(64) NOT NULL,
        default_duration VARCHAR(16) NULL,
        is_used TINYINT(1) NOT NULL DEFAULT 0,
        used_at DATETIME NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uniq_keys_pool_value (key_value),
        KEY idx_keys_pool_product (product_id),
        KEY idx_keys_pool_used (is_used),
        CONSTRAINT fk_keys_pool_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE ON UPDATE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

/**
 * Checks if the current user role is sufficient for the required action.
 */
function checkRole($currentRole, $requiredRole) {
    $roles = ['user' => 1, 'reseller' => 2, 'admin' => 3, 'owner' => 4];
    if (!isset($roles[$currentRole]) || !isset($roles[$requiredRole])) {
        return false;
    }
    return $roles[$currentRole] >= $roles[$requiredRole];
}


// --- 3. INPUT HANDLING ---
$inputJSON = file_get_contents('php://input');
$input = json_decode($inputJSON, true);
if (!is_array($input)) { $input = $_POST ?? []; }

// Determine action via body first, then query param; fallback for Paytm callbacks
$action = $input['action'] ?? ($_GET['action'] ?? null);
if (!$action && (isset($input['ORDERID']) || isset($_REQUEST['ORDERID']))) {
    $action = 'paytm_webhook';
}

if (!$action) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Invalid API request format.']);
    exit();
}

$user_id = $input['user_id'] ?? null;
$role = $input['role'] ?? null;

// --- 4. API ROUTING ---
try {
    switch ($action) {
        // Paytm UPI QR flow handled via separate payment.php; legacy API removed
        case 'load_initial_data':
            loadInitialData($user_id);
            break;
        
        case 'load_licenses':
            loadLicenses($user_id, $role);
            break;
        case 'create_license':
            createLicense($user_id, $role, $input);
            break;
        case 'reset_license':
            resetLicense($user_id, $role, $input['license_id']);
            break;
        case 'update_license_details':
            updateLicenseDetails($user_id, $role, $input);
            break;
        case 'ban_license':
            banLicense($user_id, $role, $input['license_id']);
            break;
        case 'delete_license':
            deleteLicense($user_id, $role, $input['license_id']);
            break;
        
        case 'load_referrals':
            loadReferrals($role);
            break;
        case 'create_referral':
            createReferral($user_id, $role, $input);
            break;
        case 'delete_referral':
            deleteReferral($user_id, $role, $input['code'] ?? '');
            break;
        case 'load_managed_users':
            loadManagedUsers($user_id, $role);
            break;
        case 'admin_add_balance':
            adminAddBalance($user_id, $role, $input['target_user_id'], (float)($input['amount'] ?? 0));
            break;
        case 'admin_change_role':
            adminChangeRole($user_id, $role, $input['target_user_id'], $input['new_role'] ?? 'user');
            break;
        case 'load_license_info':
            loadLicenseInfo($user_id, $role, (int)($input['license_id'] ?? 0));
            break;
        case 'admin_reset_client_key':
            adminResetClientKey($user_id, $role, $input['license_id']);
            break;
        case 'admin_reset_all_licenses':
            adminResetAllLicenses($user_id, $role);
            break;
        case 'admin_delete_all_licenses':
            adminDeleteAllLicenses($user_id, $role);
            break;
        case 'admin_extend_all_licenses':
            adminExtendAllLicenses($user_id, $role, (float)($input['extra_days'] ?? 0));
            break;
        
        case 'load_system_keys':
            loadSystemKeys($role);
            break;
        case 'generate_system_key':
            generateSystemKey($user_id, $role, $input);
            break;
        case 'owner_generate_api_key':
            ownerGenerateApiKey($user_id, $role, (float)($input['amount'] ?? 0));
            break;

        case 'get_service_status':
            getServiceStatus();
            break;
        case 'owner_set_key_generation':
            ownerSetKeyGeneration($user_id, $role, (bool)($input['enabled'] ?? false));
            break;

        case 'reset_user_login_key':
            resetUserLoginKey($user_id, $role, $input['target_user_id']);
            break;
        case 'block_user':
            blockUser($user_id, $role, $input['target_user_id']);
            break;
        case 'delete_user_account':
            deleteUserAccount($user_id, $role, $input['target_user_id']);
            break;
        case 'change_password':
            changePassword($user_id, $input['current_password'] ?? '', $input['new_password'] ?? '');
            break;
        case 'check_license':
            checkLicense($user_id, $role, (int)($input['license_id'] ?? 0), $input['device_id'] ?? null);
            break;
        case 'extend_license_time':
            extendLicenseTime($user_id, $role, (int)($input['license_id'] ?? 0), (float)($input['extra_days'] ?? 0));
            break;
        case 'owner_reset_all_licenses':
            ownerResetAllLicenses($user_id, $role);
            break;
        case 'owner_delete_all_licenses':
            ownerDeleteAllLicenses($user_id, $role);
            break;
        case 'owner_extend_all_licenses':
            ownerExtendAllLicenses($user_id, $role, (float)($input['extra_days'] ?? 0));
            break;

        case 'owner_bulk_add_keys':
            ownerBulkAddKeys(
                $user_id,
                $role,
                $input['keys'] ?? [],
                $input['name'] ?? 'SYSTEM',
                $input['bucket'] ?? null,
                $input['duration'] ?? null
            );
            break;
        case 'get_pricing':
            getPricing($role);
            break;
        case 'owner_update_pricing':
            ownerUpdatePricing($user_id, $role, $input['pricing'] ?? []);
            break;

        case 'get_catalog':
            getCatalog($role);
            break;

        // Product & Pricing management
        case 'owner_list_products':
            ownerListProducts($user_id, $role);
            break;
        case 'owner_create_product':
            ownerCreateProduct($user_id, $role, trim($input['name'] ?? ''));
            break;
        case 'owner_update_product':
            ownerUpdateProduct($user_id, $role, (int)($input['id'] ?? 0), trim($input['name'] ?? ''), trim($input['status'] ?? 'active'));
            break;
        case 'owner_delete_product':
            ownerDeleteProduct($user_id, $role, (int)($input['id'] ?? 0));
            break;
        case 'owner_list_durations':
            ownerListDurations($user_id, $role, (int)($input['product_id'] ?? 0));
            break;
        case 'owner_upsert_duration':
            ownerUpsertDuration($user_id, $role, (int)($input['product_id'] ?? 0), trim($input['duration_name'] ?? ''), (float)($input['price'] ?? 0));
            break;
        case 'owner_delete_duration':
            ownerDeleteDuration($user_id, $role, (int)($input['id'] ?? 0));
            break;
        case 'owner_bulk_add_keys_pool':
            ownerBulkAddKeysPool($user_id, $role, (int)($input['product_id'] ?? 0), $input['keys'] ?? [], trim($input['default_duration'] ?? ''));
            break;

        // User-facing product/duration catalog
        case 'list_products':
            listProducts($role);
            break;
        case 'list_durations':
            listDurations($role, (int)($input['product_id'] ?? 0));
            break;

        // Token-based API (for bots/external integrations)
        case 'api_create_license':
            apiCreateLicense($input);
            break;
        case 'api_reset_license':
            apiResetLicense($input);
            break;
        case 'api_delete_license':
            apiDeleteLicense($input);
            break;
            
        default:
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Unknown API action specified.']);
            break;
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server Error: ' . $e->getMessage()]);
}


// --- 5. FUNCTION IMPLEMENTATIONS ---

/**
 * Loads essential user data (role, balance, active keys) for dashboard rendering.
 */
function loadInitialData($user_id) {
    $conn = connectDB();
    
    $stmt = $conn->prepare("SELECT role, balance, email, referred_by_id FROM users WHERE user_id = ?");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $userData = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$userData) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'User data not found. Please re-login.']);
        $conn->close();
        return;
    }

    $stmt = $conn->prepare("SELECT COUNT(*) as active_keys FROM licenses WHERE creator_id = ? AND status != 'Deleted'");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $keyData = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    // Derive a rough key rate from recent activity (keys created in last 10 minutes)
    $stmt = $conn->prepare("SELECT COUNT(*) AS c FROM licenses WHERE created_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)");
    $stmt->execute();
    $kr = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    $key_rate = round(($kr['c'] ?? 0) / 10, 2);

    // Recent activity (10 most recent)
    $actRes = $conn->query("SELECT created_at AS ts, license_id, status FROM licenses ORDER BY created_at DESC LIMIT 10");
    $activity = [];
    if ($actRes) {
        while ($r = $actRes->fetch_assoc()) { $activity[] = $r; }
    }

    $data = [
        'role' => $userData['role'],
        'balance' => (float)$userData['balance'],
        'active_keys' => (int)$keyData['active_keys'],
        'key_rate' => $key_rate,
        'email' => $userData['email'],
        'referred_by_status' => $userData['referred_by_id'],
        'recent_activity' => $activity
    ];

    echo json_encode(['success' => true, 'data' => $data]);
    $conn->close();
}


/**
 * Helper function to define the visibility filter for licenses based on user role.
 */
function getLicenseFilterSQL($current_user_id, $current_role) {
    if ($current_role === 'owner') {
        return ['WHERE 1=1', []];
    } elseif ($current_role === 'admin') {
        $conn = connectDB();
        $stmt = $conn->prepare("SELECT user_id FROM users WHERE referred_by_id = ? OR user_id = ?");
        $stmt->bind_param("ss", $current_user_id, $current_user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $managed_ids = [$current_user_id];
        while ($row = $result->fetch_assoc()) {
            $managed_ids[] = $row['user_id'];
        }
        $in_clause = implode("','", $managed_ids);
        return ["WHERE creator_id IN ('$in_clause')", []];
        
    } else {
        return ['WHERE creator_id = ?', [$current_user_id]];
    }
}


/**
 * Loads licenses based on the user's role and visibility rules.
 */
function loadLicenses($user_id, $role) {
    try {
        $conn = connectDB();
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'DB Connection Error: ' . $e->getMessage()]);
        return;
    }
    
    list($where_clause, $params) = getLicenseFilterSQL($user_id, $role);
    
    $sql = "SELECT license_id, key_string, game_package, duration, max_devices, devices_used, status, created_at, expires FROM licenses $where_clause ORDER BY created_at DESC";
    
    $result = false;
    
    try {
        if (!empty($params)) {
            $stmt = $conn->prepare($sql);
            if (!$stmt) {
                throw new Exception("SQL Prepare failed: " . $conn->error);
            }
            $stmt->bind_param(str_repeat('s', count($params)), ...$params);
            $stmt->execute();
            $result = $stmt->get_result();
            $stmt->close();
        } else {
            $result = $conn->query($sql);
            if (!$result) {
                 throw new Exception("SQL Query failed: " . $conn->error);
            }
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'License Load Failed: ' . $e->getMessage()]);
        $conn->close();
        return;
    }
    
    $licenses = [];
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $licenses[] = $row;
        }
    }
    
    echo json_encode(['success' => true, 'data' => $licenses]);
    $conn->close();
}


/**
 * Maps duration id to hours for expiry computation.
 */
function getDurationHours($duration_id) {
    // Support custom formats: h:<hours> or d:<days>
    if (is_string($duration_id)) {
        if (preg_match('/^h:(\d{1,5})$/', $duration_id, $m)) {
            return max(1, (int)$m[1]);
        }
        if (preg_match('/^d:(\d{1,5})$/', $duration_id, $m)) {
            return max(1, (int)$m[1]) * 24;
        }
    }
    $map = [
        'opt1' => 5,     // 5 hours
        'opt2' => 24,    // 1 day
        'opt3' => 72,    // 3 days
        'opt4' => 168,   // 7 days
        'opt5' => 360,   // 15 days
        'opt6' => 720,   // 30 days
        'opt7' => 1440,  // 60 days
    ];
    return isset($map[$duration_id]) ? (int)$map[$duration_id] : 24;
}

/** Service flags helpers **/
function ensureServiceFlagsTable($conn) {
    $conn->query("CREATE TABLE IF NOT EXISTS service_flags (flag VARCHAR(64) PRIMARY KEY, value VARCHAR(16) NOT NULL DEFAULT '0', updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)");
}

function ensurePaymentsTables($conn) {
    $conn->query("CREATE TABLE IF NOT EXISTS payments (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        order_id VARCHAR(64) UNIQUE,
        txn_id VARCHAR(64) NULL,
        user_id VARCHAR(36) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'INIT',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

function createPaytmOrder($user_id, $role, $amount) {
    require_once __DIR__ . '/api/config.php';
    require_once __DIR__ . '/paytm_checksum.php';
    if (!checkRole($role, 'user')) { http_response_code(403); echo json_encode(['success'=>false,'message'=>'Authorization required.']); return; }
    if ($amount <= 0) { http_response_code(400); echo json_encode(['success'=>false,'message'=>'Invalid amount.']); return; }
    $conn = connectDB();
    ensurePaymentsTables($conn);
    $order_id = 'ORD' . date('YmdHis') . strtoupper(substr(md5(uniqid('', true)), 0, 8));
    $stmt = $conn->prepare("INSERT INTO payments (order_id, user_id, amount, status) VALUES (?, ?, ?, 'INIT')");
    $stmt->bind_param("ssd", $order_id, $user_id, $amount);
    if (!$stmt->execute()) { http_response_code(500); echo json_encode(['success'=>false,'message'=>'Failed to create order.']); $conn->close(); return; }
    // Prepare initiateTransaction payload
    $txnAmount = number_format($amount, 2, '.', '');
    $body = [
        'requestType' => 'Payment',
        'mid' => PAYTM_MID,
        'websiteName' => PAYTM_WEBSITE,
        'orderId' => $order_id,
        'callbackUrl' => PAYTM_CALLBACK_URL,
        'txnAmount' => [ 'value' => $txnAmount, 'currency' => 'INR' ],
        'userInfo' => [ 'custId' => $user_id ]
    ];
    $checksum = PaytmChecksum::generateSignature(json_encode($body, JSON_UNESCAPED_SLASHES), PAYTM_MERCHANT_KEY);
    $payload = json_encode(['body'=>$body, 'head'=>['signature'=>$checksum]], JSON_UNESCAPED_SLASHES);
    $host = PAYTM_ENVIRONMENT === 'PROD' ? 'https://securegw.paytm.in' : 'https://securegw-stage.paytm.in';
    $url = $host . '/theia/api/v1/initiateTransaction?mid=' . PAYTM_MID . '&orderId=' . $order_id;
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    $resp = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    if ($err || !$resp) { http_response_code(500); echo json_encode(['success'=>false,'message'=>'Paytm initiateTransaction failed.']); $conn->close(); return; }
    $res = json_decode($resp, true);
    if (!isset($res['body']['txnToken'])) { http_response_code(500); echo json_encode(['success'=>false,'message'=>'Paytm did not return txnToken.']); $conn->close(); return; }
    echo json_encode(['success'=>true, 'data'=>[
        'order_id'=>$order_id,
        'mid'=>PAYTM_MID,
        'txnToken'=>$res['body']['txnToken'],
        'amount'=>$txnAmount,
        'callback_url'=>PAYTM_CALLBACK_URL,
        'env'=>PAYTM_ENVIRONMENT
    ]]);
    $conn->close();
}

function paytmWebhook() {
    // Paytm server-to-server callback
    // Load checksum helper from api/ directory
    require_once __DIR__ . '/api/paytm_checksum.php';
    $inputJSON = file_get_contents('php://input');
    $payload = json_decode($inputJSON, true);
    if (!$payload) { http_response_code(400); echo json_encode(['success'=>false]); return; }
    $orderId = $payload['ORDERID'] ?? $payload['orderId'] ?? null;
    $status = $payload['STATUS'] ?? $payload['status'] ?? null;
    $amount = (float)($payload['TXNAMOUNT'] ?? $payload['txnAmount'] ?? 0);
    $checksum = $payload['CHECKSUMHASH'] ?? $payload['checksum'] ?? '';
    // Verify checksum if merchant key provided via env
    $merchantKey = getenv('PAYTM_MERCHANT_KEY') ?: '';
    if ($merchantKey && !PaytmChecksum::verifySignature($payload, $merchantKey, $checksum)) {
        http_response_code(400); echo json_encode(['success'=>false,'message'=>'Checksum failed']); return;
    }
    $conn = connectDB();
    ensurePaymentsTables($conn);
    // Fetch order and user
    $stmt = $conn->prepare("SELECT user_id, amount, status FROM payments WHERE order_id = ? LIMIT 1");
    $stmt->bind_param("s", $orderId);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    if (!$row) { http_response_code(404); echo json_encode(['success'=>false,'message'=>'Order not found']); $conn->close(); return; }
    // Idempotency: only process if not already success
    if ($row['status'] === 'SUCCESS') { echo json_encode(['success'=>true]); $conn->close(); return; }
    // Basic validation
    if ($status === 'TXN_SUCCESS' || $status === 'SUCCESS') {
        // Update payment
        $upd = $conn->prepare("UPDATE payments SET status='SUCCESS', payload=? WHERE order_id = ?");
        $pl = $inputJSON;
        $upd->bind_param("ss", $pl, $orderId);
        $upd->execute();
        // Credit user balance
        $uid = $row['user_id'];
        $amt = $row['amount'];
        $credit = $conn->prepare("UPDATE users SET balance = balance + ? WHERE user_id = ?");
        $credit->bind_param("ds", $amt, $uid);
        $credit->execute();
        echo json_encode(['success'=>true]);
    } else {
        $upd = $conn->prepare("UPDATE payments SET status='FAILED', payload=? WHERE order_id = ?");
        $pl = $inputJSON;
        $upd->bind_param("ss", $pl, $orderId);
        $upd->execute();
        echo json_encode(['success'=>true]);
    }
    $conn->close();
}
function getServiceStatus() {
    $conn = connectDB();
    ensureServiceFlagsTable($conn);
    $res = $conn->query("SELECT value FROM service_flags WHERE flag='key_generation_enabled' LIMIT 1");
    $enabled = ($res && $row = $res->fetch_assoc()) ? $row['value'] === '1' : true; // default enabled
    echo json_encode(['success' => true, 'data' => ['key_generation_enabled' => $enabled]]);
    $conn->close();
}

/** Ensure system_keys table exists for pre-added keys pool */
function ensureSystemKeysTable($conn) {
    $conn->query("CREATE TABLE IF NOT EXISTS system_keys (
        key_string VARCHAR(64) PRIMARY KEY,
        name VARCHAR(128) NOT NULL,
        created_by_id VARCHAR(36) NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'Generated',
        duration VARCHAR(16) NULL,
        bucket VARCHAR(64) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");
    // Best-effort schema upgrade if column didn't exist before (guarded)
    $hasDuration = $conn->query("SHOW COLUMNS FROM system_keys LIKE 'duration'");
    if ($hasDuration && $hasDuration->num_rows === 0) {
        $conn->query("ALTER TABLE system_keys ADD COLUMN duration VARCHAR(16) NULL");
    }
    $hasBucket = $conn->query("SHOW COLUMNS FROM system_keys LIKE 'bucket'");
    if ($hasBucket && $hasBucket->num_rows === 0) {
        $conn->query("ALTER TABLE system_keys ADD COLUMN bucket VARCHAR(64) NULL");
    }
}

/** Pricing helpers **/
function ensurePricingTable($conn) {
    $conn->query("CREATE TABLE IF NOT EXISTS pricing (
        duration_id VARCHAR(16) NOT NULL,
        bucket VARCHAR(64) NULL,
        price DECIMAL(10,2) NOT NULL,
        price_user DECIMAL(10,2) NULL,
        price_reseller DECIMAL(10,2) NULL,
        price_admin DECIMAL(10,2) NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_bucket_duration (bucket, duration_id)
    )");
    // Schema upgrades for legacy tables
    $hasBucket = $conn->query("SHOW COLUMNS FROM pricing LIKE 'bucket'");
    if ($hasBucket && $hasBucket->num_rows === 0) {
        $conn->query("ALTER TABLE pricing ADD COLUMN bucket VARCHAR(64) NULL");
    }
    $hasPriceUser = $conn->query("SHOW COLUMNS FROM pricing LIKE 'price_user'");
    if ($hasPriceUser && $hasPriceUser->num_rows === 0) {
        $conn->query("ALTER TABLE pricing ADD COLUMN price_user DECIMAL(10,2) NULL AFTER price");
    }
    $hasPriceReseller = $conn->query("SHOW COLUMNS FROM pricing LIKE 'price_reseller'");
    if ($hasPriceReseller && $hasPriceReseller->num_rows === 0) {
        $conn->query("ALTER TABLE pricing ADD COLUMN price_reseller DECIMAL(10,2) NULL AFTER price_user");
    }
    $hasPriceAdmin = $conn->query("SHOW COLUMNS FROM pricing LIKE 'price_admin'");
    if ($hasPriceAdmin && $hasPriceAdmin->num_rows === 0) {
        $conn->query("ALTER TABLE pricing ADD COLUMN price_admin DECIMAL(10,2) NULL AFTER price_reseller");
    }
    $idxRes = $conn->query("SHOW INDEX FROM pricing WHERE Key_name = 'uniq_bucket_duration'");
    if (!$idxRes || $idxRes->num_rows === 0) {
        // Best-effort; ignore if fails due to duplicates
        @$conn->query("ALTER TABLE pricing ADD UNIQUE KEY uniq_bucket_duration (bucket, duration_id)");
    }
}

function getDefaultPricing() { return []; }

/**
 * Claims the next available pre-added key from system_keys.
 * Caller should be inside a transaction for row-level locks to apply.
 * Returns key string or null when unavailable.
 */
function claimPreAddedKey($conn) {
    ensureSystemKeysTable($conn);
    // Lock next available key and mark it as Issued; optional filter by bucket
    $requestedBucket = $GLOBALS['input']['bucket'] ?? null;
    $useBucket = ($requestedBucket && preg_match('/^[A-Za-z0-9._\-]{1,64}$/', $requestedBucket)) ? $requestedBucket : null;
    if ($useBucket) {
        $select = $conn->prepare("SELECT key_string, duration FROM system_keys WHERE status = 'Generated' AND bucket = ? ORDER BY created_at ASC LIMIT 1 FOR UPDATE");
        if (!$select) { return null; }
        $select->bind_param("s", $useBucket);
        $select->execute();
    } else {
        $select = $conn->prepare("SELECT key_string, duration FROM system_keys WHERE status = 'Generated' ORDER BY created_at ASC LIMIT 1 FOR UPDATE");
        if (!$select) { return null; }
        $select->execute();
    }
    $res = $select->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $select->close();
    if (!$row || empty($row['key_string'])) { return null; }
    $candidate = $row['key_string'];
    $update = $conn->prepare("UPDATE system_keys SET status = 'Issued' WHERE key_string = ? AND status = 'Generated'");
    if (!$update) { return null; }
    $update->bind_param("s", $candidate);
    $update->execute();
    $ok = $update->affected_rows === 1;
    $update->close();
    if (!$ok) { return null; }
    return [
        'key_string' => $candidate,
        'duration' => $row['duration'] ?? null,
    ];
}

function ownerSetKeyGeneration($user_id, $role, $enabled) {
    if (!checkRole($role, 'owner')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Owner authorization required.']);
        return;
    }
    $conn = connectDB();
    ensureServiceFlagsTable($conn);
    $val = $enabled ? '1' : '0';
    $stmt = $conn->prepare("INSERT INTO service_flags (flag, value) VALUES ('key_generation_enabled', ?) ON DUPLICATE KEY UPDATE value=VALUES(value)");
    $stmt->bind_param("s", $val);
    $stmt->execute();
    echo json_encode(['success' => true]);
    $conn->close();
}

/**
 * Generates a license key, deducts balance, and saves the record.
 */
function createLicense($user_id, $role, $input) {
    if (!checkRole($role, 'user')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Authorization required to create license.']);
        return;
    }
    
    $quantity = isset($input['quantity']) ? (int)$input['quantity'] : 1;
    if ($quantity < 1) { $quantity = 1; }
    if ($quantity > 10) { $quantity = 10; }

    $conn = connectDB();
    ensurePricingTable($conn);

    // Determine unit price from pricing for provided bucket/duration
    $bucket = isset($input['bucket']) && preg_match('/^[A-Za-z0-9._\-]{1,64}$/', (string)$input['bucket']) ? (string)$input['bucket'] : null;
    $durationId = (string)($input['duration_id'] ?? '');
    $productId = isset($input['product_id']) ? (int)$input['product_id'] : 0;
    if ($durationId === '') {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing duration_id.']);
        return;
    }

    $unitPrice = 0.0;
    // Prefer role-tiered PRICING using product name when product_id is provided; fallback to durations table
    if ($productId > 0) {
        // Load product name to use as bucket key
        $pn = $conn->prepare("SELECT name FROM products WHERE id = ? LIMIT 1");
        if ($pn) {
            $pn->bind_param("i", $productId);
            $pn->execute();
            $pRow = $pn->get_result()->fetch_assoc();
            $pn->close();
            $productName = $pRow['name'] ?? null;
            if ($productName) {
                $tierCol = ($role === 'reseller') ? 'price_reseller' : (($role === 'admin' || $role === 'owner') ? 'price_admin' : 'price_user');
                $ps = $conn->prepare("SELECT price, $tierCol AS tier_price FROM pricing WHERE bucket = ? AND duration_id = ? LIMIT 1");
                if ($ps) {
                    $ps->bind_param("ss", $productName, $durationId);
                    $ps->execute();
                    $row = $ps->get_result()->fetch_assoc();
                    $ps->close();
                    if ($row) {
                        $unitPrice = isset($row['tier_price']) && (float)$row['tier_price'] > 0 ? (float)$row['tier_price'] : (float)($row['price'] ?? 0);
                    }
                }
            }
        }
        // Fallback to durations table price if tiered pricing not found
        if ($unitPrice <= 0) {
            $ps = $conn->prepare("SELECT price FROM durations WHERE product_id = ? AND duration_name = ? LIMIT 1");
            if ($ps) {
                $ps->bind_param("is", $productId, $durationId);
                $ps->execute();
                $row = $ps->get_result()->fetch_assoc();
                $ps->close();
                if ($row) { $unitPrice = (float)$row['price']; }
            }
        }
    }
    if ($bucket !== null) {
        // Choose role-based tier when available
        $tierCol = ($role === 'reseller') ? 'price_reseller' : (($role === 'admin' || $role === 'owner') ? 'price_admin' : 'price_user');
        $ps = $conn->prepare("SELECT price, $tierCol AS tier_price FROM pricing WHERE bucket = ? AND duration_id = ? LIMIT 1");
        $ps->bind_param("ss", $bucket, $durationId);
        $ps->execute();
        $row = $ps->get_result()->fetch_assoc();
        $ps->close();
        if ($row) {
            $unitPrice = isset($row['tier_price']) && (float)$row['tier_price'] > 0 ? (float)$row['tier_price'] : (float)($row['price'] ?? 0);
        }
    }
    if ($unitPrice <= 0) {
        $tierCol = ($role === 'reseller') ? 'price_reseller' : (($role === 'admin' || $role === 'owner') ? 'price_admin' : 'price_user');
        $ps = $conn->prepare("SELECT price, $tierCol AS tier_price FROM pricing WHERE bucket IS NULL AND duration_id = ? LIMIT 1");
        if ($ps) {
            $ps->bind_param("s", $durationId);
            $ps->execute();
            $row = $ps->get_result()->fetch_assoc();
            $ps->close();
            if ($row) {
                $unitPrice = isset($row['tier_price']) && (float)$row['tier_price'] > 0 ? (float)$row['tier_price'] : (float)($row['price'] ?? 0);
            }
        }
    }
    if ($unitPrice <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Pricing not configured for selected product/duration.']);
        return;
    }
    $totalCost = $unitPrice * $quantity;

    $conn->begin_transaction();
    $stmt = $conn->prepare("SELECT balance FROM users WHERE user_id = ? FOR UPDATE");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $userBalance = $stmt->get_result()->fetch_assoc()['balance'] ?? 0;
    $stmt->close();

    if ($userBalance < $totalCost) {
        $conn->rollback();
        http_response_code(402);
        echo json_encode(['success' => false, 'message' => 'Insufficient balance.']);
        $conn->close();
        return;
    }
    
    $max_devices = 1; // fixed
    $game_package = $input['package_id'];
    $productId = isset($input['product_id']) ? (int)$input['product_id'] : 0;
    $expires = NULL; // start on first use
    $durationInput = $durationId;
    $keys = [];

    $insertSql = "INSERT INTO licenses (key_string, game_package, duration, max_devices, devices_used, status, creator_id, expires) VALUES (?, ?, ?, ?, 0, 'Issued', ?, ?)";
    $ins = $conn->prepare($insertSql);
    if (!$ins) {
        $conn->rollback();
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Preparation failed for license insert.']);
        $conn->close();
        return;
    }
    for ($i = 0; $i < $quantity; $i++) {
        // Prefer keys_pool when product is provided; fallback to system_keys
        $key_string = null;
        if ($productId > 0) {
            // lock next unused key for product
            $sel = $conn->prepare("SELECT id, key_value, default_duration FROM keys_pool WHERE product_id = ? AND is_used = 0 ORDER BY id ASC LIMIT 1 FOR UPDATE");
            $sel->bind_param("i", $productId);
            $sel->execute();
            $r = $sel->get_result()->fetch_assoc();
            $sel->close();
            if (!$r) {
                $conn->rollback();
                http_response_code(409);
                echo json_encode(['success'=>false,'message'=>'No unused keys in pool for selected product.']);
                $conn->close();
                return;
            }
            $kpId = (int)$r['id'];
            $key_string = $r['key_value'];
            $pooledDur = $r['default_duration'];
            // mark used
            $upd = $conn->prepare("UPDATE keys_pool SET is_used = 1, used_at = NOW() WHERE id = ? AND is_used = 0");
            $upd->bind_param("i", $kpId);
            $upd->execute();
            if ($upd->affected_rows !== 1) {
                $conn->rollback();
                http_response_code(409);
                echo json_encode(['success'=>false,'message'=>'Key reservation race condition. Try again.']);
                $conn->close();
                return;
            }
            $duration = $pooledDur ?: $durationInput;
        } else {
            $claimed = claimPreAddedKey($conn);
            if (!$claimed) {
                $conn->rollback();
                http_response_code(409);
                echo json_encode(['success' => false, 'message' => 'Insufficient pre-added keys available. Try fewer quantity or contact owner.']);
                $conn->close();
                return;
            }
            $key_string = $claimed['key_string'];
            $duration = $claimed['duration'] ?: $durationInput;
        }
        if (!$ins->bind_param("sssiss", $key_string, $game_package, $duration, $max_devices, $user_id, $expires) || !$ins->execute()) {
            $conn->rollback();
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Key creation failed during batch.']);
            $conn->close();
            return;
        }
        $keys[] = $key_string;
    }

    $newBalance = $userBalance - $totalCost;
    $stmt = $conn->prepare("UPDATE users SET balance = ? WHERE user_id = ?");
    $stmt->bind_param("ds", $newBalance, $user_id);
    $stmt->execute();
    
    $conn->commit();
    echo json_encode(['success' => true, 'data' => ['keys' => $keys, 'new_balance' => $newBalance]]);
    $conn->close();
}


/**
 * Resets the device linkage for a specific license key (User/Reseller action).
 */
function resetLicense($user_id, $role, $license_id) {
    if (!checkRole($role, 'user')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Authorization required to reset key.']);
        return;
    }
    
    $conn = connectDB();
    
    // 1. Check current devices_used status
    $stmt = $conn->prepare("SELECT devices_used FROM licenses WHERE license_id = ? AND creator_id = ?");
    $stmt->bind_param("is", $license_id, $user_id);
    $stmt->execute();
    $key_data = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    if (!$key_data) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Key not found or user not authorized.']);
        $conn->close();
        return;
    }

    if ($key_data['devices_used'] == 0) {
        // Condition 1: Already reset/free
        http_response_code(200);
        echo json_encode(['success' => true, 'message' => 'Key is already reset and ready for new device login.']);
        $conn->close();
        return;
    }
    
    // 2. Perform the UPDATE (Reset)
    $sql = "UPDATE licenses SET devices_used = 0, linked_device_id = NULL 
            WHERE license_id = ? AND creator_id = ? AND status != 'Banned'";
    $stmt = $conn->prepare($sql);
    
    if (!$stmt->bind_param("is", $license_id, $user_id) || !$stmt->execute()) {
        $error_message = $conn->error;
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Key reset failed: ' . $error_message]);
        $conn->close();
        return;
    }

    // 3. Success Confirmation
    if ($stmt->affected_rows > 0) {
        echo json_encode(['success' => true, 'message' => 'License device linkage reset successfully!']);
    } else {
        // Should not be reached if devices_used > 0, but included as a fail-safe
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Key reset failed (No rows were updated).']);
    }
    $conn->close();
}

/**
 * Updates license details (Admin/Owner action).
 */
function updateLicenseDetails($user_id, $role, $input) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    
    echo json_encode(['success' => true, 'message' => 'License details updated (Simulated).']);
}


/**
 * Bans a license key (Admin/Owner action).
 */
function banLicense($user_id, $role, $license_id) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    
    $conn = connectDB();
    $sql = "UPDATE licenses SET status = 'Banned' WHERE license_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $license_id);

    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo json_encode(['success' => true, 'message' => 'License key banned.']);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'License not found.']);
    }
    $conn->close();
}

/**
 * Deletes a license key permanently (Admin/Owner action). No refund.
 */
function deleteLicense($user_id, $role, $license_id) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    
    $conn = connectDB();
    $sql = "DELETE FROM licenses WHERE license_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $license_id);

    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo json_encode(['success' => true, 'message' => 'License key deleted permanently.']);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'License not found.']);
    }
    $conn->close();
}

/**
 * Creates a new referral code (Admin/Owner action).
 */
function createReferral($user_id, $role, $input) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }

    $conn = connectDB();
    $code = strtoupper(substr(bin2hex(random_bytes(4)), 0, 8));
    $balance = (float)($input['balance'] ?? 0);
    $max_role = $input['max_role'] ?? 'user';
    if (!in_array($max_role, ['user','reseller','admin'], true)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid max_role.']);
        $conn->close();
        return;
    }

    $sql = "INSERT INTO referrals (code, initial_balance, max_role, creator_id) 
            VALUES (?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sdss", $code, $balance, $max_role, $user_id);
    
    if ($stmt->execute()) {
        http_response_code(201);
        echo json_encode(['success' => true, 'data' => ['code' => $code]]);
    } else {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Referral creation failed.']);
    }
    $conn->close();
}

/**
 * Loads all referral codes created by the Admin/Owner.
 */
function loadReferrals($role) {
     if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    
    $conn = connectDB();
    $sql = "SELECT code, initial_balance, max_role, creator_id FROM referrals ORDER BY created_at DESC";
    $result = $conn->query($sql);
    
    $referrals = [];
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $referrals[] = $row;
        }
    }
    
    echo json_encode(['success' => true, 'data' => $referrals]);
    $conn->close();
}

/**
 * Deletes a referral code (Admin/Owner action).
 */
function deleteReferral($user_id, $role, $code) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    if (!$code) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing code.']);
        return;
    }
    $conn = connectDB();
    $stmt = $conn->prepare("DELETE FROM referrals WHERE code = ?");
    $stmt->bind_param("s", $code);
    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo json_encode(['success' => true]);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Referral not found.']);
    }
    $conn->close();
}


/**
 * Loads users managed by the current Admin/Owner (referred clients).
 */
function loadManagedUsers($user_id, $role) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    
    $conn = connectDB();
    $where_clause = ($role === 'owner') ? "" : "WHERE referred_by_id = ?";
    $sql = "SELECT user_id, email, role, referred_by_id, status FROM users $where_clause ORDER BY created_at DESC";
    
    if ($role !== 'owner') {
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
    } else {
        $result = $conn->query($sql);
    }
    
    $users = [];
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $row['active_license_id'] = ($row['role'] !== 'owner') ? 'LID-' . substr($row['user_id'], 0, 8) : null;
            $users[] = $row;
        }
    }
    
    echo json_encode(['success' => true, 'data' => $users]);
    $conn->close();
}


/**
 * Admin/Owner: Add balance to a user.
 */
function adminAddBalance($current_user_id, $role, $target_user_id, $amount) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    if ($amount <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid amount.']);
        return;
    }
    $conn = connectDB();
    $stmt = $conn->prepare("UPDATE users SET balance = balance + ? WHERE user_id = ?");
    $stmt->bind_param("ds", $amount, $target_user_id);
    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo json_encode(['success' => true]);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'User not found or update failed.']);
    }
    $conn->close();
}

/**
 * Admin/Owner: Change user role (cannot set owner).
 */
function adminChangeRole($current_user_id, $role, $target_user_id, $new_role) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    $allowed = ['user','reseller','admin'];
    if (!in_array($new_role, $allowed, true)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid role.']);
        return;
    }
    $conn = connectDB();
    $stmt = $conn->prepare("UPDATE users SET role = ? WHERE user_id = ?");
    $stmt->bind_param("ss", $new_role, $target_user_id);
    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo json_encode(['success' => true]);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'User not found or update failed.']);
    }
    $conn->close();
}

/**
 * Load single license info for the key info modal.
 */
function loadLicenseInfo($user_id, $role, $license_id) {
    if (!checkRole($role, 'user')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Authorization required.']);
        return;
    }
    $conn = connectDB();
    // Owner/Admin can view any; users can only view their own licenses
    if ($role === 'user') {
        $stmt = $conn->prepare("SELECT license_id, key_string, game_package, duration, max_devices, devices_used, status, expires FROM licenses WHERE license_id = ? AND creator_id = ?");
        $stmt->bind_param("is", $license_id, $user_id);
    } else {
        $stmt = $conn->prepare("SELECT license_id, key_string, game_package, duration, max_devices, devices_used, status, expires FROM licenses WHERE license_id = ?");
        $stmt->bind_param("i", $license_id);
    }
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    if ($row) {
        echo json_encode(['success' => true, 'data' => $row]);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'License not found.']);
    }
    $conn->close();
}

/**
 * Check/Activate a license. Starts expiry if not started.
 */
function checkLicense($user_id, $role, $license_id, $device_id = null) {
    if (!checkRole($role, 'user')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Authorization required.']);
        return;
    }
    $conn = connectDB();
    // Users can only check their own; admin/owner can check any
    if ($role === 'user') {
        $stmt = $conn->prepare("SELECT expires, devices_used, max_devices, status FROM licenses WHERE license_id = ? AND creator_id = ? AND status != 'Banned'");
        $stmt->bind_param("is", $license_id, $user_id);
    } else {
        $stmt = $conn->prepare("SELECT expires, devices_used, max_devices, status FROM licenses WHERE license_id = ? AND status != 'Banned'");
        $stmt->bind_param("i", $license_id);
    }
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if (!$row) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'License not found.']);
        $conn->close();
        return;
    }
    // Activation on first login + increment devices_used up to max_devices
    if ($row['expires'] === NULL) {
        $stmt = $conn->prepare("SELECT duration FROM licenses WHERE license_id = ?");
        $stmt->bind_param("i", $license_id);
        $stmt->execute();
        $durRes = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        $duration_id = $durRes ? $durRes['duration'] : 'opt2';
        $hours = getDurationHours($duration_id);
        $stmt = $conn->prepare("UPDATE licenses SET expires = DATE_ADD(NOW(), INTERVAL ? HOUR), status = 'Active', devices_used = LEAST(max_devices, devices_used + 1), linked_device_id = IFNULL(?, linked_device_id) WHERE license_id = ?");
        $stmt->bind_param("isi", $hours, $device_id, $license_id);
        $stmt->execute();
    } else if ($row['devices_used'] < $row['max_devices']) {
        $stmt = $conn->prepare("UPDATE licenses SET devices_used = devices_used + 1, linked_device_id = IFNULL(?, linked_device_id) WHERE license_id = ?");
        $stmt->bind_param("si", $device_id, $license_id);
        $stmt->execute();
    }
    // Return updated devices count
    $res = $conn->prepare("SELECT devices_used, max_devices, status, expires FROM licenses WHERE license_id = ?");
    $res->bind_param("i", $license_id);
    $res->execute();
    $info = $res->get_result()->fetch_assoc();
    echo json_encode(['success' => true, 'data' => $info]);
    $conn->close();
}

/**
 * Extend license by extra days (Admin/Owner).
 */
function extendLicenseTime($user_id, $role, $license_id, $extra_days) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    if ($extra_days <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid extra_days.']);
        return;
    }
    $conn = connectDB();
    $stmt = $conn->prepare("UPDATE licenses SET expires = COALESCE(expires, NOW()) + INTERVAL ? DAY WHERE license_id = ?");
    $stmt->bind_param("ii", $extra_days, $license_id);
    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo json_encode(['success' => true]);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'License not found or update failed.']);
    }
    $conn->close();
}

/**
 * Owner: reset all licenses (devices_used=0, linked_device_id=NULL)
 */
function ownerResetAllLicenses($user_id, $role) {
    if (!checkRole($role, 'owner')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Owner authorization required.']);
        return;
    }
    $conn = connectDB();
    $conn->query("UPDATE licenses SET devices_used = 0, linked_device_id = NULL");
    echo json_encode(['success' => true]);
    $conn->close();
}

/**
 * Owner: delete all licenses
 */
function ownerDeleteAllLicenses($user_id, $role) {
    if (!checkRole($role, 'owner')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Owner authorization required.']);
        return;
    }
    $conn = connectDB();
    $conn->query("DELETE FROM licenses");
    echo json_encode(['success' => true]);
    $conn->close();
}

/**
 * Admin: reset all managed licenses (self + referred)
 */
function adminResetAllLicenses($user_id, $role) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    $conn = connectDB();
    if ($role === 'owner') {
        $conn->query("UPDATE licenses SET devices_used = 0, linked_device_id = NULL");
    } else {
        // reset licenses created by admin or their referred users
        $stmt = $conn->prepare("UPDATE licenses SET devices_used = 0, linked_device_id = NULL WHERE creator_id IN (SELECT user_id FROM users WHERE referred_by_id = ? UNION SELECT ?)");
        $stmt->bind_param("ss", $user_id, $user_id);
        $stmt->execute();
    }
    echo json_encode(['success' => true]);
    $conn->close();
}

/**
 * Admin: delete all managed licenses
 */
function adminDeleteAllLicenses($user_id, $role) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    $conn = connectDB();
    if ($role === 'owner') {
        $conn->query("DELETE FROM licenses");
    } else {
        $stmt = $conn->prepare("DELETE FROM licenses WHERE creator_id IN (SELECT user_id FROM users WHERE referred_by_id = ? UNION SELECT ?)");
        $stmt->bind_param("ss", $user_id, $user_id);
        $stmt->execute();
    }
    echo json_encode(['success' => true]);
    $conn->close();
}

/**
 * Admin: extend all managed licenses by extra days
 */
function adminExtendAllLicenses($user_id, $role, $extra_days) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    if ($extra_days <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid extra_days.']);
        return;
    }
    $conn = connectDB();
    if ($role === 'owner') {
        $stmt = $conn->prepare("UPDATE licenses SET expires = COALESCE(expires, NOW()) + INTERVAL ? DAY");
        $stmt->bind_param("i", $extra_days);
        $stmt->execute();
    } else {
        $stmt = $conn->prepare("UPDATE licenses SET expires = COALESCE(expires, NOW()) + INTERVAL ? DAY WHERE creator_id IN (SELECT user_id FROM users WHERE referred_by_id = ? UNION SELECT ?)");
        $stmt->bind_param("iss", $extra_days, $user_id, $user_id);
        $stmt->execute();
    }
    echo json_encode(['success' => true]);
    $conn->close();
}

/**
 * Owner: extend all licenses by extra days
 */
function ownerExtendAllLicenses($user_id, $role, $extra_days) {
    if (!checkRole($role, 'owner')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Owner authorization required.']);
        return;
    }
    if ($extra_days <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid extra_days.']);
        return;
    }
    $conn = connectDB();
    $stmt = $conn->prepare("UPDATE licenses SET expires = COALESCE(expires, NOW()) + INTERVAL ? DAY");
    $stmt->bind_param("i", $extra_days);
    $stmt->execute();
    echo json_encode(['success' => true]);
    $conn->close();
}


/**
 * Admin/Owner action to reset the device linkage on a client's key.
 */
function adminResetClientKey($current_user_id, $role, $license_id) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }

    $conn = connectDB();
    
    $stmt = $conn->prepare("SELECT creator_id FROM licenses WHERE license_id = ?");
    $stmt->bind_param("i", $license_id);
    $stmt->execute();
    $licenseOwnerId = $stmt->get_result()->fetch_assoc()['creator_id'] ?? null;
    $stmt->close();
    
    if (!$licenseOwnerId) {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'License not found.']);
        $conn->close();
        return;
    }
    
    if ($role === 'admin') {
        $stmt = $conn->prepare("SELECT referred_by_id FROM users WHERE user_id = ?");
        $stmt->bind_param("s", $licenseOwnerId);
        $stmt->execute();
        $referredById = $stmt->get_result()->fetch_assoc()['referred_by_id'] ?? null;
        $stmt->close();

        if ($referredById !== $current_user_id) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Authorization denied. License is not from a managed client.']);
            $conn->close();
            return;
        }
    }

    $sql = "UPDATE licenses SET devices_used = 0, linked_device_id = NULL WHERE license_id = ?";
    $stmt = $conn->prepare($sql);
    // Correct binding: single integer parameter for license_id
    if (!$stmt->bind_param("i", $license_id) || !$stmt->execute()) {
        $error_message = $conn->error;
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Admin reset failed: ' . $error_message]);
        $conn->close();
        return;
    }

    if ($stmt->affected_rows > 0) {
        echo json_encode(['success' => true, 'message' => 'Client license device link reset.']);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Client license reset failed (No rows affected).']);
    }
    $conn->close();
}

/**
 * Loads system keys (Admin/Owner view).
 */
function loadSystemKeys($role) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required.']);
        return;
    }
    
    $conn = connectDB();
    ensureSystemKeysTable($conn);
    $sql = "SELECT key_string, name, created_by_id, status FROM system_keys ORDER BY created_at DESC";
    $result = $conn->query($sql);
    
    $keys = [];
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $keys[] = $row;
        }
    }
    
    echo json_encode(['success' => true, 'data' => $keys]);
    $conn->close();
}

/**
 * Generates a high-privilege system key (Admin/Owner action).
 */
function generateSystemKey($user_id, $role, $input) {
    if (!checkRole($role, 'owner')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Owner authorization required.']);
        return;
    }
    
    $conn = connectDB();
    ensureSystemKeysTable($conn);
    $name = trim($input['name'] ?? 'SYSTEM');
    $key_string = trim($input['key_string'] ?? '');
    if ($key_string === '') {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Key string is required.']);
        $conn->close();
        return;
    }
    if (!preg_match('/^[A-Za-z0-9._\-]{6,64}$/', $key_string)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid key format. Use 6-64 chars [A-Za-z0-9._-].']);
        $conn->close();
        return;
    }

    $sql = "INSERT INTO system_keys (key_string, name, created_by_id, status) 
            VALUES (?, ?, ?, 'Generated')";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sss", $key_string, $name, $user_id);
    
    if ($stmt->execute()) {
        http_response_code(201);
        echo json_encode(['success' => true, 'message' => 'System key added to pool.', 'data' => ['key_string' => $key_string]]);
    } else {
        http_response_code(500);
        $msg = (strpos($conn->error ?? '', 'Duplicate') !== false || ($conn->errno ?? 0) === 1062) ? 'Duplicate key. Already exists.' : 'System key creation failed.';
        echo json_encode(['success' => false, 'message' => $msg]);
    }
    $conn->close();
}

/**
 * Owner bulk add keys into pool.
 */
function ownerBulkAddKeys($user_id, $role, $keys, $name, $bucket = null, $durationOverride = null) {
    if (!checkRole($role, 'owner')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Owner authorization required.']);
        return;
    }
    if (!is_array($keys) || count($keys) === 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'No keys provided.']);
        return;
    }
    $conn = connectDB();
    ensureSystemKeysTable($conn);
    $stmt = $conn->prepare("INSERT INTO system_keys (key_string, name, created_by_id, status, duration, bucket) VALUES (?, ?, ?, 'Generated', ?, ?) ON DUPLICATE KEY UPDATE name=VALUES(name), duration=VALUES(duration), bucket=VALUES(bucket)");
    if (!$stmt) {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Preparation failed.']);
        $conn->close();
        return;
    }
    $added = 0; $skipped = 0;
    $defaultDuration = null; // optional default duration
    if (is_string($durationOverride)) {
        $d = trim($durationOverride);
        if ($d === '' || preg_match('/^(h:\\d{1,5}|d:\\d{1,5})$/', $d)) { $defaultDuration = $d ?: null; }
    }
    $bucketClean = null;
    if (is_string($bucket) && preg_match('/^[A-Za-z0-9._\-]{1,64}$/', $bucket)) { $bucketClean = $bucket; }
    foreach ($keys as $k) {
        $key = trim($k);
        if ($key === '' || !preg_match('/^[A-Za-z0-9._\-]{6,64}$/', $key)) { $skipped++; continue; }
        $dur = $defaultDuration;
        $stmt->bind_param("sssss", $key, $name, $user_id, $dur, $bucketClean);
        if ($stmt->execute()) { $added++; } else { $skipped++; }
    }
    echo json_encode(['success' => true, 'data' => ['added' => $added, 'skipped' => $skipped]]);
    $conn->close();
}

/**
 * Get pricing table (admin/owner).
 */
function getPricing($role) {
    if (!checkRole($role, 'user')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Authorization required.']);
        return;
    }
    $conn = connectDB();
    ensurePricingTable($conn);
    // Use already-parsed global input so we don't re-read php://input
    global $input;
    $full = !empty($input['full']) && checkRole($role, 'owner');
    $res = $conn->query("SELECT bucket, duration_id, price, price_user, price_reseller, price_admin FROM pricing ORDER BY bucket, duration_id");
    $pricing = [];
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $bucketKey = $row['bucket'] ?: '_default_';
            if (!isset($pricing[$bucketKey])) { $pricing[$bucketKey] = []; }
            if ($full) {
                $pricing[$bucketKey][$row['duration_id']] = [
                    'user' => isset($row['price_user']) ? (float)$row['price_user'] : (isset($row['price']) ? (float)$row['price'] : 0.0),
                    'reseller' => isset($row['price_reseller']) ? (float)$row['price_reseller'] : (isset($row['price']) ? (float)$row['price'] : 0.0),
                    'admin' => isset($row['price_admin']) ? (float)$row['price_admin'] : (isset($row['price']) ? (float)$row['price'] : 0.0),
                ];
            } else {
                // Role-appropriate single price
                $tier = ($role === 'reseller') ? 'price_reseller' : (($role === 'admin' || $role === 'owner') ? 'price_admin' : 'price_user');
                $val = $row[$tier] ?? null;
                if ($val === null || (float)$val <= 0) { $val = $row['price'] ?? 0; }
                $pricing[$bucketKey][$row['duration_id']] = (float)$val;
            }
        }
    }
    echo json_encode(['success' => true, 'data' => $pricing]);
    $conn->close();
}

/**
 * Returns list of available buckets/products and their durations for UI building.
 */
function getCatalog($role) {
    if (!checkRole($role, 'user')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Authorization required.']);
        return;
    }
    $conn = connectDB();
    ensurePricingTable($conn);
    $res = $conn->query("SELECT bucket, duration_id FROM pricing ORDER BY bucket, duration_id");
    $catalog = [];
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $b = $row['bucket'] ?: '_default_';
            if (!isset($catalog[$b])) { $catalog[$b] = []; }
            $catalog[$b][] = $row['duration_id'];
        }
    }
    echo json_encode(['success' => true, 'data' => $catalog]);
    $conn->close();
}

/**
 * Owner update pricing.
 */
function ownerUpdatePricing($user_id, $role, $pricing) {
    if (!checkRole($role, 'owner')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Owner authorization required.']);
        return;
    }
    if (!is_array($pricing)) { http_response_code(400); echo json_encode(['success' => false, 'message' => 'Invalid pricing payload.']); return; }
    if (empty($pricing)) { echo json_encode(['success' => true]); return; }
    $conn = connectDB();
    ensurePricingTable($conn);
    // We'll upsert role-tiered prices; accept two shapes:
    // 1) { bucket: { durationId: number } }
    // 2) { bucket: { durationId: { user: n1, reseller: n2, admin: n3 } } }
    $stmt = $conn->prepare("INSERT INTO pricing (bucket, duration_id, price, price_user, price_reseller, price_admin) VALUES (?, ?, ?, ?, ?, ?) 
        ON DUPLICATE KEY UPDATE 
            price = COALESCE(VALUES(price), price),
            price_user = VALUES(price_user),
            price_reseller = VALUES(price_reseller),
            price_admin = VALUES(price_admin)");
    if (!$stmt) { http_response_code(500); echo json_encode(['success' => false, 'message' => 'Preparation failed.']); $conn->close(); return; }
    foreach ($pricing as $bucketName => $bucketPrices) {
        $b = ($bucketName === '_default_' ? null : (string)$bucketName);
        if (!is_array($bucketPrices)) { continue; }
        foreach ($bucketPrices as $durationId => $val) {
            $did = (string)$durationId;
            if ($did === '') { continue; }
            $base = null; $pu = null; $pr = null; $pa = null;
            if (is_array($val)) {
                $pu = isset($val['user']) ? (float)$val['user'] : null;
                $pr = isset($val['reseller']) ? (float)$val['reseller'] : null;
                $pa = isset($val['admin']) ? (float)$val['admin'] : null;
                // Optional base price fallback
                $base = isset($val['price']) ? (float)$val['price'] : null;
            } else {
                $base = (float)$val;
            }
            // Ensure NOT NULL base 'price' column gets a value
            if ($base === null) {
                if ($pu !== null) { $base = $pu; }
                elseif ($pr !== null) { $base = $pr; }
                elseif ($pa !== null) { $base = $pa; }
                else { $base = 0.00; }
            }
            // Bind as strings to allow NULLs when needed for tier columns; MySQL will cast DECIMAL
            $puParam = ($pu === null) ? null : (string)$pu;
            $prParam = ($pr === null) ? null : (string)$pr;
            $paParam = ($pa === null) ? null : (string)$pa;
            $baseParam = (string)$base;
            $stmt->bind_param("ssssss", $b, $did, $baseParam, $puParam, $prParam, $paParam);
            $stmt->execute();
        }
    }
    echo json_encode(['success' => true]);
    $conn->close();
}

/** New: Owner Product Management **/
function ownerListProducts($user_id, $role) {
    if (!checkRole($role, 'owner')) { http_response_code(403); echo json_encode(['success'=>false,'message'=>'Owner authorization required.']); return; }
    $conn = connectDB();
    $res = $conn->query("SELECT id, name, status, created_at FROM products ORDER BY name");
    $rows = [];
    if ($res) { while ($r = $res->fetch_assoc()) { $rows[] = $r; } }
    echo json_encode(['success'=>true, 'data'=>$rows]);
    $conn->close();
}

function ownerCreateProduct($user_id, $role, $name) {
    if (!checkRole($role, 'owner')) { http_response_code(403); echo json_encode(['success'=>false,'message'=>'Owner authorization required.']); return; }
    if ($name === '' || !preg_match('/^[A-Za-z0-9._\-]{1,64}$/', $name)) { http_response_code(400); echo json_encode(['success'=>false,'message'=>'Invalid product name.']); return; }
    $conn = connectDB();
    $stmt = $conn->prepare("INSERT INTO products (name) VALUES (?)");
    $stmt->bind_param("s", $name);
    if ($stmt->execute()) { echo json_encode(['success'=>true, 'data'=>['id'=>$conn->insert_id]]); } else { http_response_code(500); echo json_encode(['success'=>false,'message'=>'Create failed.']); }
    $conn->close();
}

function ownerUpdateProduct($user_id, $role, $id, $name, $status) {
    if (!checkRole($role, 'owner')) { http_response_code(403); echo json_encode(['success'=>false,'message'=>'Owner authorization required.']); return; }
    if ($id <= 0) { http_response_code(400); echo json_encode(['success'=>false,'message'=>'Invalid product id.']); return; }
    if ($name !== '' && !preg_match('/^[A-Za-z0-9._\-]{1,64}$/', $name)) { http_response_code(400); echo json_encode(['success'=>false,'message'=>'Invalid product name.']); return; }
    if ($status !== '' && !in_array($status, ['active','inactive'], true)) { http_response_code(400); echo json_encode(['success'=>false,'message'=>'Invalid status.']); return; }
    $conn = connectDB();
    if ($name !== '' && $status !== '') {
        $stmt = $conn->prepare("UPDATE products SET name = ?, status = ? WHERE id = ?");
        $stmt->bind_param("ssi", $name, $status, $id);
    } elseif ($name !== '') {
        $stmt = $conn->prepare("UPDATE products SET name = ? WHERE id = ?");
        $stmt->bind_param("si", $name, $id);
    } else {
        $stmt = $conn->prepare("UPDATE products SET status = ? WHERE id = ?");
        $stmt->bind_param("si", $status, $id);
    }
    if ($stmt->execute() && $stmt->affected_rows >= 0) { echo json_encode(['success'=>true]); } else { http_response_code(404); echo json_encode(['success'=>false,'message'=>'Update failed.']); }
    $conn->close();
}

function ownerDeleteProduct($user_id, $role, $id) {
    if (!checkRole($role, 'owner')) { http_response_code(403); echo json_encode(['success'=>false,'message'=>'Owner authorization required.']); return; }
    if ($id <= 0) { http_response_code(400); echo json_encode(['success'=>false,'message'=>'Invalid product id.']); return; }
    $conn = connectDB();
    $stmt = $conn->prepare("DELETE FROM products WHERE id = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute() && $stmt->affected_rows > 0) { echo json_encode(['success'=>true]); } else { http_response_code(404); echo json_encode(['success'=>false,'message'=>'Delete failed.']); }
    $conn->close();
}

function ownerListDurations($user_id, $role, $product_id) {
    if (!checkRole($role, 'owner')) { http_response_code(403); echo json_encode(['success'=>false,'message'=>'Owner authorization required.']); return; }
    if ($product_id <= 0) { http_response_code(400); echo json_encode(['success'=>false,'message'=>'Invalid product id.']); return; }
    $conn = connectDB();
    $stmt = $conn->prepare("SELECT id, duration_name, price FROM durations WHERE product_id = ? ORDER BY id");
    $stmt->bind_param("i", $product_id);
    $stmt->execute();
    $res = $stmt->get_result();
    $rows = [];
    while ($r = $res->fetch_assoc()) { $rows[] = $r; }
    echo json_encode(['success'=>true, 'data'=>$rows]);
    $conn->close();
}

function ownerUpsertDuration($user_id, $role, $product_id, $duration_name, $price) {
    if (!checkRole($role, 'owner')) { http_response_code(403); echo json_encode(['success'=>false,'message'=>'Owner authorization required.']); return; }
    if ($product_id <= 0 || $duration_name === '' || $price <= 0) { http_response_code(400); echo json_encode(['success'=>false,'message'=>'Invalid payload.']); return; }
    $conn = connectDB();
    $stmt = $conn->prepare("INSERT INTO durations (product_id, duration_name, price) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE price = VALUES(price)");
    $stmt->bind_param("isd", $product_id, $duration_name, $price);
    if ($stmt->execute()) { echo json_encode(['success'=>true]); } else { http_response_code(500); echo json_encode(['success'=>false,'message'=>'Upsert failed.']); }
    $conn->close();
}

function ownerDeleteDuration($user_id, $role, $id) {
    if (!checkRole($role, 'owner')) { http_response_code(403); echo json_encode(['success'=>false,'message'=>'Owner authorization required.']); return; }
    if ($id <= 0) { http_response_code(400); echo json_encode(['success'=>false,'message'=>'Invalid id.']); return; }
    $conn = connectDB();
    $stmt = $conn->prepare("DELETE FROM durations WHERE id = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute() && $stmt->affected_rows > 0) { echo json_encode(['success'=>true]); } else { http_response_code(404); echo json_encode(['success'=>false,'message'=>'Delete failed.']); }
    $conn->close();
}

function ownerBulkAddKeysPool($user_id, $role, $product_id, $keys, $default_duration) {
    if (!checkRole($role, 'owner')) { http_response_code(403); echo json_encode(['success'=>false,'message'=>'Owner authorization required.']); return; }
    if ($product_id <= 0 || !is_array($keys) || count($keys) === 0) { http_response_code(400); echo json_encode(['success'=>false,'message'=>'Invalid payload.']); return; }
    $conn = connectDB();
    $stmt = $conn->prepare("INSERT INTO keys_pool (product_id, key_value, default_duration, is_used) VALUES (?, ?, ?, 0) ON DUPLICATE KEY UPDATE default_duration=VALUES(default_duration)");
    if (!$stmt) { http_response_code(500); echo json_encode(['success'=>false,'message'=>'Preparation failed.']); $conn->close(); return; }
    $added=0; $skipped=0;
    foreach ($keys as $k) {
        $kv = trim($k);
        if ($kv === '' || !preg_match('/^[A-Za-z0-9._\-]{6,64}$/', $kv)) { $skipped++; continue; }
        $dur = ($default_duration && preg_match('/^(opt\d+|h:\\d{1,5}|d:\\d{1,5})$/', $default_duration)) ? $default_duration : NULL;
        $stmt->bind_param("iss", $product_id, $kv, $dur);
        if ($stmt->execute()) { $added++; } else { $skipped++; }
    }
    echo json_encode(['success'=>true, 'data'=>['added'=>$added,'skipped'=>$skipped]]);
    $conn->close();
}

/** New: User-facing listing **/
function listProducts($role) {
    if (!checkRole($role, 'user')) { http_response_code(403); echo json_encode(['success'=>false,'message' => 'Authorization required.']); return; }
    $conn = connectDB();
    $res = $conn->query("SELECT id, name FROM products WHERE status='active' ORDER BY name");
    $rows = [];
    if ($res) { while ($r = $res->fetch_assoc()) { $rows[] = $r; } }
    echo json_encode(['success'=>true, 'data'=>$rows]);
    $conn->close();
}

function listDurations($role, $product_id) {
    if (!checkRole($role, 'user')) { http_response_code(403); echo json_encode(['success'=>false,'message' => 'Authorization required.']); return; }
    if ($product_id <= 0) { http_response_code(400); echo json_encode(['success'=>false,'message' => 'Invalid product id.']); return; }
    $conn = connectDB();
    // Fetch product name for role-tiered pricing overlay
    $pname = null;
    $p = $conn->prepare("SELECT name FROM products WHERE id = ? LIMIT 1");
    if ($p) { $p->bind_param("i", $product_id); $p->execute(); $prow = $p->get_result()->fetch_assoc(); $p->close(); $pname = $prow['name'] ?? null; }

    $stmt = $conn->prepare("SELECT id, duration_name, price FROM durations WHERE product_id = ? ORDER BY id");
    $stmt->bind_param("i", $product_id);
    $stmt->execute();
    $res = $stmt->get_result();
    $rows = [];
    ensurePricingTable($conn);
    $tierCol = ($role === 'reseller') ? 'price_reseller' : (($role === 'admin' || $role === 'owner') ? 'price_admin' : 'price_user');
    while ($r = $res->fetch_assoc()) {
        // Overlay role-tiered pricing if present for this product name
        if ($pname) {
            $q = $conn->prepare("SELECT price, $tierCol AS tier_price FROM pricing WHERE bucket = ? AND duration_id = ? LIMIT 1");
            if ($q) {
                $q->bind_param("ss", $pname, $r['duration_name']);
                $q->execute();
                $pr = $q->get_result()->fetch_assoc();
                $q->close();
                if ($pr) {
                    $eff = isset($pr['tier_price']) && (float)$pr['tier_price'] > 0 ? (float)$pr['tier_price'] : (float)($pr['price'] ?? 0);
                    if ($eff > 0) { $r['price'] = $eff; }
                }
            }
        }
        $rows[] = $r;
    }
    echo json_encode(['success'=>true, 'data'=>$rows]);
    $conn->close();
}
/**
 * Owner: Generate API key with limit/amount for external automation.
 */
function ownerGenerateApiKey($user_id, $role, $amount) {
    if (!checkRole($role, 'owner')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Owner authorization required.']);
        return;
    }
    if ($amount <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid amount.']);
        return;
    }
    $conn = connectDB();
    $conn->query("CREATE TABLE IF NOT EXISTS api_keys (api_key CHAR(40) PRIMARY KEY, amount DECIMAL(10,2) NOT NULL, created_by_id VARCHAR(36) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $api_key = bin2hex(random_bytes(20));
    $stmt = $conn->prepare("INSERT INTO api_keys (api_key, amount, created_by_id) VALUES (?, ?, ?)");
    $stmt->bind_param("sds", $api_key, $amount, $user_id);
    if ($stmt->execute()) {
        echo json_encode(['success' => true, 'data' => ['api_key' => $api_key, 'amount' => (float)$amount]]);
    } else {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'API key generation failed.']);
    }
    $conn->close();
}

/**
 * API helpers: authenticate API key and retrieve allowed amount.
 */
function requireApiKey($input) {
    $api_key = $input['api_key'] ?? '';
    if (!$api_key) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'API key required.']);
        exit();
    }
    $conn = connectDB();
    $conn->query("CREATE TABLE IF NOT EXISTS api_keys (api_key CHAR(40) PRIMARY KEY, amount DECIMAL(10,2) NOT NULL, created_by_id VARCHAR(36) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $stmt = $conn->prepare("SELECT amount FROM api_keys WHERE api_key = ?");
    $stmt->bind_param("s", $api_key);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    if (!$row) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Invalid API key.']);
        $conn->close();
        exit();
    }
    return [$conn, (float)$row['amount']];
}

function apiCreateLicense($input) {
    list($conn, $amount) = requireApiKey($input);
    // For bot-created license, expect: creator_id, package_id, duration_id, max_devices, cost
    $creator_id = $input['creator_id'] ?? null;
    $package_id = $input['package_id'] ?? null;
    $duration_id = $input['duration_id'] ?? null;
    $max_devices = (int)($input['max_devices'] ?? 1);
    $cost = (float)($input['cost'] ?? 0);
    if (!$creator_id || !$package_id || !$duration_id || $cost <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing fields for license creation.']);
        $conn->close();
        return;
    }
    if ($cost > $amount) {
        http_response_code(402);
        echo json_encode(['success' => false, 'message' => 'API key amount insufficient.']);
        $conn->close();
        return;
    }
    $conn->begin_transaction();
    // Deduct from user's balance and API key allowance
    $stmt = $conn->prepare("SELECT balance FROM users WHERE user_id = ? FOR UPDATE");
    $stmt->bind_param("s", $creator_id);
    $stmt->execute();
    $userBalance = $stmt->get_result()->fetch_assoc()['balance'] ?? 0;
    $stmt->close();
    if ($userBalance < $cost) {
        $conn->rollback();
        http_response_code(402);
        echo json_encode(['success' => false, 'message' => 'User balance insufficient.']);
        $conn->close();
        return;
    }
    // Claim a pre-added key from the pool managed by owner
    $claimed = claimPreAddedKey($conn);
    if (!$claimed) {
        $conn->rollback();
        http_response_code(409);
        echo json_encode(['success' => false, 'message' => 'No pre-added keys available. Contact owner.']);
        $conn->close();
        return;
    }
    $key_string = $claimed['key_string'];
    // If owner attached duration to the key, prefer it
    $duration_id = $claimed['duration'] ?: $duration_id;
    $expires = NULL;
    $sql = "INSERT INTO licenses (key_string, game_package, duration, max_devices, devices_used, status, creator_id, expires) VALUES (?, ?, ?, ?, 0, 'Issued', ?, ?)";
    $stmt = $conn->prepare($sql);
    if (!$stmt->bind_param("sssiss", $key_string, $package_id, $duration_id, $max_devices, $creator_id, $expires) || !$stmt->execute()) {
        $conn->rollback();
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'API key license creation failed.']);
        $conn->close();
        return;
    }
    $newBalance = $userBalance - $cost;
    $stmt = $conn->prepare("UPDATE users SET balance = ? WHERE user_id = ?");
    $stmt->bind_param("ds", $newBalance, $creator_id);
    $stmt->execute();
    // Reduce API key allowance
    $stmt = $conn->prepare("UPDATE api_keys SET amount = amount - ? WHERE api_key = ?");
    $stmt->bind_param("ds", $cost, $input['api_key']);
    $stmt->execute();
    $conn->commit();
    echo json_encode(['success' => true, 'data' => ['key_string' => $key_string, 'new_balance' => $newBalance]]);
    $conn->close();
}

function apiResetLicense($input) {
    list($conn, $amount) = requireApiKey($input);
    $license_id = (int)($input['license_id'] ?? 0);
    $creator_id = $input['creator_id'] ?? null;
    if (!$license_id || !$creator_id) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing license_id/creator_id.']);
        $conn->close();
        return;
    }
    $stmt = $conn->prepare("UPDATE licenses SET devices_used = 0, linked_device_id = NULL WHERE license_id = ? AND creator_id = ?");
    $stmt->bind_param("is", $license_id, $creator_id);
    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo json_encode(['success' => true]);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'License not found or unauthorized.']);
    }
    $conn->close();
}

function apiDeleteLicense($input) {
    list($conn, $amount) = requireApiKey($input);
    $license_id = (int)($input['license_id'] ?? 0);
    if (!$license_id) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Missing license_id.']);
        $conn->close();
        return;
    }
    $stmt = $conn->prepare("DELETE FROM licenses WHERE license_id = ?");
    $stmt->bind_param("i", $license_id);
    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo json_encode(['success' => true]);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'License not found.']);
    }
    $conn->close();
}


/**
 * Resets a user's login token (simulated by updating password hash).
 */
function resetUserLoginKey($current_user_id, $role, $target_user_id) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required to reset login.']);
        return;
    }
    
    $conn = connectDB();
    $new_hash = password_hash(bin2hex(random_bytes(8)), PASSWORD_DEFAULT);
    $sql = "UPDATE users SET password_hash = ?, status = 'Active' WHERE user_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $new_hash, $target_user_id);

    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo json_encode(['success' => true, 'message' => "User $target_user_id login token reset. User forced to re-login."]);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Login reset failed or user not found.']);
    }
    $conn->close();
}

/**
 * Blocks a user's account by updating their status.
 */
function blockUser($current_user_id, $role, $target_user_id) {
    if (!checkRole($role, 'admin')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Admin authorization required to block user.']);
        return;
    }
    
    if ($target_user_id === $current_user_id) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Cannot block self.']);
        return;
    }

    $conn = connectDB();
    $sql = "UPDATE users SET status = 'Blocked' WHERE user_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $target_user_id);

    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo json_encode(['success' => true, 'message' => "User $target_user_id account blocked."]);
    } else {
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Blocking failed or user not found.']);
    }
    $conn->close();
}

/**
 * Permanently deletes a user account.
 */
function deleteUserAccount($current_user_id, $role, $target_user_id) {
    if (!checkRole($role, 'owner')) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Owner authorization required for permanent deletion.']);
        return;
    }

    if ($target_user_id === $current_user_id) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Cannot delete your own account via this panel.']);
        return;
    }

    $conn = connectDB();
    $conn->begin_transaction();

    try {
        $stmt = $conn->prepare("DELETE FROM licenses WHERE creator_id = ?");
        $stmt->bind_param("s", $target_user_id);
        $stmt->execute();
        
        $stmt = $conn->prepare("DELETE FROM users WHERE user_id = ?");
        $stmt->bind_param("s", $target_user_id);
        $stmt->execute();
        
        if ($stmt->affected_rows === 0) {
            $conn->rollback();
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'User not found for deletion.']);
            $conn->close();
            return;
        }

        $conn->commit();
        echo json_encode(['success' => true, 'message' => "User $target_user_id and all associated data permanently deleted."]);
        
    } catch (Exception $e) {
        $conn->rollback();
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Deletion failed due to database error.']);
    }
    $conn->close();
}

/**
 * User: change own password (requires current password).
 */
function changePassword($user_id, $current_password, $new_password) {
    if (!$new_password || strlen($new_password) < 8) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'New password must be at least 8 characters.']);
        return;
    }
    $conn = connectDB();
    $stmt = $conn->prepare("SELECT password_hash FROM users WHERE user_id = ?");
    $stmt->bind_param("s", $user_id);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if (!$row || !password_verify($current_password, $row['password_hash'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Current password is incorrect.']);
        $conn->close();
        return;
    }
    $new_hash = password_hash($new_password, PASSWORD_DEFAULT);
    $stmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE user_id = ?");
    $stmt->bind_param("ss", $new_hash, $user_id);
    if ($stmt->execute() && $stmt->affected_rows > 0) {
        echo json_encode(['success' => true, 'message' => 'Password updated successfully.']);
    } else {
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Password update failed.']);
    }
    $conn->close();
}
?>