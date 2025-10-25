<?php
// =========================================================================
// ZTRAX AUTHENTICATION API - SECURE PHP BACKEND FOR LOGIN/SIGNUP
// =========================================================================
// SECURITY NOTE: Uses Prepared Statements, password hashing, HMAC tokens,
// restrictive CORS, and security headers.
// =========================================================================

require_once __DIR__ . '/config.php';

applyCors(true);
applySecurityHeaders('application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// --- Simple IP-based rate limiting (best-effort, file-backed) ---
function rl_key(string $action): string {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $dir = __DIR__ . '/storage';
    if (!is_dir($dir)) { @mkdir($dir, 0775, true); }
    return $dir . '/rl_' . preg_replace('/[^A-Za-z0-9_.-]/', '_', $action . '_' . $ip) . '.json';
}
function rateLimit(string $action, int $limit = 10, int $windowSec = 600): bool {
    $file = rl_key($action);
    $now = time();
    $data = ['start' => $now, 'count' => 0];
    if (is_file($file)) {
        $raw = @file_get_contents($file);
        $parsed = $raw ? json_decode($raw, true) : null;
        if (is_array($parsed) && isset($parsed['start'], $parsed['count'])) {
            $data = $parsed;
        }
        if (($now - (int)$data['start']) > $windowSec) {
            $data = ['start' => $now, 'count' => 0];
        }
    }
    $data['count'] = (int)$data['count'] + 1;
    @file_put_contents($file, json_encode($data), LOCK_EX);
    return $data['count'] <= $limit;
}

// --- 2. Input Handling and Routing ---
$input_json = file_get_contents('php://input');
$input_data = json_decode($input_json, true);

if (!isset($input_data['action'])) {
    http_response_code(400);
    echo json_encode(array("success" => false, "message" => "Missing action parameter."));
    exit;
}

$action = $input_data['action'];

try {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($conn->connect_error) {
        notifyTelegram('❌ <b>DB connect failed</b> in auth');
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    
    switch ($action) {
        case 'register_user':
            if (!rateLimit('register_user')) { http_response_code(429); $response = ["success"=>false, "message"=>"Too many attempts. Try later."]; break; }
            $response = handleRegistration($conn, $input_data);
            break;
        case 'login_user':
            if (!rateLimit('login_user')) { http_response_code(429); $response = ["success"=>false, "message"=>"Too many attempts. Try later."]; break; }
            $response = handleLogin($conn, $input_data);
            break;
        case 'set_client_key':
            $response = handleSetClientKey($conn, $input_data);
            break;
        case 'logout':
            // handleLogout will send its own response and exit to avoid echoing JSON
            handleLogout($conn, $input_data);
            // no break; unreachable
            break;
        default:
            $response = array("success" => false, "message" => "Invalid action requested.");
            http_response_code(400);
            break;
    }

} catch (Exception $e) {
    error_log('Auth server error: ' . $e->getMessage());
    $response = array("success" => false, "message" => "Server Error. Please try again later.");
    http_response_code(500);
} finally {
    if (isset($conn)) {
        $conn->close();
    }
}

echo json_encode($response);
exit;

// =========================================================================
// AUTHENTICATION FUNCTIONS
// =========================================================================

function handleRegistration($conn, $data) {
    $email = filter_var($data['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $password = $data['password'] ?? '';
    $nameRaw = trim((string)($data['name'] ?? 'Ztrax User'));
    $name = mb_substr(preg_replace('/[^\p{L}0-9 ._\-]/u', '', $nameRaw), 0, 64) ?: 'Ztrax User';
    $referral_code = strtoupper(trim($data['referral_code'] ?? ''));

    if (!$email || empty($password)) {
        http_response_code(400);
        return array("success" => false, "message" => "Invalid email or password.");
    }
    if (strlen($password) < 8) {
        http_response_code(400);
        return array("success" => false, "message" => "Password must be at least 8 characters.");
    }

    $stmt = $conn->prepare("SELECT user_id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        $stmt->close();
        http_response_code(409);
        return array("success" => false, "message" => "Email already registered. Try logging in.");
    }
    $stmt->close();

    // Defaults for no-referral signups
    $final_balance = 0.00;
    $final_role = 'user';
    $referred_by_id = null;

    // If a referral code was provided, validate and apply its attributes
    if (!empty($referral_code)) {
        $stmt = $conn->prepare("SELECT initial_balance, max_role, creator_id FROM referrals WHERE code = ?");
        $stmt->bind_param("s", $referral_code);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows !== 1) {
            http_response_code(400);
            return array("success" => false, "message" => "Invalid referral code.");
        }
        $referral_data = $result->fetch_assoc();
        $stmt->close();

        $final_balance = (float)$referral_data['initial_balance'];
        $final_role = $referral_data['max_role'];
        $referred_by_id = $referral_data['creator_id'];
    }
    $final_user_id = uniqid('UID-', true);

    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    $conn->begin_transaction();
    try {
        $sql = "INSERT INTO users (user_id, email, password_hash, role, balance, referred_by_id, name) 
                VALUES (?, ?, ?, ?, ?, ?, ?)";
        $stmt = $conn->prepare($sql);

        // fixed: bind_param types corrected
        $stmt->bind_param("ssssdss", 
            $final_user_id, 
            $email, 
            $password_hash, 
            $final_role, 
            $final_balance, 
            $referred_by_id,
            $name
        );
        
        if (!$stmt->execute()) {
            throw new Exception("Database INSERT failed.");
        }
        $stmt->close();

        $conn->commit();
        http_response_code(201);
        return array("success" => true, "message" => "Registration successful. You may now log in.");

    } catch (Exception $e) {
        $conn->rollback();
        error_log("Registration Transaction Failed: " . $e->getMessage());
        http_response_code(500);
        return array("success" => false, "message" => "Registration failed due to a server error. Try again later.");
    }
}

function handleLogin($conn, $data) {
    $email = filter_var($data['email'] ?? '', FILTER_VALIDATE_EMAIL);
    $password = $data['password'] ?? '';

    if (!$email || empty($password)) {
        http_response_code(400);
        return array("success" => false, "message" => "Invalid email or password format.");
    }

    $stmt = $conn->prepare("SELECT user_id, password_hash, role, status FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows !== 1) {
        $stmt->close();
        return array("success" => false, "message" => "Invalid credentials provided.");
    }

    $user = $result->fetch_assoc();
    $stmt->close();

    if (!password_verify($password, $user['password_hash'])) {
        return array("success" => false, "message" => "Invalid credentials provided.");
    }
    
    if ($user['status'] === 'Blocked') {
        return array("success" => false, "message" => "Access denied. Your account has been blocked.");
    }

    // Issue auth token and set secure cookie
    $token = createAuthToken($user['user_id'], $user['role']);
    setAuthCookie($token);

    http_response_code(200);
    $payload = array(
        "success" => true, 
        "message" => "Login successful.", 
        "user_id" => $user['user_id'],
        "role" => $user['role'],
        "token" => $token
    );
    // For compatibility, do NOT encrypt login response. Return plain JSON.
    return $payload;
}

function handleSetClientKey($conn, $data) {
    $uid = isset($data['user_id']) ? (string)$data['user_id'] : '';
    if ($uid === '') {
        $claims = verifyAuthToken(getTokenFromRequest());
        if (is_array($claims) && isset($claims['uid'])) { $uid = (string)$claims['uid']; }
    }
    $b64 = isset($data['client_key']) ? (string)$data['client_key'] : '';
    if ($uid === '' || $b64 === '') { http_response_code(400); return [ 'success'=>false, 'message'=>'Missing user_id/client_key' ]; }
    $ok = setClientEncKeyForUid($uid, $b64);
    if (!$ok) { http_response_code(400); return [ 'success'=>false, 'message'=>'Invalid client_key' ]; }
    return [ 'success'=>true, 'message'=>'Client key set' ];
}

function handleLogout($conn, $data) {
    $token = getTokenFromRequest();
    $claims = verifyAuthToken($token);
    // Invalidate cookie
    setcookie('ztrax_token', '', [ 'expires'=>time()-3600, 'path'=>'/', 'secure'=>(!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'), 'httponly'=>true, 'samesite'=>'Lax' ]);
    if (is_array($claims) && isset($claims['uid'])) {
        // Remove stored client key to prevent reuse of signatures
        deleteClientEncKeyForUid((string)$claims['uid']);
    }
    // Return empty 204 so browsers/devtools don't display HTML fallback
    http_response_code(204);
    header('Content-Type: text/plain; charset=UTF-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Content-Length: 0');
    exit;
}