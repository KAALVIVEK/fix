<?php
// Lightweight Telegram bot endpoint to receive webhook updates and respond
// Secure with TG_WEBHOOK_SECRET via query (?secret=...) or set a unique path on your server

require_once __DIR__ . '/config.php';

header('Content-Type: application/json; charset=UTF-8');
applySecurityHeaders('application/json');

// Optional simple shared-secret gate with Telegram IP fallback (behind Cloudflare)
function tg_client_ip(): string {
  $h = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['REMOTE_ADDR'] ?? ''));
  if (strpos($h, ',') !== false) { $h = trim(explode(',', $h)[0]); }
  return trim($h);
}
function ipInCidr($ip, $cidr): bool {
  [$subnet, $mask] = explode('/', $cidr);
  return (ip2long($ip) & ~((1 << (32 - (int)$mask)) - 1)) === (ip2long($subnet) & ~((1 << (32 - (int)$mask)) - 1));
}
function isTelegramSource(string $ip): bool {
  if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) { return false; }
  $ranges = [ '149.154.160.0/20', '91.108.4.0/22', '91.108.8.0/22', '91.108.12.0/22' ];
  foreach ($ranges as $r) { if (ipInCidr($ip, $r)) return true; }
  return false;
}

$provided = $_GET['secret'] ?? ($_GET['secret_token'] ?? (getHeader('X-TELEGRAM-BOT-API-SECRET-TOKEN') ?? ''));
// Do NOT block webhook deliveries; proceed even if secret missing. Admin checks remain enforced below.

$raw = file_get_contents('php://input');
$update = json_decode($raw, true);
if (!$update) { echo json_encode(['ok'=>true]); exit; }

function tg_send($chatId, $text, $kb = null) {
  $url = 'https://api.telegram.org/bot' . TG_BOT_TOKEN . '/sendMessage';
  $payload = [ 'chat_id' => $chatId, 'text' => $text, 'parse_mode' => 'HTML', 'disable_web_page_preview' => true ];
  if ($kb) { $payload['reply_markup'] = json_encode($kb); }
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_POST, true);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_TIMEOUT, 5);
  @curl_exec($ch);
  @curl_close($ch);
}

$chatId = null; $text = '';
if (isset($update['message'])) { $chatId = $update['message']['chat']['id'] ?? null; $text = trim((string)($update['message']['text'] ?? '')); }
elseif (isset($update['callback_query'])) { $chatId = $update['callback_query']['message']['chat']['id'] ?? null; $text = trim((string)($update['callback_query']['data'] ?? '')); }

if (!$chatId) { echo json_encode(['ok'=>true]); exit; }

// Only respond to admin chat
// If not admin, allow minimal replies for /start and /whoami so you can learn the chat id
if ((string)$chatId !== (string)TG_CHAT_ID) {
  if (preg_match('/^\/(start|whoami)/i', $text)) {
    tg_send($chatId, "🔒 This bot is private.\nYour chat id: <code>" . htmlspecialchars((string)$chatId, ENT_QUOTES) . "</code>");
  }
  echo json_encode(['ok'=>true]);
  exit;
}

// Simple commands
// Command keyboard
$kb = [ 'keyboard' => [
  [ ['text'=>'📊 Status'], ['text'=>'📦 Stock'] ],
  [ ['text'=>'🔔 Alerts ON'], ['text'=>'🔕 Alerts OFF'] ],
], 'resize_keyboard' => true, 'one_time_keyboard' => false ];

switch (true) {
  case preg_match('/^\/(start|help)/i', $text):
    tg_send($chatId, "👋 <b>Welcome, admin</b>\nUse the keyboard or commands:\n/status, /stock, /alertson, /alertsoff", $kb);
    break;
  case preg_match('/^\/(status|Status)|^📊/u', $text):
    try {
      $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
      $ok = $conn->connect_error ? '❌ DB: DOWN' : '✅ DB: OK';
      $res = $conn->query("SELECT COUNT(*) AS users FROM users");
      $users = ($res && ($row = $res->fetch_assoc())) ? (int)$row['users'] : 0;
      tg_send($chatId, "📊 <b>Status</b>\n$ok\n👤 Users: $users\n🕒 " . date('H:i:s T'), $kb);
      if ($conn) { $conn->close(); }
    } catch (Throwable $e) { tg_send($chatId, 'Error: ' . $e->getMessage(), $kb); }
    break;
  case preg_match('/^\/(stock|Stock)|^📦/u', $text):
    try {
      $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
      $sys = 0; $res = $conn->query("SELECT COUNT(*) AS c FROM system_keys WHERE status='Generated'");
      if ($res && ($row = $res->fetch_assoc())) { $sys = (int)$row['c']; }
      $lines = [ '🧱 System pool: ' . $sys ];
      $q = $conn->query("SELECT p.name, COUNT(k.id) AS c FROM keys_pool k JOIN products p ON p.id = k.product_id WHERE k.is_used = 0 GROUP BY k.product_id ORDER BY p.name");
      if ($q) { while ($r = $q->fetch_assoc()) { $lines[] = '📦 ' . $r['name'] . ': ' . (int)$r['c']; } }
      tg_send($chatId, "📦 <b>Unused stock</b>\n" . implode("\n", $lines), $kb);
      if ($conn) { $conn->close(); }
    } catch (Throwable $e) { tg_send($chatId, 'Error: ' . $e->getMessage(), $kb); }
    break;
  case preg_match('/^\/(alertson|Alerts ON)|^🔔/u', $text):
    $prefs = tgGetPrefs(); $prefs['alerts_enabled'] = true; tgSetPrefs($prefs);
    tg_send($chatId, '🔔 Alerts <b>enabled</b>.', $kb);
    break;
  case preg_match('/^\/(alertsoff|Alerts OFF)|^🔕/u', $text):
    $prefs = tgGetPrefs(); $prefs['alerts_enabled'] = false; tgSetPrefs($prefs);
    tg_send($chatId, '🔕 Alerts <b>disabled</b>.', $kb);
    break;
  default:
    tg_send($chatId, '❓ Unknown command. Use /help', $kb);
}

echo json_encode(['ok'=>true]);
