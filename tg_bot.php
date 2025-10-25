<?php
// Lightweight Telegram bot endpoint to receive webhook updates and respond
// Secure with TG_WEBHOOK_SECRET via query (?secret=...) or set a unique path on your server

require_once __DIR__ . '/config.php';

header('Content-Type: application/json; charset=UTF-8');
applySecurityHeaders('application/json');

// Optional simple shared-secret gate
$provided = $_GET['secret'] ?? '';
if (TG_WEBHOOK_SECRET !== '' && $provided !== TG_WEBHOOK_SECRET) {
  http_response_code(403);
  echo json_encode(['ok' => false]);
  exit;
}

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
if ((string)$chatId !== (string)TG_CHAT_ID) { echo json_encode(['ok'=>true]); exit; }

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
