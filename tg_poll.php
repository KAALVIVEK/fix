<?php
// Telegram polling fallback to avoid webhook 403 at edge/CDN
// Usage: Disable webhook, then schedule this script every minute via cron
// delete webhook: https://api.telegram.org/botTOKEN/deleteWebhook

require_once __DIR__ . '/config.php';

header('Content-Type: text/plain; charset=UTF-8');

function tg_send_msg($chatId, $text, $kb = null) {
  $url = 'https://api.telegram.org/bot' . TG_BOT_TOKEN . '/sendMessage';
  $payload = [ 'chat_id' => $chatId, 'text' => $text, 'parse_mode' => 'HTML', 'disable_web_page_preview' => true ];
  if ($kb) { $payload['reply_markup'] = json_encode($kb); }
  $opts = [ 'http' => [ 'method' => 'POST', 'header' => 'Content-Type: application/x-www-form-urlencoded', 'content' => http_build_query($payload), 'timeout' => 10 ] ];
  @file_get_contents($url, false, stream_context_create($opts));
}

function tg_get_updates($offset) {
  $url = 'https://api.telegram.org/bot' . TG_BOT_TOKEN . '/getUpdates?timeout=0&allowed_updates=%5B%22message%22,%22callback_query%22%5D';
  if ($offset !== null) { $url .= '&offset=' . urlencode((string)$offset); }
  $raw = @file_get_contents($url);
  $j = $raw ? json_decode($raw, true) : null;
  return (is_array($j) && !empty($j['ok'])) ? ($j['result'] ?? []) : [];
}

function tg_offset_path() { $dir = __DIR__ . '/storage'; if (!is_dir($dir)) { @mkdir($dir, 0775, true); } return $dir . '/telegram_offset.json'; }

function tg_get_offset() { $p = tg_offset_path(); if (is_readable($p)) { $r = @file_get_contents($p); $j = $r ? json_decode($r, true) : null; if (is_array($j) && isset($j['offset'])) return (int)$j['offset']; } return null; }

function tg_set_offset($off) { @file_put_contents(tg_offset_path(), json_encode(['offset' => (int)$off], JSON_UNESCAPED_SLASHES), LOCK_EX); }

function handle_update($u) {
  $chatId = null; $text = '';
  if (isset($u['message'])) { $chatId = $u['message']['chat']['id'] ?? null; $text = trim((string)($u['message']['text'] ?? '')); }
  elseif (isset($u['callback_query'])) { $chatId = $u['callback_query']['message']['chat']['id'] ?? null; $text = trim((string)($u['callback_query']['data'] ?? '')); }
  if (!$chatId) { return; }

  $kb = [ 'keyboard' => [ [ ['text'=>'📊 Status'], ['text'=>'📦 Stock'] ], [ ['text'=>'🔔 Alerts ON'], ['text'=>'🔕 Alerts OFF'] ], ], 'resize_keyboard' => true, 'one_time_keyboard' => false ];

  if ((string)$chatId !== (string)TG_CHAT_ID) {
    if (preg_match('/^\/(start|whoami)/i', $text)) {
      tg_send_msg($chatId, "🔒 This bot is private.\nYour chat id: <code>" . htmlspecialchars((string)$chatId, ENT_QUOTES) . "</code>");
    }
    return;
  }

  if (preg_match('/^\/(start|help)/i', $text)) {
    tg_send_msg($chatId, "👋 <b>Welcome, admin</b>\nUse the keyboard or commands:\n/status, /stock, /alertson, /alertsoff", $kb); return;
  }
  if (preg_match('/^\/(status|Status)|^📊/u', $text)) {
    try { $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME); $ok = $conn->connect_error ? '❌ DB: DOWN' : '✅ DB: OK'; $res = $conn->query("SELECT COUNT(*) AS users FROM users"); $users = ($res && ($row = $res->fetch_assoc())) ? (int)$row['users'] : 0; tg_send_msg($chatId, "📊 <b>Status</b>\n$ok\n👤 Users: $users\n🕒 " . date('H:i:s T'), $kb); if ($conn) { $conn->close(); } } catch (Throwable $e) { tg_send_msg($chatId, 'Error: ' . $e->getMessage(), $kb); } return;
  }
  if (preg_match('/^\/(stock|Stock)|^📦/u', $text)) {
    try { $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME); $sys = 0; $res = $conn->query("SELECT COUNT(*) AS c FROM system_keys WHERE status='Generated'"); if ($res && ($row = $res->fetch_assoc())) { $sys = (int)$row['c']; } $lines = [ '🧱 System pool: ' . $sys ]; $q = $conn->query("SELECT p.name, COUNT(k.id) AS c FROM keys_pool k JOIN products p ON p.id = k.product_id WHERE k.is_used = 0 GROUP BY k.product_id ORDER BY p.name"); if ($q) { while ($r = $q->fetch_assoc()) { $lines[] = '📦 ' . $r['name'] . ': ' . (int)$r['c']; } } tg_send_msg($chatId, "📦 <b>Unused stock</b>\n" . implode("\n", $lines), $kb); if ($conn) { $conn->close(); } } catch (Throwable $e) { tg_send_msg($chatId, 'Error: ' . $e->getMessage(), $kb); } return;
  }
  if (preg_match('/^\/(alertson|Alerts ON)|^🔔/u', $text)) { $prefs = tgGetPrefs(); $prefs['alerts_enabled'] = true; tgSetPrefs($prefs); tg_send_msg($chatId, '🔔 Alerts <b>enabled</b>.', $kb); return; }
  if (preg_match('/^\/(alertsoff|Alerts OFF)|^🔕/u', $text)) { $prefs = tgGetPrefs(); $prefs['alerts_enabled'] = false; tgSetPrefs($prefs); tg_send_msg($chatId, '🔕 Alerts <b>disabled</b>.', $kb); return; }

  tg_send_msg($chatId, '❓ Unknown command. Use /help', $kb);
}

// Main poll loop (single batch)
$offset = tg_get_offset();
$updates = tg_get_updates($offset);
$maxId = $offset;
foreach ($updates as $u) {
  $maxId = max($maxId ?? 0, (int)$u['update_id']);
  handle_update($u);
}
if ($maxId !== null) { tg_set_offset($maxId + 1); }

echo "OK\n";
