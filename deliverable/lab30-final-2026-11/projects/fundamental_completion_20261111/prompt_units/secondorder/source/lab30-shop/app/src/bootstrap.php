<?php
declare(strict_types=1);
const APP_ROOT = __DIR__ . '/..';
function db(): PDO {
    static $pdo;
    if (!$pdo) $pdo = new PDO('mysql:host=' . (getenv('DB_HOST') ?: 'db') . ';dbname=' . (getenv('DB_NAME') ?: 'shop') . ';charset=utf8mb4', getenv('DB_USER') ?: 'shop', getenv('DB_PASSWORD') ?: 'shop-local-password', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]);
    return $pdo;
}
function data_dir(): string { return getenv('SHOP_DATA_DIR') ?: '/var/lib/shop'; }
function h(mixed $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function start_session(?string $sid = null): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    ini_set('session.use_strict_mode', '0');
    session_save_path(data_dir() . '/sessions');
    session_name('SHOPSESSID');
    session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'path' => '/']);
    if ($sid !== null && preg_match('/^[a-zA-Z0-9,-]{16,64}$/D', $sid)) session_id($sid);
    session_start();
}
function user(): ?array {
    start_session();
    if (empty($_SESSION['user_id'])) return null;
    $q = db()->prepare('SELECT id,username,display_name,email,role,balance,tier,nickname,homepage FROM users WHERE id=?');
    $q->execute([$_SESSION['user_id']]); return $q->fetch() ?: null;
}
function json_response(mixed $value, int $status = 200): never {
    http_response_code($status); header('Content-Type: application/json; charset=utf-8'); echo json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); exit;
}
function fail_request(string $message, int $status = 400): never {
    if (str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json')) json_response(['error' => $message], $status);
    http_response_code($status); page('请求未完成', function() use ($message) { echo '<div class="notice error" role="alert">' . h($message) . '</div><div class="actions"><a class="button" href="/auth/login.php">前往登录</a><a class="button secondary" href="/">返回首页</a></div>'; }); exit;
}
function require_user(array $roles = []): array {
    $u = user(); if (!$u) fail_request('请先登录后使用此功能。', 401);
    if ($roles && !in_array($u['role'], $roles, true)) fail_request('当前账号没有访问该功能的权限。', 403);
    return $u;
}
function csrf_token(): string { start_session(); return $_SESSION['csrf'] ??= bin2hex(random_bytes(24)); }
function csrf_field(): string { return '<input type="hidden" name="csrf" value="' . h(csrf_token()) . '">'; }
function check_csrf(): void { if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) fail_request('页面已过期，请刷新后重试。', 403); }
function event_log(string $action, array $data = []): void {
    $q = db()->prepare('INSERT INTO events(user_id,action,details) VALUES(?,?,?)');
    $q->execute([$_SESSION['user_id'] ?? null, $action, json_encode($data, JSON_UNESCAPED_UNICODE)]);
}
function require_post(): void { if ($_SERVER['REQUEST_METHOD'] !== 'POST') fail_request('此操作需要 POST 请求。', 405); }
function form_input(string $name, string $label, string $value = '', string $type = 'text'): void { echo '<label>' . h($label) . '<input name="' . h($name) . '" type="' . h($type) . '" value="' . h($value) . '" required></label>'; }
function page(string $title, callable $body, string $section = ''): void {
    db();
    $u = user();
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>' . h($title) . ' · 拾光商城</title><meta name="theme-color" content="#1b573f"><link rel="stylesheet" href="/assets/app.css"><script src="/assets/app.js" defer></script></head><body><div class="shell"><aside><a class="brand" href="/"><span>拾</span><div>拾光商城<small>SHIGUANG COMMERCE</small></div></a><nav>';
    $nav = ['/' => '工作台', '/catalog/index.php' => '商品目录', '/orders/index.php' => '订单中心', '/wallet/index.php' => '我的钱包', '/account/index.php' => '账户与会员', '/support/index.php' => '客服与帮助', '/content/page.php' => '内容中心', '/ops/index.php' => '运营工作台'];
    if (!$u || !in_array($u['role'], ['operator','admin'], true)) unset($nav['/ops/index.php']);
    foreach ($nav as $url => $label) echo '<a ' . ($section === $label ? 'class="active" ' : '') . 'href="' . $url . '">' . $label . '</a>';
    echo '</nav><div class="side-bottom">本地演示商城<small>数据可通过重置命令恢复</small></div></aside><main><header class="topbar"><a class="mobile-brand" href="/">拾光商城</a><span>商城工作空间 / ' . h($title) . '</span><div>';
    if ($u) echo '<span>' . h($u['display_name']) . '</span><a href="/account/index.php">我的账户</a><a href="/auth/logout.php">退出</a>';
    else echo '<a href="/auth/login.php">登录</a><a href="/auth/register.php">注册</a>';
    echo '</div></header><div class="content"><div class="page-heading"><span class="eyebrow">SHIGUANG WORKSPACE</span><h1>' . h($title) . '</h1></div>';
    $body();
    echo '</div><footer>拾光商城 · 会员、订单与运营协作平台 <span>版本 ' . h(trim(file_get_contents(APP_ROOT . '/VERSION'))) . '</span></footer></main></div></body></html>';
}
set_exception_handler(function(Throwable $error) {
    error_log((string)$error);
    if (!headers_sent()) http_response_code(503);
    if (str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json')) { header('Content-Type: application/json'); echo json_encode(['error' => '服务暂时不可用，请稍后重试。']); }
    else echo '<!doctype html><meta charset="utf-8"><title>服务暂不可用</title><h1>服务暂时不可用</h1><p>数据库或依赖服务尚未就绪，请稍后重试。</p>';
});
