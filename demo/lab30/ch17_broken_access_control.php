<?php
// 管理后台：仅当客户端 Cookie 中的 role 为 admin 时展示管理功能。
$role = $_COOKIE['role'] ?? 'guest';
if ($role === 'admin') {
    echo '欢迎管理员，这是用户管理面板。';
} else {
    echo '无权限';
}
