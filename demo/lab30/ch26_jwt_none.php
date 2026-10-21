<?php
// 令牌验证：按 "." 拆分 JWT，只解码载荷、不校验签名和算法。
$token = $_COOKIE['token'] ?? '';
$parts = explode('.', $token);
if (count($parts) === 3) {
    $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
    if ($payload['role'] === 'admin') {
        echo '欢迎管理员';
        exit;
    }
}
echo '无权限';
