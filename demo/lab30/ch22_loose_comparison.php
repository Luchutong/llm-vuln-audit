<?php
// 令牌校验：用弱类型比较校验用户提交的令牌。
$secret_hash = '0e123456789012345678901234567890';
if (md5($_GET['token']) == $secret_hash) {
    echo '令牌有效，放行';
} else {
    echo '令牌无效';
}
