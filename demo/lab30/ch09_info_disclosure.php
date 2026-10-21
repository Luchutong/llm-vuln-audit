<?php
// 数据库健康检查：连接失败时输出完整异常信息便于排查。
try {
    $pdo = new PDO('mysql:host=localhost;dbname=shop', 'app', 'secret');
} catch (Throwable $e) {
    echo '连接失败：' . $e->getMessage() . "\n";
    echo $e->getTraceAsString();
    exit;
}
echo 'ok';
