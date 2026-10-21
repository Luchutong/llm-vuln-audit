<?php
// 资料更新：把客户端提交的字段原样批量写入用户记录，未做字段白名单。
$pdo = new PDO('mysql:host=localhost;dbname=shop', 'app', 'secret');
$userId = 1;

foreach ($_POST as $field => $value) {
    if ($field === 'submit') {
        continue;
    }
    $pdo->query("UPDATE users SET " . $field . " = '" . $value . "' WHERE id = " . $userId);
}
echo '资料已更新';
