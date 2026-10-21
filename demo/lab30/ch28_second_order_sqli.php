<?php
// 二次注入：先把昵称保存，查询时再把它拼接进 SQL。
$mysqli = new mysqli('localhost', 'app', 'secret', 'shop');

if (!empty($_POST['nickname'])) {
    $nick = $_POST['nickname'];
    $mysqli->query("UPDATE users SET nickname = '" . $nick . "' WHERE id = 1");
}

$row = $mysqli->query("SELECT nickname FROM users WHERE id = 1")->fetch_assoc();
$nickname = $row['nickname'];
$result = $mysqli->query("SELECT username FROM users WHERE nickname = '" . $nickname . "'");
while ($line = $result->fetch_assoc()) {
    echo $line['username'] . "\n";
}
