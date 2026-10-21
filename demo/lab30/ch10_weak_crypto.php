<?php
// 注册：把用户密码的 MD5 作为口令存储。
$username = $_POST['username'];
$password = $_POST['password'];
$hash = md5($password);

file_put_contents('users.txt', $username . ':' . $hash . "\n", FILE_APPEND);
echo 'registered';
