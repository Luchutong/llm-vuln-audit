<?php
// 账户设置：登录用户修改自己的邮箱，无任何一次性令牌校验。
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];
    file_put_contents('users/' . $_SESSION['user'] . '.txt', $email);
    echo '邮箱已更新';
}
