<?php
// 登录后跳转：登录成功后按 next 参数重定向。
session_start();
if (!empty($_POST['username']) && !empty($_POST['password'])) {
    $_SESSION['user'] = $_POST['username'];
    header('Location: ' . ($_POST['next'] ?? '/home'));
    exit;
}
