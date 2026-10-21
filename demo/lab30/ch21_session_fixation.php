<?php
// 会话接入：直接采用 URL 传入的会话 ID，登录成功后也不重新生成。
if (!empty($_GET['sid'])) {
    session_id($_GET['sid']);
}
session_start();

if (!empty($_POST['user']) && !empty($_POST['pass'])) {
    $_SESSION['user'] = $_POST['user'];
    echo '已登录';
}
