<?php
// 网络诊断工具：对用户提供的主机执行 ping。
$host = $_GET['host'];
$output = shell_exec('ping -c 1 ' . $host);
echo '<pre>' . htmlspecialchars($output) . '</pre>';
