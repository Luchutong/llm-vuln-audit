<?php
// 订单详情：按订单号查询，使用预处理语句但没有校验订单归属。
$pdo = new PDO('mysql:host=localhost;dbname=shop', 'app', 'secret');
$stmt = $pdo->prepare('SELECT order_no, amount, owner FROM orders WHERE id = ?');
$stmt->execute([$_GET['id']]);
$order = $stmt->fetch(PDO::FETCH_ASSOC);
echo $order['order_no'] . ':' . $order['amount'];
