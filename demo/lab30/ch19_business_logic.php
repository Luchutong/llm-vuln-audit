<?php
// 下单：直接使用客户端提交的单价与数量计算总价。
$price = $_POST['price'];
$quantity = $_POST['quantity'];
$total = $price * $quantity;

echo '应付金额：' . $total;
file_put_contents('orders.txt', 'total=' . $total . "\n", FILE_APPEND);
