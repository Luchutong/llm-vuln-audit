<?php
// 用户资料：入口把查询转发给公共的数据访问助手。
require 'helpers/db_lookup.php';

$id = $_GET['id'];
$rows = db_lookup_users($id);
foreach ($rows as $row) {
    echo $row['username'] . ':' . $row['email'] . "\n";
}
