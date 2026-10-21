<?php
// 公共数据访问助手：按 id 查询用户（供多个入口复用）。
function db_lookup_users($id)
{
    $mysqli = new mysqli('localhost', 'app', 'secret', 'shop');
    $sql = "SELECT username, email FROM users WHERE id = " . $id;
    $result = $mysqli->query($sql);
    $rows = [];
    while ($row = $result->fetch_assoc()) {
        $rows[] = $row;
    }
    return $rows;
}
