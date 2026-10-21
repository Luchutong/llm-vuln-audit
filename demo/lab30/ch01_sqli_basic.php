<?php
// 用户查询接口：根据 id 查询用户资料。
$mysqli = new mysqli('localhost', 'app', 'secret', 'shop');

$id = $_GET['id'];
$sql = "SELECT username, email FROM users WHERE id = " . $id;
$result = $mysqli->query($sql);

while ($row = $result->fetch_assoc()) {
    echo $row['username'] . ':' . $row['email'] . "\n";
}
