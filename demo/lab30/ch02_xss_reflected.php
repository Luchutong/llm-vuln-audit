<?php
// 欢迎页：把请求中的名字原样回显给访问者。
$name = $_GET['name'] ?? 'guest';
?>
<!doctype html>
<html>
<body>
<h1>Welcome</h1>
<p>Hello, <?php echo $name; ?>!</p>
</body>
</html>
