<?php
// 个人主页：把用户提供的链接渲染进属性上下文。
$url = $_GET['url'] ?? '#';
?>
<!doctype html>
<html><body>
<p>你的主页：<a href="<?php echo $url; ?>">点击访问</a></p>
</body></html>
