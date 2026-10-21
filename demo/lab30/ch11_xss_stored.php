<?php
// 留言板：保存访客留言并原样回显。
if (!empty($_POST['message'])) {
    file_put_contents('messages.txt', $_POST['message'] . "\n", FILE_APPEND);
}
?>
<!doctype html>
<html><body>
<h1>Guestbook</h1>
<ul>
<?php
foreach (file('messages.txt') ?: [] as $line) {
    echo '<li>' . $line . '</li>';
}
?>
</ul>
<form method="post"><textarea name="message"></textarea><button>提交</button></form>
</body></html>
