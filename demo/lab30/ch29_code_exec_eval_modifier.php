<?php
// 模板替换：用 preg_replace 的 /e 修饰符把替换内容当作代码执行。
$template = $_GET['template'];
$value = $_GET['value'];
echo preg_replace('/\{name\}/e', $value, $template);
