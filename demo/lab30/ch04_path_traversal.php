<?php
// 文档下载：按文件名读取并返回文档内容。
$file = $_GET['file'];
$content = file_get_contents('docs/' . $file);
header('Content-Type: text/plain');
echo $content;
