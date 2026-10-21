<?php
// 链接预览：抓取用户提供的 URL 并展示其内容。
$url = $_GET['url'];
$content = file_get_contents($url);
echo htmlspecialchars($content);
