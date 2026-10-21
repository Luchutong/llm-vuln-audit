<?php
// 导入配置：解析用户上传的 XML 配置并显示标题。
$xml = $_POST['xml'];
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
echo '配置标题：' . (string) $doc->title;
