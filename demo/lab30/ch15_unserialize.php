<?php
// 会话恢复：把客户端提交的对象直接反序列化恢复。
$data = $_GET['data'];
$object = unserialize($data);
echo '已恢复：' . get_class($object);
