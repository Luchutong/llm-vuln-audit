<?php
// 主机巡检：入口把主机参数交给公共的命令执行助手。
require 'helpers/run_cmd.php';

$host = $_GET['host'];
echo run_host_check($host);
