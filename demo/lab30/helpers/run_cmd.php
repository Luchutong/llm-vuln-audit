<?php
// 公共命令执行助手：对主机执行连通性检查（供多个入口复用）。
function run_host_check($host)
{
    return shell_exec('ping -c 1 ' . $host);
}
