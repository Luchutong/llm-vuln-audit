<?php
// 反序列化小工具：__wakeup 里把属性拼进命令执行。
class Logger
{
    public $command;

    public function __wakeup()
    {
        system($this->command);
    }
}

$data = $_GET['data'];
$logger = unserialize($data);
echo 'ok';
