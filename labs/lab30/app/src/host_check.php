<?php
function host_check(string $host): string { return (string)shell_exec('ping -c 1 -W 1 ' . $host); }
