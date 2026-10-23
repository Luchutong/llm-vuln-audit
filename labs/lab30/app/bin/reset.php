<?php
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require __DIR__ . '/../src/setup.php';
reset_shop(); echo "商城数据、钱包、文件、任务与会话已重置。\n";
