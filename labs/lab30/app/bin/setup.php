<?php
require __DIR__ . '/../src/setup.php';
try { $ready = db()->query("SELECT value FROM settings WHERE `key`='generation'")->fetchColumn(); } catch (Throwable $e) { $ready=false; }
if (!$ready) { reset_shop(); echo "商城初始数据已建立。\n"; } else echo "使用已有商城数据。\n";
