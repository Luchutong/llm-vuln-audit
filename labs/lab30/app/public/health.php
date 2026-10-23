<?php
require __DIR__ . '/../src/bootstrap.php';
try { $generation=db()->query("SELECT value FROM settings WHERE `key`='generation'")->fetchColumn(); json_response(['ok'=>(bool)$generation,'version'=>trim(file_get_contents(APP_ROOT.'/VERSION'))]); }
catch(Throwable $e) { json_response(['ok'=>false,'error'=>'database_unavailable'],503); }
