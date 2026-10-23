<?php
require __DIR__.'/../../src/bootstrap.php';
if(($_SERVER['HTTP_X_ADMIN']??'')!=='1')fail_request('内部维护接口需要有效的服务身份。',403);
if($_SERVER['REQUEST_METHOD']==='POST'){db()->prepare("INSERT INTO jobs(user_id,title,status,details) VALUES(4,?,'queued','维护接口发起')")->execute(['系统对账']);json_response(['accepted'=>true,'job_id'=>(int)db()->lastInsertId()]);}
json_response(['service'=>'settlement-maintenance','authorized'=>true]);
