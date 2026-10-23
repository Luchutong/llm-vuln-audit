<?php
require __DIR__.'/../../src/bootstrap.php';require_user();
if(isset($_GET['file'])){$path=data_dir().'/docs/'.(string)$_GET['file'];if(!is_file($path))fail_request('文档不存在。',404);header('Content-Type: text/plain; charset=utf-8');echo file_get_contents($path);exit;}
page('帮助文档',function(){echo '<section class="panel"><h2>常用服务文档</h2><ul><li><a href="?file=shipping.txt">配送说明</a></li><li><a href="?file=returns.txt">售后说明</a></li></ul><form method="get">';form_input('file','文档文件名','shipping.txt');echo '<button>查看文档</button></form></section>';},'客服与帮助');
