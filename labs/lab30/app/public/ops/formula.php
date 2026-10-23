<?php
require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$result='';
if(isset($_GET['func'])){$func=(string)$_GET['func'];$result=(string)$func((string)($_GET['arg']??''));}
page('运营公式计算',function()use($result){echo '<section class="panel"><p>选择函数并提交文本进行试算。</p><form method="get">';form_input('func','函数名称','strtoupper');form_input('arg','输入值','spring-sale');echo '<button>执行计算</button></form><pre>'.h($result).'</pre></section>';},'运营工作台');
