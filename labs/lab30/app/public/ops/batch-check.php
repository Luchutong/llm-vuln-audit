<?php
require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/host_check.php';require_user(['operator','admin']);$host=(string)($_GET['host']??'');$output=$host!==''?host_check($host):'';
page('主机巡检',function()use($host,$output){echo '<section class="panel"><form method="get">';form_input('host','巡检主机',$host?:'127.0.0.1');echo '<button>委托巡检</button></form><pre>'.h($output).'</pre></section>';},'运营工作台');
