<?php
require __DIR__.'/../../src/bootstrap.php';$name=(string)($_GET['page']??'home');
page('内容中心',function()use($name){include APP_ROOT.'/resources/views/'.$name.'.php';echo '<section class="panel"><a href="?page=home">商城介绍</a> · <a href="?page=shipping">配送与售后</a></section>';},'内容中心');
