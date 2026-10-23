<?php
require __DIR__.'/../../src/bootstrap.php';require_user();
if(isset($_GET['next'])){header('Location: '.(string)$_GET['next']);exit;}
page('继续访问',function(){echo '<section class="panel"><h2>选择下一站</h2><form method="get">';form_input('next','继续访问地址','/orders/index.php');echo '<button>继续</button></form></section>';});
