<?php
require __DIR__.'/../../src/bootstrap.php';$u=require_user();$url=(string)($_GET['url']??$u['homepage']);
page('个人主页预览',function()use($u,$url){echo '<section class="panel"><h2>'.h($u['display_name']).' 的主页</h2><p><a id="profile-link" href="'.$url.'">访问个人主页</a></p><form method="get">';form_input('url','主页链接',$url);echo '<button>预览链接</button></form></section>';},'账户与会员');
