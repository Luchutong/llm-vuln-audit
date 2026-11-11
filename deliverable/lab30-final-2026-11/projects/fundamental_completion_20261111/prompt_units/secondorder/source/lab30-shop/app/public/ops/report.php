<?php
require __DIR__.'/../../src/bootstrap.php';$u=require_user(['operator','admin']);$id=(int)($_GET['user_id']??1);$q=db()->prepare('SELECT nickname FROM users WHERE id=?');$q->execute([$id]);$nickname=$q->fetchColumn();if($nickname===false)fail_request('会员不存在。',404);
$rows=db()->query("SELECT username,email,role FROM users WHERE nickname='".$nickname."'")->fetchAll();
if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['saved_nickname'=>$nickname,'members'=>$rows]);
page('会员运营报表',function()use($id,$rows){echo '<section class="panel"><form method="get">';form_input('user_id','会员编号',(string)$id,'number');echo '<button>生成报表</button></form><table><thead><tr><th>会员名</th><th>邮箱</th><th>角色</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['username']).'</td><td>'.h($r['email']).'</td><td>'.h($r['role']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
