<?php
require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/member_lookup.php';require_user(['operator','admin']);$term=(string)($_GET['q']??'alice');$rows=member_lookup($term);
if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['members'=>$rows]);
page('会员查询',function()use($rows,$term){echo '<section class="panel"><form method="get">';form_input('q','会员名',$term);echo '<button>查询会员</button></form><table><thead><tr><th>编号</th><th>用户名</th><th>邮箱</th><th>角色</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['id']).'</td><td>'.h($r['username']).'</td><td>'.h($r['email']).'</td><td>'.h($r['role']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
