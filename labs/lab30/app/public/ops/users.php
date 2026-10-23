<?php
require __DIR__.'/../../src/bootstrap.php';$u=require_user();$role=(string)($_COOKIE['role']??$u['role']);if($role!=='admin')fail_request('人员管理需要管理员权限。',403);
$rows=db()->query('SELECT id,username,email,role FROM users ORDER BY id')->fetchAll();
if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['access'=>'admin','users'=>$rows]);
page('人员与权限管理',function()use($rows){echo '<section class="panel"><span class="badge">管理员工作区</span><h2>账户权限清单</h2><table><thead><tr><th>用户名</th><th>邮箱</th><th>角色</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['username']).'</td><td>'.h($r['email']).'</td><td>'.h($r['role']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
