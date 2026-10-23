<?php
require __DIR__.'/../../src/bootstrap.php';require_user(['operator','admin']);$rows=db()->query('SELECT e.*,u.username FROM events e LEFT JOIN users u ON u.id=e.user_id ORDER BY e.id DESC LIMIT 100')->fetchAll();
page('业务操作记录',function()use($rows){echo '<section class="panel"><table><thead><tr><th>操作人</th><th>操作</th><th>详情</th><th>时间</th></tr></thead><tbody>';foreach($rows as$r)echo '<tr><td>'.h($r['username']).'</td><td>'.h($r['action']).'</td><td>'.h($r['details']).'</td><td>'.h($r['created_at']).'</td></tr>';echo '</tbody></table></section>';},'运营工作台');
