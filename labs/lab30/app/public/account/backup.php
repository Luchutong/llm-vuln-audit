<?php
require __DIR__.'/../../src/bootstrap.php';require __DIR__.'/../../src/backup.php';$u=require_user();$obj=new MemberBackup();$obj->tier=$u['tier'];$obj->displayName=$u['display_name'];$export=base64_encode(serialize($obj));$notice='';
if($_SERVER['REQUEST_METHOD']==='POST'){
    check_csrf();$raw=base64_decode((string)($_POST['backup']??''),true);if($raw===false)fail_request('备份格式不正确。');
    $restored=unserialize($raw);if(!$restored instanceof MemberBackup)fail_request('不是有效的会员备份。');
    db()->prepare('UPDATE users SET tier=?,display_name=? WHERE id=?')->execute([$restored->tier,$restored->displayName,$u['id']]);event_log('restore_member_backup');$notice='会员备份已恢复。';
}
page('会员备份与恢复',function()use($export,$notice){echo '<section class="panel"><h2>当前备份</h2><p>将备份保存到本地，便于恢复会员偏好。</p><textarea readonly aria-label="当前会员备份">'.h($export).'</textarea></section><section class="panel">';if($notice)echo '<div class="notice">'.h($notice).'</div>';echo '<h2>恢复备份</h2><form method="post">'.csrf_field().'<label>备份内容<textarea name="backup" required></textarea></label><button>恢复会员备份</button></form></section>';},'账户与会员');
