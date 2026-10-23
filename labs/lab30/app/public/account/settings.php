<?php
require __DIR__.'/../../src/bootstrap.php';$u=require_user();$notice='';
if($_SERVER['REQUEST_METHOD']==='POST'){
    $email=(string)($_POST['email']??'');if(!filter_var($email,FILTER_VALIDATE_EMAIL))fail_request('请输入有效邮箱。');
    db()->prepare('UPDATE users SET email=? WHERE id=?')->execute([$email,$u['id']]);event_log('update_email',['email'=>$email]);$u['email']=$email;$notice='邮箱已更新。';
    if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['email'=>$email,'updated'=>true]);
}
page('邮箱设置',function()use($u,$notice){echo '<section class="panel narrow">';if($notice)echo '<div class="notice">'.h($notice).'</div>';echo '<form method="post">';form_input('email','常用邮箱',$u['email'],'email');echo '<button>保存邮箱</button></form></section>';},'账户与会员');
