<?php
require __DIR__.'/../../src/bootstrap.php';$u=require_user();$notice='';
if($_SERVER['REQUEST_METHOD']==='POST'){
    check_csrf();$columns=['display_name','email','role','balance','tier','nickname','homepage'];$set=[];$values=[];
    foreach($_POST as$key=>$value)if(in_array($key,$columns,true)){$set[]='`'.$key.'`=?';$values[]=(string)$value;}
    if(!$set)fail_request('没有可更新的资料。');$values[]=$u['id'];db()->prepare('UPDATE users SET '.implode(',',$set).' WHERE id=?')->execute($values);event_log('update_profile',['fields'=>array_keys($_POST)]);$notice='资料已保存。';$u=user();
    if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response($u);
}
page('会员资料维护',function()use($u,$notice){echo '<section class="panel narrow">';if($notice)echo '<div class="notice">'.h($notice).'</div>';echo '<form method="post">'.csrf_field();form_input('display_name','显示名称',$u['display_name']);form_input('nickname','对外昵称',$u['nickname']);form_input('email','常用邮箱',$u['email'],'email');form_input('homepage','个人网站',$u['homepage']);echo '<button>保存资料</button></form></section>';},'账户与会员');
