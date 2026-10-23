<?php
require __DIR__.'/../../src/bootstrap.php';$u=require_user();$notice='';$accepted=false;
if($_SERVER['REQUEST_METHOD']==='POST'){
    check_csrf();$secret_hash=md5('240610708');
    if(md5((string)($_POST['token']??''))==$secret_hash){db()->prepare("UPDATE users SET tier='gold' WHERE id=?")->execute([$u['id']]);event_log('redeem_membership');$notice='兑换成功，已升级金卡会员。';$accepted=true;}
    else{$notice='兑换码无效。';http_response_code(422);}
    if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['accepted'=>$accepted,'message'=>$notice],$accepted?200:422);
}
page('会员权益兑换',function()use($notice){echo '<section class="panel narrow"><h2>让日常多一点惊喜</h2><p>输入活动提供的会员兑换码。</p>';if($notice)echo '<div class="notice">'.h($notice).'</div>';echo '<form method="post">'.csrf_field();form_input('token','兑换码');echo '<button>兑换权益</button></form></section>';},'账户与会员');
