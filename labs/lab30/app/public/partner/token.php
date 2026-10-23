<?php
require __DIR__.'/../../src/bootstrap.php';$u=require_user();
function b64url(string $s):string{return rtrim(strtr(base64_encode($s),'+/','-_'),'=');}
$header=b64url(json_encode(['alg'=>'HS256','typ'=>'JWT']));$payload=b64url(json_encode(['sub'=>$u['id'],'role'=>$u['role'],'name'=>$u['username']]));$key=db()->query("SELECT value FROM settings WHERE `key`='generation'")->fetchColumn();$token=$header.'.'.$payload.'.'.b64url(hash_hmac('sha256',$header.'.'.$payload,$key,true));
if(str_contains($_SERVER['HTTP_ACCEPT']??'','application/json'))json_response(['token'=>$token]);
page('合作方服务凭证',function()use($token){echo '<section class="panel"><h2>访问合作方工作台</h2><p>凭证代表当前账户的合作方身份。合作方结算工作台仅对管理员开放。</p><textarea readonly aria-label="合作方凭证">'.h($token).'</textarea><form action="/partner/portal.php" method="post"><input type="hidden" name="token" value="'.h($token).'"><button>进入合作方工作台</button></form></section>';},'账户与会员');
