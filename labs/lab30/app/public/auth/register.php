<?php
require __DIR__ . '/../../src/bootstrap.php';
$notice='';
if($_SERVER['REQUEST_METHOD']==='POST') {
    $name=(string)($_POST['username']??''); $password=(string)($_POST['password']??'');
    if(!preg_match('/^[a-zA-Z][a-zA-Z0-9_]{2,39}$/D',$name)||strlen($password)<8) fail_request('用户名需为 3–40 位字母数字，密码至少 8 位。');
    $q=db()->prepare('INSERT INTO users(username,password_md5,display_name,email,role,balance,tier,nickname) VALUES(?,?,?,?,?,100,?,?)');
    try {$q->execute([$name,md5($password),$name,(string)($_POST['email']??''),'customer','standard',$name]); $notice='注册成功，现在可以登录。';} catch(PDOException $e) {fail_request('该用户名已注册。',409);}
}
page('创建账户',function()use($notice){echo '<section class="panel narrow">';if($notice)echo '<div class="notice">'.h($notice).'</div>';echo '<form method="post">';form_input('username','用户名');form_input('email','邮箱','','email');form_input('password','密码（至少 8 位）','','password');echo '<button>注册账户</button></form><a href="/auth/login.php">已有账户，去登录</a></section>';});
