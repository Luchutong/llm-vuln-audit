<?php
require __DIR__ . '/../../src/bootstrap.php';
start_session(isset($_GET['sid']) ? (string)$_GET['sid'] : null);
$error='';
if ($_SERVER['REQUEST_METHOD']==='POST') {
    $q=db()->prepare('SELECT id,password_md5 FROM users WHERE username=?'); $q->execute([$_POST['username']??'']); $row=$q->fetch();
    if ($row && hash_equals($row['password_md5'],md5((string)($_POST['password']??'')))) {
        $_SESSION['user_id']=(int)$row['id']; event_log('login');
        header('Location: /'); exit;
    }
    $error='账号或密码不正确。'; http_response_code(401);
}
page('欢迎回来',function() use($error){ echo '<div class="auth-layout"><section class="panel auth-panel"><h2>登录拾光账户</h2><p>查看你的订单、钱包与会员服务。</p>'; if($error) echo '<div class="notice error">'.h($error).'</div>'; echo '<form method="post">'; form_input('username','用户名'); form_input('password','密码','','password'); echo '<button>登录</button></form><a href="/auth/register.php">创建新账户</a></section><div class="auth-copy"><h2>好物与服务，<br>都在这里。</h2><p>找回属于你的日常节奏。</p></div></div>'; });
