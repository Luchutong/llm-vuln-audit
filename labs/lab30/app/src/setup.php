<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
function reset_shop(): void {
    $pdo = db();
    $pdo->exec("CREATE TABLE IF NOT EXISTS settings (`key` VARCHAR(100) PRIMARY KEY, value TEXT NOT NULL)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS users(id INT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(60) UNIQUE NOT NULL, password_md5 CHAR(32) NOT NULL, display_name VARCHAR(100) NOT NULL, email VARCHAR(200) NOT NULL, role VARCHAR(24) NOT NULL DEFAULT 'customer', balance DECIMAL(12,2) NOT NULL DEFAULT 100, tier VARCHAR(30) NOT NULL DEFAULT 'standard', nickname VARCHAR(200) NOT NULL, homepage VARCHAR(500) NOT NULL DEFAULT '#')");
    $pdo->exec("CREATE TABLE IF NOT EXISTS products(id INT PRIMARY KEY, name VARCHAR(100), description TEXT, price DECIMAL(12,2), stock INT, color VARCHAR(20))");
    $pdo->exec("CREATE TABLE IF NOT EXISTS orders(id INT PRIMARY KEY AUTO_INCREMENT, order_no VARCHAR(60), user_id INT, product_id INT, quantity INT, unit_price DECIMAL(12,2), total DECIMAL(12,2), private_note TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS withdrawals(id INT PRIMARY KEY AUTO_INCREMENT,user_id INT,amount DECIMAL(12,2),created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS messages(id INT PRIMARY KEY AUTO_INCREMENT,user_id INT,message TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS jobs(id INT PRIMARY KEY AUTO_INCREMENT,user_id INT,title VARCHAR(200),status VARCHAR(30),details TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $pdo->exec("CREATE TABLE IF NOT EXISTS events(id INT PRIMARY KEY AUTO_INCREMENT,user_id INT NULL,action VARCHAR(100),details TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
    $pdo->beginTransaction();
    foreach (['withdrawals','messages','jobs','events','orders','products','users','settings'] as $table) $pdo->exec("DELETE FROM $table");
    $q=$pdo->prepare('INSERT INTO users(id,username,password_md5,display_name,email,role,balance,tier,nickname) VALUES(?,?,?,?,?,?,100,?,?)');
    foreach ([[1,'alice','Alice123!','林晓','alice@shop.local','customer'],[2,'bob','Bob123!','陈远','bob@shop.local','customer'],[3,'operator','Ops123!','运营同事','ops@shop.local','operator'],[4,'admin','Admin123!','系统管理员','admin@shop.local','admin']] as $u) $q->execute([$u[0],$u[1],md5($u[2]),$u[3],$u[4],$u[5],'standard',$u[1]]);
    $p=$pdo->prepare('INSERT INTO products VALUES(?,?,?,?,?,?)');
    foreach ([[1,'晨光手冲壶','为每天的第一杯咖啡留一点仪式感。',129,50,'sand'],[2,'山野帆布包','轻装出发，也装得下日常。',79,120,'sage'],[3,'周末香氛蜡烛','雪松与柑橘，属于自己的慢时光。',59,80,'peach'],[4,'留白手账本','把新的想法留在纸上。',39,100,'cream']] as $row) $p->execute($row);
    $q=$pdo->prepare('INSERT INTO orders(id,order_no,user_id,product_id,quantity,unit_price,total,private_note) VALUES(?,?,?,?,?,?,?,?)');
    $q->execute([1,'SG-1001',1,1,1,129,129,'ALICE_PRIVATE_ORDER_delivery_morning']);
    $q->execute([2,'SG-1002',2,2,2,79,158,'BOB_PRIVATE_ORDER_gift_for_family']);
    $pdo->exec("INSERT INTO messages(user_id,message) VALUES(1,'包装很好，期待下次上新。'),(2,'请问帆布包可以机洗吗？')");
    $pdo->exec("INSERT INTO jobs(user_id,title,status,details) VALUES(3,'日常库存同步','completed','已同步 4 个商品')");
    $marker = 'SHOP_INTERNAL_' . bin2hex(random_bytes(12));
    $pdo->prepare('INSERT INTO settings(`key`,value) VALUES(?,?)')->execute(['internal_marker',$marker]);
    $pdo->prepare('INSERT INTO settings(`key`,value) VALUES(?,?)')->execute(['generation',bin2hex(random_bytes(12))]);
    $pdo->commit();
    foreach (['users'=>5,'orders'=>3,'withdrawals'=>1,'messages'=>3,'jobs'=>2,'events'=>1] as $table=>$next) $pdo->exec("ALTER TABLE `$table` AUTO_INCREMENT=$next");
    $root=data_dir();
    foreach (['sessions','vault','docs','messages','exports'] as $dir) { if (!is_dir("$root/$dir")) mkdir("$root/$dir",0770,true); }
    $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
    foreach($it as $file) if($file->isFile()) unlink($file->getPathname());
    file_put_contents("$root/vault/internal.txt",$marker . "\n");
    file_put_contents("$root/vault/account.php",'<?php echo "' . $marker . '";');
    file_put_contents("$root/docs/shipping.txt","配送说明：工作日 48 小时内发货。\n");
    file_put_contents("$root/docs/returns.txt","售后说明：签收后七天内可申请退货。\n");
    file_put_contents("$root/messages/readme.txt","客服文件区\n");
}
