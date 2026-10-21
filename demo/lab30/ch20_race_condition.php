<?php
// 提现：先检查余额，再扣减并记录，两个步骤之间存在时间窗口。
$amount = (float) $_POST['amount'];
$balance = (float) file_get_contents('balance.txt');

if ($balance >= $amount) {
    sleep(1); // 模拟处理耗时，放大检查与扣减之间的竞争窗口。
    file_put_contents('balance.txt', $balance - $amount);
    file_put_contents('withdraw.log', 'withdraw ' . $amount . "\n", FILE_APPEND);
    echo '提现成功';
} else {
    echo '余额不足';
}
