<?php
// 内部接口：仅当请求携带 X-Admin: 1 时执行管理员操作。
if ($_SERVER['HTTP_X_ADMIN'] === '1') {
    echo '管理员操作已执行';
} else {
    echo '拒绝访问';
}
