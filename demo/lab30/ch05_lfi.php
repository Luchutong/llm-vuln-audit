<?php
// 页面路由：根据 page 参数加载对应的视图文件。
$page = $_GET['page'] ?? 'home';
include 'views/' . $page . '.php';
