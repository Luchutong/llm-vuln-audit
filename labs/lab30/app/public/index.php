<?php
require __DIR__ . '/../src/bootstrap.php';
page('让每一份日常，都值得期待', function() {
    $u=user();
    echo '<section class="hero"><div><span class="eyebrow">A LITTLE EVERYDAY JOY</span><h2>给生活，<br>留一点拾光。</h2><p>精选好物、贴心服务，以及简单可靠的购物体验。</p><a class="button" href="/catalog/index.php">探索本季好物 →</a></div><div class="hero-art"><div class="vase"></div><div class="book"></div><div class="circle"></div><span>拾光 · 日常系列</span></div></section>';
    echo '<div class="stats"><div><strong>' . db()->query('SELECT COUNT(*) FROM products')->fetchColumn() . '</strong><span>本季精选</span></div><div><strong>' . ($u ? h($u['tier']==='standard'?'普通会员':$u['tier']) : '欢迎') . '</strong><span>会员服务</span></div><div><strong>' . ($u ? '¥'.h($u['balance']) : '—') . '</strong><span>账户余额</span></div></div>';
    echo '<div class="section-title"><h2>从这里开始</h2><span>所有业务，共用一个账户</span></div><div class="cards">';
    foreach ([['/catalog/index.php','选购好物','浏览本季目录，查看商品详情与库存。'],['/orders/index.php','追踪订单','查看订单金额、配送备注与购买记录。'],['/support/index.php','联系服务','留言、查阅帮助，下载配送与售后文档。'],['/account/index.php','会员账户','管理资料、兑换权益、查看合作方服务。']] as $card) echo '<a class="feature-card" href="'.$card[0].'"><h3>'.$card[1].' ↗</h3><p>'.$card[2].'</p></a>';
    echo '</div>';
}, '工作台');
