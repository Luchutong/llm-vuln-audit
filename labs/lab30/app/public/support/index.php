<?php
require __DIR__.'/../../src/bootstrap.php';
page('客服与帮助',function(){echo '<div class="cards">';foreach([['/support/messages.php','在线留言','分享你的使用体验或提出问题。'],['/support/download.php','帮助文档','查看配送和售后说明。'],['/content/page.php?page=shipping','配送规则','了解物流时效与服务范围。']]as$c)echo '<a class="feature-card" href="'.$c[0].'"><h3>'.$c[1].' ↗</h3><p>'.$c[2].'</p></a>';echo '</div>';},'客服与帮助');
