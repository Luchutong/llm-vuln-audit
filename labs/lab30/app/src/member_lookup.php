<?php
function member_lookup(string $term): array {
    return db()->query("SELECT id,username,email,role FROM users WHERE username LIKE '%" . $term . "%'")->fetchAll();
}
