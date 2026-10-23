#!/bin/sh
set -eu
mkdir -p /var/lib/shop/sessions
chown -R www-data:www-data /var/lib/shop
su -s /bin/sh www-data -c 'php /var/www/shop/bin/setup.php'
exec docker-php-entrypoint "$@"
