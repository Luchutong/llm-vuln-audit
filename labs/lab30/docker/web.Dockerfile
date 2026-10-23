FROM php:8.4-apache-bookworm@sha256:e653ff90d7f6e2e6f81eddb07c864f1eae224ccbf5143f82a44f25e2f110e320
RUN apt-get update && apt-get install -y --no-install-recommends libxml2-dev libonig-dev iputils-ping \
    && docker-php-ext-install -j2 pdo_mysql mysqli simplexml mbstring \
    && rm -rf /var/lib/apt/lists/*
COPY docker/php.ini /usr/local/etc/php/conf.d/shop.ini
COPY docker/apache.conf /etc/apache2/sites-available/000-default.conf
COPY app /var/www/shop
COPY docker/entrypoint.sh /usr/local/bin/shop-entrypoint
RUN chmod +x /usr/local/bin/shop-entrypoint && mkdir -p /var/lib/shop && chown www-data:www-data /var/lib/shop
WORKDIR /var/www/shop
ENTRYPOINT ["shop-entrypoint"]
CMD ["apache2-foreground"]
