# ============================================================================
# phpMyFAQ 4.1.1 local audit image (self-built, offline, deterministic)
#
# The third-party dependencies are pre-fetched and committed inside the source
# tree at phpmyfaq/src/libs (vendor-dir per composer.json), with every package
# .git metadata removed. Therefore this build performs NO network access for
# Composer and is fully reproducible. The only network step is APT, pointed at
# the Aliyun mirror, used to compile the required PHP extensions.
#
# Base image php:8.4-apache-bookworm is already in the local Docker cache.
# ============================================================================
FROM php:8.4-apache-bookworm

# ---- 1. Switch APT to the Aliyun mirror -------------------------------------
RUN set -eux; \
    for f in /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list; do \
        if [ -f "$f" ]; then \
            sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' "$f"; \
        fi; \
    done; \
    apt-get update

# ---- 2. System libraries for the PHP extensions -----------------------------
RUN apt-get install -y --no-install-recommends \
        libpng-dev libjpeg-dev libfreetype6-dev \
        libicu-dev libldap2-dev libzip-dev libsodium-dev libbz2-dev \
        libonig-dev libxml2-dev zlib1g-dev libcurl4-openssl-dev \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# ---- 3. Build every extension phpMyFAQ needs --------------------------------
RUN docker-php-ext-configure gd --with-freetype --with-jpeg; \
    docker-php-ext-configure ldap --with-libdir=lib/x86_64-linux-gnu; \
    docker-php-ext-install -j"$(nproc)" \
        gd intl ldap bz2 sodium zip opcache \
        pdo pdo_mysql mysqli

# ---- 4. Copy the full release tree (includes the pre-fetched vendor) ---------
WORKDIR /var/www/app
COPY . /var/www/app
# Remove the build-only helper files so they are not served or shipped.
RUN rm -f /var/www/app/composer.phar /var/www/app/Dockerfile.audit

# ---- 5. Serve phpmyfaq/ as the document root --------------------------------
RUN set -eux; \
    mkdir -p /var/www/app/phpmyfaq/content/core/config \
             /var/www/app/phpmyfaq/content/core/data \
             /var/www/app/phpmyfaq/content/core/logs \
             /var/www/app/phpmyfaq/content/user/attachments \
             /var/www/app/phpmyfaq/content/user/images; \
    rm -rf /var/www/html; \
    ln -s /var/www/app/phpmyfaq /var/www/html; \
    chown -R www-data:www-data /var/www/app/phpmyfaq; \
    a2enmod rewrite headers

# ---- 6. Runtime PHP / upload settings ---------------------------------------
RUN { \
        echo 'date.timezone=Asia/Shanghai'; \
        echo 'memory_limit=512M'; \
        echo 'upload_max_filesize=64M'; \
        echo 'post_max_size=64M'; \
        echo 'error_reporting=E_ALL & ~E_DEPRECATED & ~E_STRICT'; \
        echo 'log_errors=On'; \
    } > /usr/local/etc/php/conf.d/zz-pmf.ini

EXPOSE 80
CMD ["apache2-foreground"]
