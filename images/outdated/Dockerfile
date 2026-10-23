# Outdated target — PHP 8.4.26 (supported branch, older than the fixed 8.4.27). Affected.
# Stock production php.ini + realistic banner; only the PHP version differs from the patched image.
ARG PHP_TAG=8.4.26-apache
FROM php:${PHP_TAG}
LABEL lab="php2shell-poc" role="outdated-vulnerable"
# Production php.ini + a natural fingerprint for WAF/IDS rule testing:
#  - expose_php=On                              -> "X-Powered-By: PHP/x.y.z" on PHP responses
#  - mod_ssl + ServerTokens Full + ServerSignature On
#        -> "Server: Apache/2.4.x (Debian) OpenSSL/x.y.z PHP/x.y.z" on EVERY response and on
#           Apache's own error pages (e.g. a 404 to a nonexistent path), not just PHP-handled ones.
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
 && sed -ri 's/^[; ]*expose_php\s*=.*/expose_php = On/' "$PHP_INI_DIR/php.ini" \
 && a2enmod ssl >/dev/null \
 && printf 'ServerTokens Full\nServerSignature On\n' > /etc/apache2/conf-enabled/zzz-fingerprint.conf
# Raw-HTTP capture (config/rawlog.conf) is mounted by docker-compose at runtime — not baked.
EXPOSE 80
