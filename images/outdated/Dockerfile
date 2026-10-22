# Outdated target — PHP 8.3.10 (supported branch, older than the fixed 8.3.36). Affected.
# Stock production php.ini; only the PHP version differs from the patched image.
ARG PHP_TAG=8.3.10-apache
FROM php:${PHP_TAG}
LABEL lab="php2shell-poc" role="outdated-vulnerable"
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
EXPOSE 80
