# Patched target — current 8.3 branch (>= 8.3.36, contains the PHP2Shell fix).
# Same stock production php.ini as the others: the fix is in the PHP code, not in config.
ARG PHP_TAG=8.3-apache
FROM php:${PHP_TAG}
LABEL lab="php2shell-poc" role="patched"
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
EXPOSE 80
