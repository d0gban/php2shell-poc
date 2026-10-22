# EOL target — PHP 8.0 (end-of-life). Genuinely affected by PHP2Shell; no upstream fix.
# Uses PHP's stock production php.ini (the configuration real deployments ship with),
# so this is an authentic production-shaped target, not a tuned-for-PoC setup.
ARG PHP_TAG=8.0-apache
FROM php:${PHP_TAG}
LABEL lab="php2shell-poc" role="eol-vulnerable"
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
EXPOSE 80
