# Outdated image — supported branch (8.3) but older than the fixed 8.3.36. Exposed to PHP2Shell.
ARG PHP_TAG=8.3.10-apache
FROM php:${PHP_TAG}

LABEL lab="php2shell-poc" role="outdated-vulnerable"

# Vulnerable-config reference: session.upload_progress left ENABLED.
RUN printf 'session.upload_progress.enabled = 1\n' > /usr/local/etc/php/conf.d/zz-lab.ini \
 && a2enmod rewrite >/dev/null 2>&1 || true

EXPOSE 80
