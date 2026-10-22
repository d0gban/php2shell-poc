# EOL image — PHP 8.0 (end-of-life, unsupported). Exposed to PHP2Shell, no upstream fix.
ARG PHP_TAG=8.0-apache
FROM php:${PHP_TAG}

LABEL lab="php2shell-poc" role="eol-vulnerable"

# Vulnerable-config reference: leave session.upload_progress ENABLED (PHP default),
# which PHP flags as an interim-mitigation knob for PHP2Shell.
RUN printf 'session.upload_progress.enabled = 1\n' > /usr/local/etc/php/conf.d/zz-lab.ini \
 && a2enmod rewrite >/dev/null 2>&1 || true

EXPOSE 80
