# Patched image — current 8.3 branch (>= 8.3.36, includes the PHP2Shell fix).
# Doubles as the remediated-config reference. The foothold simulation is NOT mounted here.
ARG PHP_TAG=8.3-apache
FROM php:${PHP_TAG}

LABEL lab="php2shell-poc" role="patched"

# Remediated config: apply PHP's documented interim mitigation as defense-in-depth.
RUN printf 'session.upload_progress.enabled = 0\n' > /usr/local/etc/php/conf.d/zz-lab.ini \
 && a2enmod rewrite >/dev/null 2>&1 || true

EXPOSE 80
