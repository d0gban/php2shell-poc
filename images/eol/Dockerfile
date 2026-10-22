# EOL target — PHP 8.0 (end-of-life). Genuinely affected by PHP2Shell; no upstream fix.
# Uses PHP's stock production php.ini and a realistic, un-hardened server banner, so this is an
# authentic production-shaped target (with the fingerprint real boxes leak), not a tuned-for-PoC setup.
ARG PHP_TAG=8.0.30-apache
FROM php:${PHP_TAG}
LABEL lab="php2shell-poc" role="eol-vulnerable"
# Production php.ini + a natural fingerprint for WAF/IDS rule testing:
#  - expose_php=On                              -> "X-Powered-By: PHP/x.y.z" on PHP responses
#  - mod_ssl + ServerTokens Full + ServerSignature On
#        -> "Server: Apache/2.4.x (Debian) OpenSSL/x.y.z PHP/x.y.z" on EVERY response and on
#           Apache's own error pages (e.g. a 404 to a nonexistent path), not just PHP-handled ones.
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
 && sed -ri 's/^[; ]*expose_php\s*=.*/expose_php = On/' "$PHP_INI_DIR/php.ini" \
 && a2enmod ssl dumpio >/dev/null \
 && printf 'ServerTokens Full\nServerSignature On\n' > /etc/apache2/conf-enabled/zzz-fingerprint.conf
# Raw-HTTP capture for WAF rule development (observability only; see rawlog.conf).
COPY rawlog.conf /etc/apache2/conf-enabled/zzz-rawlog.conf
EXPOSE 80
