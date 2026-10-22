# Patched target — PHP 8.3.36, the PHP2Shell fix for the 8.3 branch (released 2026-10-21).
# Same stock production php.ini and banner config as the others: the fix is in the PHP code, not
# in config — so the patched host presents the same realistic fingerprint, only on a fixed version.
ARG PHP_TAG=8.3.36-apache
FROM php:${PHP_TAG}
LABEL lab="php2shell-poc" role="patched"
# Production php.ini + a natural fingerprint for WAF/IDS rule testing:
#  - expose_php=On                              -> "X-Powered-By: PHP/x.y.z" on PHP responses
#  - mod_ssl + ServerTokens Full + ServerSignature On
#        -> "Server: Apache/2.4.x (Debian) OpenSSL/x.y.z PHP/x.y.z" on EVERY response and on
#           Apache's own error pages (e.g. a 404 to a nonexistent path), not just PHP-handled ones.
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
 && sed -ri 's/^[; ]*expose_php\s*=.*/expose_php = On/' "$PHP_INI_DIR/php.ini" \
 && a2enmod ssl >/dev/null \
 && printf 'ServerTokens Full\nServerSignature On\n' > /etc/apache2/conf-enabled/zzz-fingerprint.conf
# Raw-HTTP capture for WAF rule development (observability only; see rawlog.conf).
COPY rawlog.conf /etc/apache2/conf-enabled/zzz-rawlog.conf
EXPOSE 80
