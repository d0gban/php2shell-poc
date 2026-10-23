# EOL target — PHP 8.0.30 (final 8.0 release; branch is end-of-life). Affected, no upstream fix.
# Same stock production php.ini + natural banner as the outdated/patched images, so the fingerprint
# is genuine for WAF/IDS rule testing. The ONLY eol-specific extras are:
#   - prefork MPM + mod_php (stable address space the PHP2Shell OOM chain needs)
#   - the baked PHP2Shell trigger php.ini settings (memory_limit=16M, post_max_size=64M, upload
#     progress, etc.) that make the lab host reach the vulnerable code path.
# For authorized security testing only.
ARG PHP_TAG=8.0.30-apache
FROM php:${PHP_TAG}
LABEL lab="php2shell-poc" role="eol-vulnerable" \
      cve.2026.109618="vulnerable" cve.2026.109619="vulnerable"

# Production php.ini + natural fingerprint (identical to images/outdated & images/patched):
#  - expose_php=On                              -> "X-Powered-By: PHP/x.y.z" on PHP responses
#  - mod_ssl + ServerTokens Full + ServerSignature On
#        -> "Server: Apache/2.4.x (Debian) OpenSSL/x.y.z PHP/x.y.z" on EVERY response and on
#           Apache's own error pages (e.g. a 404 to a nonexistent path), not just PHP-handled ones.
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
 && sed -ri 's/^[; ]*expose_php\s*=.*/expose_php = On/' "$PHP_INI_DIR/php.ini" \
 && a2enmod ssl >/dev/null \
 && printf 'ServerTokens Full\nServerSignature On\n' > /etc/apache2/conf-enabled/zzz-fingerprint.conf

# Force prefork MPM — mod_php requires it and the PHP2Shell OOM chain needs a stable address space.
# (The 8.0-apache base is already prefork; this makes it explicit and survives a base-image change.)
RUN a2dismod mpm_event >/dev/null 2>&1 || true; \
    a2dismod mpm_worker >/dev/null 2>&1 || true; \
    a2enmod mpm_prefork >/dev/null

# PHP2Shell trigger requirements — baked on top of the production php.ini.
# These are what make the EOL host actually reach the vulnerable code path.
RUN { \
      printf '\n; ===== PHP2Shell lab trigger requirements =====\n'; \
      printf 'memory_limit=16M\n'; \
      printf 'post_max_size=64M\n'; \
      printf 'upload_max_filesize=64M\n'; \
      printf 'max_input_nesting_level=128\n'; \
      printf 'max_input_vars=10000\n'; \
      printf 'max_execution_time=60\n'; \
      printf 'session.upload_progress.enabled=On\n'; \
      printf 'session.upload_progress.cleanup=Off\n'; \
      printf 'session.upload_progress.prefix=PHP_SESSION_UPLOAD_PROGRESS\n'; \
      printf 'session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS\n'; \
      printf 'session.upload_progress.freq=1%%\n'; \
      printf 'session.upload_progress.min_freq=1\n'; \
      printf 'session.use_only_cookies=Off\n'; \
      printf 'session.use_strict_mode=Off\n'; \
      printf 'session.serialize_handler=php\n'; \
      printf 'session.save_path=/tmp\n'; \
      printf 'display_errors=On\n'; \
      printf 'log_errors=On\n'; \
      printf 'error_log=/var/log/apache2/error.log\n'; \
      printf '; ===== end PHP2Shell =====\n'; \
    } >> "$PHP_INI_DIR/php.ini" \
 && mkdir -p /tmp && chmod 1733 /tmp

# Raw-HTTP capture (config/rawlog.conf) and the per-target webapp tree are both
# mounted by docker-compose at runtime — not baked — so one source serves every host.
EXPOSE 80
