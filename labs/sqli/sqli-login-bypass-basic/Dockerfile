# SPDX-License-Identifier: MIT
# Sample lab base — Alpine 3.20 + Apache 2.4 + PHP 8.3 + SQLite.
# Digest-pinned, non-root, no baked flag. Runs Apache on a non-privileged port
# (8080) so the container needs neither root nor CAP_NET_BIND_SERVICE.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache \
      apache2 \
      php83 php83-apache2 php83-pdo php83-pdo_sqlite php83-session php83-sqlite3 \
 && adduser -D -H -u 10001 app \
 && sed -ri \
      -e 's/^([[:space:]]*)Listen 80$/\1Listen 8080/' \
      -e 's/^([[:space:]]*)User apache/\1#User apache/' \
      -e 's/^([[:space:]]*)Group apache/\1#Group apache/' \
      -e 's/^([[:space:]]*)(CustomLog|TransferLog|ErrorLog)/\1#\2/' \
      /etc/apache2/httpd.conf

# Web root (served) and shared lib (never web-served) live in separate trees.
COPY --chown=app:app src/web/ /var/www/html/
COPY --chown=app:app src/lib/ /opt/lab/
COPY conf/zz-lab.conf /etc/apache2/conf.d/zz-lab.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
