# SPDX-License-Identifier: MIT
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

# Install ODBC Driver 18 for SQL Server (runtime) + build deps for pyodbc.
# unixodbc is the runtime dep; unixodbc-dev + gcc + g++ are build-only.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl gnupg2 apt-transport-https \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
 && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/mssql-release.list \
 && apt-get update \
 && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 unixodbc libgssapi-krb5-2 \
 && apt-get install -y --no-install-recommends unixodbc-dev gcc g++ \
 && pip install --no-cache-dir pyodbc==5.2.0 \
 && apt-get purge -y curl gnupg2 apt-transport-https unixodbc-dev gcc g++ \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -u 10001 -m -s /usr/sbin/nologin app
WORKDIR /opt/app
COPY src/requirements.txt /opt/app/requirements.txt
RUN pip install --no-cache-dir -r /opt/app/requirements.txt
COPY src/ /opt/app/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
