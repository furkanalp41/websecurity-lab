# SPDX-License-Identifier: MIT
# Generic XSS victim-bot image. Every XSS lab builds this same image from this
# context (build.context: ../../../packages/xss-verifier) and configures it purely
# through XSSBOT_* env vars — no per-lab bot code. Chromium ships pre-installed in
# the Playwright base image, so this image is browser INFRA (large, like a pulled
# DB engine) rather than the size-gated `websec-lab/*` lab app image.
FROM mcr.microsoft.com/playwright/python:v1.49.1-jammy@sha256:a34c7c0c74cc5c94f39bedbee2cb220b1e0c0408c78610eade5ab1db32c3294f

# Non-root bot user; posture gate requires a non-root container.
RUN useradd -u 10001 -m -s /usr/sbin/nologin botuser

WORKDIR /opt/xss-verifier
COPY pyproject.toml requirements.txt ./
COPY xss_verifier/ ./xss_verifier/
RUN pip install --no-cache-dir --no-compile . \
 && python -c "import xss_verifier; print('xss-verifier', xss_verifier.__version__)"

USER botuser
ENTRYPOINT ["python", "-m", "xss_verifier"]
