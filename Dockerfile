# Hugging Face Docker Space image. The existing production images remain
# separate; this image intentionally co-locates all demo services behind one
# public port because Docker Spaces expose a single container port.
FROM node:24-bookworm-slim AS web-builder

WORKDIR /build/web
COPY frontend/web/package*.json ./
# The current web lockfile is temporarily behind package.json (sharp's optional
# native runtime entries are absent). Keep that production-file issue isolated
# from the Space image and do not rewrite the repository lockfile here.
RUN npm install --no-package-lock --no-audit --no-fund
COPY frontend/web/ ./
ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_API_MODE=real \
    NEXT_PUBLIC_API_BASE_URL=https://__PREWISE_SPACE_HOST__ \
    NEXT_PUBLIC_WS_BASE_URL=wss://__PREWISE_SPACE_HOST__ \
    NEXT_PUBLIC_BACKEND_URL=http://127.0.0.1:8000
RUN npm run build

FROM node:24-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=7860

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates clamav clamav-daemon clamav-freshclam curl locales nginx \
      openssl postgresql postgresql-client procps python3 python3-pip python3-venv \
      tesseract-ocr tesseract-ocr-eng tesseract-ocr-vie util-linux \
    && sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
    && locale-gen \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.runtime.txt ./
RUN python3 -m venv /opt/prewise-venv \
    && /opt/prewise-venv/bin/pip install --no-cache-dir --no-compile -r requirements.runtime.txt \
    && /opt/prewise-venv/bin/python -m playwright install --with-deps --only-shell chromium
RUN groupmod --new-name prewise node \
    && usermod --login prewise --home /home/prewise --move-home node \
    && mkdir -p /ms-playwright /app/web \
    && chown -R prewise:prewise /ms-playwright /app/web

COPY backend/ ./backend/
COPY ai/ ./ai/
COPY security/ ./security/
COPY shared/ ./shared/
COPY mcp_server/ ./mcp_server/
COPY server/ ./server/
COPY data/ ./data/
COPY migrations/ ./migrations/
COPY alembic.ini ./alembic.ini
COPY --from=web-builder --chown=prewise:prewise /build/web/package*.json ./web/
COPY --from=web-builder --chown=prewise:prewise /build/web/.next ./web/.next
COPY --from=web-builder --chown=prewise:prewise /build/web/public ./web/public
COPY --from=web-builder --chown=prewise:prewise /build/web/node_modules ./web/node_modules
COPY --from=web-builder --chown=prewise:prewise /build/web/next.config.js ./web/next.config.js
COPY deploy/huggingface/nginx.conf /etc/nginx/nginx.conf
COPY deploy/huggingface/clamd.conf /etc/clamav/clamd-prewise.conf
COPY deploy/huggingface/freshclam.conf /etc/clamav/freshclam-prewise.conf
COPY deploy/huggingface/patch_next_origin.py /usr/local/lib/prewise/patch_next_origin.py
COPY --chmod=755 deploy/huggingface/entrypoint.sh /usr/local/bin/prewise-hf-entrypoint

EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=10s --start-period=180s --retries=5 \
  CMD curl --fail --silent http://127.0.0.1:7860/v1/ready >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/prewise-hf-entrypoint"]
