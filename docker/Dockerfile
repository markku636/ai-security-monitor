# syntax=docker/dockerfile:1.7
# Security Hub（Next.js standalone）映像。建置環境是 repo 根目錄：
#   docker build -f docker/Dockerfile -t ai-security-monitor-hub .
# 發佈為 ghcr.io/markku636/ai-security-monitor-hub（過渡期也推舊名 ghcr.io/markku636/ai-security-agent-hub）
# 預設內含 Claude Code 與 Codex CLI（給 /ai 頁用）；不要的話 --build-arg AI_CLIS=
ARG NODE_VERSION=22

FROM node:${NODE_VERSION}-bookworm-slim AS deps
WORKDIR /src/hub
COPY hub/package.json hub/package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:${NODE_VERSION}-bookworm-slim AS build
WORKDIR /src
ARG ASA_HUB_VERSION=0.7.0
ENV NEXT_TELEMETRY_DISABLED=1 \
    ASA_HUB_VERSION=${ASA_HUB_VERSION}
COPY --from=deps /src/hub/node_modules hub/node_modules
COPY hub hub
COPY feeds feeds
COPY scripts/install.sh scripts/install.ps1 scripts/
RUN cd hub && npx next build \
 && cp -r .next/static .next/standalone/hub/.next/static \
 && if [ -d public ]; then cp -r public .next/standalone/hub/public; fi \
 && rm -rf .next/standalone/hub/tests .next/standalone/hub/tsconfig.tsbuildinfo

FROM node:${NODE_VERSION}-bookworm-slim AS runtime
ARG ASA_HUB_VERSION=0.7.0
ARG AI_CLIS="@anthropic-ai/claude-code@2.1.302 @openai/codex@0.163.0"
LABEL org.opencontainers.image.title="AI Security Monitor Security Hub" \
      org.opencontainers.image.source="https://github.com/markku636/ai-security-monitor" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${ASA_HUB_VERSION}"
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git ripgrep tini \
 && rm -rf /var/lib/apt/lists/* \
 && if [ -n "$AI_CLIS" ]; then npm install -g --no-audit --no-fund $AI_CLIS && npm cache clean --force; fi \
 && mkdir -p /data/home && chown -R node:node /data
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    ASA_HUB_VERSION=${ASA_HUB_VERSION} \
    ASA_HUB_EDITION=server \
    HOME=/data/home \
    CLAUDE_CONFIG_DIR=/data/claude \
    CODEX_HOME=/data/codex \
    USE_BUILTIN_RIPGREP=0
WORKDIR /app/hub
COPY --from=build --chown=node:node /src/hub/.next/standalone /app
COPY --chown=node:node docker/entrypoint.sh /usr/local/bin/asa-hub-entrypoint
USER node
VOLUME ["/data"]
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["tini", "--", "sh", "/usr/local/bin/asa-hub-entrypoint"]
CMD ["node", "server.js"]
