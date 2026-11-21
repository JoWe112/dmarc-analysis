# syntax=docker/dockerfile:1.7

ARG NODE_IMAGE=node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a

# ---- Stage 1: install production dependencies (pure JS, so build on the host platform) ----
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force

# ---- Stage 2: minimal runtime ----
FROM ${NODE_IMAGE}

ARG VERSION=2.0.0
LABEL org.opencontainers.image.title="dmarc-analysis" \
      org.opencontainers.image.description="DMARC aggregate report analysis (web UI + REST API, PostgreSQL)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

# Pick up security fixes on every rebuild, then strip everything not needed at runtime:
# npm/npx/corepack/yarn (their bundled deps carry most CVE findings) and the apk package manager.
RUN apk upgrade --no-cache && \
    apk add --no-cache tzdata ca-certificates && \
    rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx \
           /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn* \
           /root/.npm /tmp/* && \
    apk --purge del apk-tools && \
    rm -rf /var/cache/apk /etc/apk /lib/apk

WORKDIR /app
ENV NODE_ENV=production \
    PORT=8080 \
    HOME=/tmp

# Owned by root:0 and group-readable so any arbitrary UID (OpenShift) can read the files.
# The app never writes to /app; the root filesystem can be mounted read-only.
COPY --from=deps --chown=0:0 /app/node_modules ./node_modules
COPY --chown=0:0 package.json ./
COPY --chown=0:0 src ./src
COPY --chown=0:0 public ./public
COPY --chown=0:0 docs/openapi.yaml ./docs/openapi.yaml
RUN chmod -R g=u /app

# Non-root default (the image's "node" user, UID 1000); works with any arbitrary UID.
USER 1000
EXPOSE 8080

# Exits 0 only when /healthz returns 200 (i.e. PostgreSQL is reachable).
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

CMD ["node", "src/server.js"]
