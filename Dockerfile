# Multi-stage build — final image carries dist + prod deps only, runs as non-root.
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN npx --yes pnpm@11.24.0 install --frozen-lockfile
COPY . .
RUN npx --yes pnpm@11.24.0 build && npx --yes pnpm@11.24.0 prune --prod

FROM node:24-alpine
ENV NODE_ENV=production \
    DXM_TRANSPORT=http
WORKDIR /app
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/package.json ./
# Pre-create the audit mount point owned by node — named volumes inherit
# image ownership on first use; without this, audit writes fail as non-root.
RUN mkdir -p /audit && chown node:node /audit
USER node
EXPOSE 3020
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://127.0.0.1:3020/healthz || exit 1
CMD ["node", "dist/index.js"]
