# syntax=docker/dockerfile:1
# Multi-stage: compile with dev deps, install prod deps separately, ship only those + dist as a non-root user.
ARG NODE_VERSION=20

FROM node:${NODE_VERSION}-bookworm-slim AS base
RUN corepack enable && corepack prepare pnpm@10.23.0 --activate
# Toolchain for the build stages only: argon2 compiles when no prebuild matches (e.g. linux/arm64).
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json pnpm-lock.yaml ./

FROM base AS build
RUN pnpm install --frozen-lockfile
COPY tsconfig.json tsconfig.build.json nest-cli.json prisma.config.ts ./
COPY prisma ./prisma
COPY src ./src
RUN pnpm build

# Known ceiling: @prisma/client's optional peers (prisma CLI, typescript) resolve to the dev copies in the
# lockfile, so they stay in the prod tree (~440 MB node_modules). Splitting them out needs a separate lockfile.
FROM base AS prod-deps
RUN pnpm install --frozen-lockfile --prod

FROM node:${NODE_VERSION}-bookworm-slim AS runtime
ENV NODE_ENV=production APP_ENV=production PORT=8080
# Size of the libuv threadpool (argon2, DNS lookups, fs). It must be in the environment at process start: an ESM
# entry cannot change it. argon2 gets one thread fewer than this (capped at the CPU count). Raise with the CPUs.
ENV UV_THREADPOOL_SIZE=8
WORKDIR /app
COPY --from=prod-deps --chown=node:node /app/package.json ./
COPY --from=prod-deps --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
USER node
EXPOSE 8080
# Migrations are a separate step (`make migrate` / a release job), never run on start.
CMD ["node", "dist/main.js"]
