# Same targets in all four implementations. Reads .env if present (see .env.example).
-include .env
# libuv threadpool size for `make dev`; must be set before node starts (see README). Override in .env.
UV_THREADPOOL_SIZE ?= 8
export

.PHONY: install dev build migrate test lint

node_modules: package.json pnpm-lock.yaml
	pnpm install --frozen-lockfile
	@touch node_modules

install: node_modules

dev: node_modules
	pnpm dev

build: node_modules
	pnpm build

# Explicit step, never on app start.
migrate: node_modules
	pnpm exec prisma migrate deploy

test: node_modules
	pnpm test

lint: node_modules
	pnpm lint
	pnpm typecheck
