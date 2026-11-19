# Loads .env when present (plain KEY=value lines, no quotes).
-include .env
export

BIN := bin/api

.PHONY: dev build migrate test lint

dev: ## run the API with env from .env
	go run ./cmd/api

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/api

migrate: ## apply migrations; `make migrate CMD=status` (or down) for other goose commands
	go run ./cmd/api migrate $(or $(CMD),up)

test:
	go test -race ./...

lint:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	go vet ./...
