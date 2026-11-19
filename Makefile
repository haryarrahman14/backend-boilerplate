# Root helpers. Each service has its own Makefile with: dev, build, migrate, test, lint.
PG := postgres://postgres:postgres@localhost:5433

infra:        ## Postgres :5433, MinIO :9000, Mailpit :8025
	docker compose up -d

infra-down:
	docker compose down

# Build, migrate, start, test and stop one implementation: make contract-go
contract-%:
	contract/run.sh $*

contract: contract-go contract-rust contract-python contract-nestjs

# sslmode behaviour of all four against a throwaway TLS-only Postgres (run `make contract` first so everything is built)
contract-tls:
	contract/tls.sh

.PHONY: infra infra-down contract contract-tls
