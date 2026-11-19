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

.PHONY: infra infra-down contract
