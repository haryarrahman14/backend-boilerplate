.PHONY: dev build migrate test lint

IMAGE ?= boilerplate-python

dev:  ## run with auto-reload (reads .env)
	uv run python -m app --reload

build:
	docker build -t $(IMAGE) .

migrate:  ## needs only DATABASE_URL (env or .env)
	uv run alembic upgrade head

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .
