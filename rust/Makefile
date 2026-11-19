# Loads .env when present (plain KEY=value lines, no quotes).
-include .env
export

.PHONY: dev build migrate test lint

dev:
	cargo run -- serve

build:
	cargo build --release

migrate:
	cargo run --quiet -- migrate

test:
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings
	cargo fmt --check
