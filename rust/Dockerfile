# syntax=docker/dockerfile:1
FROM rust:1.97-slim-trixie AS build
WORKDIR /app

# Build dependencies first so source edits do not recompile them.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release --locked && rm -rf src

COPY migrations migrations
COPY src src
RUN touch src/main.rs && cargo build --release --locked

FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=build /app/target/release/boilerplate /usr/local/bin/boilerplate
USER 10001
ENV PORT=8080 APP_ENV=production
EXPOSE 8080
# `docker run <image> migrate` applies the embedded migrations.
ENTRYPOINT ["boilerplate"]
CMD ["serve"]
