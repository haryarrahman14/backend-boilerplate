# syntax=docker/dockerfile:1
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

# distroless: no shell, CA certs included, non-root uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/api /api
# Production rules apply (https URLs, sslmode, SMTP required, no /docs); override only for local runs.
ENV APP_ENV=production
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/api"]
# Migrations: docker run --rm -e DATABASE_URL=... <image> migrate
