// Package migrations embeds the goose SQL migrations so the binary can run them via `api migrate`.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
