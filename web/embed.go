package web

import "embed"

//go:embed dist/index.html
var Assets embed.FS
