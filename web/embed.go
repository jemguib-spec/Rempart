// Package web embeds the administration interface (no build step, no CDN:
// every asset is served by Rempart itself, which keeps the CSP strict).
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// FS returns the static files rooted at "static".
func FS() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
