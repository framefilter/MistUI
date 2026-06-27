// Package web embeds the MistUI single-page app into the daemon binary so
// the whole UI ships as one static file — no separate webroot to install.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:public
var assets embed.FS

// FS returns the SPA asset tree rooted at the public/ directory.
func FS() fs.FS {
	sub, err := fs.Sub(assets, "public")
	if err != nil {
		panic(err) // embed guarantees public/ exists at build time
	}
	return sub
}
