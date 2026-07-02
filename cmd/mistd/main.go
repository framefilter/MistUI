// Command mistd is the MistUI daemon: one small static binary that serves
// the embedded SPA and a JSON API for WireGuard, login, and privacy
// controls. It is built CGO-free so it cross-compiles to every
// OpenWRT-supported architecture, including the small mipsle routers that
// the heavier stacks can't target.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"

	"github.com/framefilter/mistui/internal/httpapi"
	"github.com/framefilter/mistui/internal/store"
	"github.com/framefilter/mistui/internal/vpn"
	"github.com/framefilter/mistui/web"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address (plain HTTP; TLS terminated by nginx/uhttpd)")
	dbPath := flag.String("db", "/etc/mistui/mistui.db", "bbolt database path")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		slog.Error("open store", "path", *dbPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()

	srv := httpapi.New(st, vpn.ExecConnector{})
	handler := srv.Handler(web.FS())

	slog.Info("mistd listening", "addr", *addr, "db", *dbPath)
	if err := http.ListenAndServe(*addr, handler); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
