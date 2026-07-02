// Command mistd is the MistUI daemon: one small static binary that serves
// the embedded SPA and a JSON API for WireGuard, login, and privacy
// controls. It is built CGO-free so it cross-compiles to every
// OpenWRT-supported architecture, including the small mipsle routers that
// the heavier stacks can't target.
//
// TLS is served natively from a self-signed cert generated on first boot —
// WebAuthn requires a secure context and a DNS-name RP ID, so the intended
// posture is: dnsmasq resolves the RP name (default mist.lan) to the router
// and mistd serves it over -tls-addr. The plain -addr listener exists for
// localhost development (localhost is itself a secure context; use
// -rp localhost there).
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/framefilter/mistui/internal/certgen"
	"github.com/framefilter/mistui/internal/httpapi"
	"github.com/framefilter/mistui/internal/netcfg"
	"github.com/framefilter/mistui/internal/store"
	"github.com/framefilter/mistui/internal/vpn"
	"github.com/framefilter/mistui/web"
)

func main() {
	addr := flag.String("addr", "", "plain-HTTP listen address (dev only, e.g. 127.0.0.1:8080)")
	tlsAddr := flag.String("tls-addr", ":443", "TLS listen address; empty disables TLS")
	tlsDir := flag.String("tls-dir", "/etc/mistui/tls", "directory for the self-signed keypair")
	dbPath := flag.String("db", "/etc/mistui/mistui.db", "bbolt database path")
	rpID := flag.String("rp", "mist.lan", "WebAuthn RP ID: the DNS name users reach the UI at")
	origins := flag.String("origins", "", "comma-separated allowed origins (default https://<rp>[:port from -tls-addr])")
	flag.Parse()

	st, err := store.Open(*dbPath)
	if err != nil {
		slog.Error("open store", "path", *dbPath, "err", err)
		os.Exit(1)
	}
	defer st.Close()

	var material certgen.Material
	if *tlsAddr != "" {
		var err error
		material, err = certgen.EnsureMaterial(*tlsDir, *rpID)
		if err != nil {
			slog.Error("tls material", "dir", *tlsDir, "err", err)
			os.Exit(1)
		}
	}
	srv := httpapi.New(st, vpn.NewUCIConnector(), netcfg.NewWiFi(), *rpID, allowedOrigins(*origins, *rpID, *tlsAddr, *addr))
	handler := srv.Handler(web.FS(), material.CAPath)

	// Daily MAC rotation, when the user has chosen that mode.
	schedCtx, schedCancel := context.WithCancel(context.Background())
	defer schedCancel()
	go srv.RunMACSchedule(schedCtx)

	errs := make(chan error, 2)
	n := 0
	if *tlsAddr != "" {
		n++
		go func() {
			slog.Info("mistd listening (tls)", "addr", *tlsAddr, "rp", *rpID, "db", *dbPath)
			errs <- http.ListenAndServeTLS(*tlsAddr, material.CertPath, material.KeyPath, handler)
		}()
	}
	if *addr != "" {
		n++
		go func() {
			slog.Info("mistd listening (plain http, dev)", "addr", *addr)
			errs <- http.ListenAndServe(*addr, handler)
		}()
	}
	if n == 0 {
		slog.Error("nothing to serve: both -addr and -tls-addr are empty")
		os.Exit(1)
	}
	if err := <-errs; err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}

// allowedOrigins derives the browser origins we accept ceremonies from.
// Explicit -origins wins; otherwise https://<rp> (plus the :port variant
// when TLS listens off 443) and, for a dev -addr, http://<rp>:<port>.
func allowedOrigins(explicit, rp, tlsAddr, devAddr string) []string {
	if explicit != "" {
		return strings.Split(explicit, ",")
	}
	var out []string
	if tlsAddr != "" {
		out = append(out, "https://"+rp)
		if _, port, err := net.SplitHostPort(tlsAddr); err == nil && port != "443" && port != "" {
			out = append(out, "https://"+rp+":"+port)
		}
	}
	if devAddr != "" {
		if _, port, err := net.SplitHostPort(devAddr); err == nil && port != "80" && port != "" {
			out = append(out, "http://"+rp+":"+port)
		} else {
			out = append(out, "http://"+rp)
		}
	}
	return out
}
