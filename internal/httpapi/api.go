// Package httpapi is MistUI's single HTTP surface: a small JSON API under
// /api plus the embedded SPA on every other path. TLS termination is the
// caller's concern (mistd serves it natively from its self-signed cert).
package httpapi

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/framefilter/mistui/internal/netcfg"
	"github.com/framefilter/mistui/internal/store"
	"github.com/framefilter/mistui/internal/vpn"
)

const sessionCookie = "mistui_session"

// Server holds the daemon's dependencies and routes.
type Server struct {
	store   *store.Store
	vpn     vpn.Connector
	wgIface string
	apnIf   string // wireless interface MAC rolling targets
	rpID    string // WebAuthn RP ID — the hostname users reach us at
	origins []string
	chals   *challenges
	api     *http.ServeMux
}

// New builds a Server with sane defaults for the reference hardware. rpID
// is the WebAuthn relying-party ID (a DNS name, never an IP); origins are
// the exact browser origins allowed to run ceremonies.
func New(st *store.Store, conn vpn.Connector, rpID string, origins []string) *Server {
	s := &Server{
		store: st, vpn: conn, wgIface: "wg0", apnIf: "phy0-ap0",
		rpID: rpID, origins: origins, chals: newChallenges(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/health", s.health)
	m.HandleFunc("GET /api/session", s.session)
	m.HandleFunc("POST /api/register/begin", s.registerBegin)
	m.HandleFunc("POST /api/register/finish", s.registerFinish)
	m.HandleFunc("POST /api/login/begin", s.loginBegin)
	m.HandleFunc("POST /api/login/finish", s.loginFinish)
	m.HandleFunc("POST /api/login/recovery", s.loginRecovery)
	m.HandleFunc("POST /api/recovery/regenerate", s.requireSession(s.recoveryRegenerate))
	m.HandleFunc("POST /api/vpn/up", s.requireSession(s.vpnUp))
	m.HandleFunc("POST /api/vpn/down", s.requireSession(s.vpnDown))
	m.HandleFunc("GET /api/vpn/status", s.requireSession(s.vpnStatus))
	m.HandleFunc("POST /api/privacy/roll-mac", s.requireSession(s.rollMAC))
	s.api = m
}

// Handler returns the root handler: API under /api, the device-CA download
// at /ca.pem (public key material; users install it to trust the device),
// and the SPA everywhere else. caPath may be empty when TLS is off.
func (s *Server) Handler(spa fs.FS, caPath string) http.Handler {
	root := http.NewServeMux()
	root.Handle("/api/", s.api)
	if caPath != "" {
		root.HandleFunc("GET /ca.pem", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			http.ServeFile(w, r, caPath)
		})
	}
	root.Handle("/", http.FileServer(http.FS(spa)))
	return root
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func sessionToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value
	}
	return ""
}

func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ok, _ := s.store.SessionValid(sessionToken(r))
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// --- handlers ---

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	n, _ := s.store.CredentialCount()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "provisioned": n > 0})
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	ok, _ := s.store.SessionValid(sessionToken(r))
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": ok})
}

func (s *Server) vpnUp(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.vpn.Up(ctx, s.wgIface); err != nil {
		slog.Error("vpn up", "iface", s.wgIface, "err", err)
		http.Error(w, "vpn up failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "up", "iface": s.wgIface})
}

func (s *Server) vpnDown(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.vpn.Down(ctx, s.wgIface); err != nil {
		slog.Error("vpn down", "iface", s.wgIface, "err", err)
		http.Error(w, "vpn down failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "down", "iface": s.wgIface})
}

func (s *Server) vpnStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out, err := s.vpn.Status(ctx)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"up": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"up": out != "", "detail": out})
}

func (s *Server) rollMAC(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	mac, err := netcfg.RollMAC(ctx, s.apnIf)
	if err != nil {
		slog.Error("roll mac", "iface", s.apnIf, "err", err)
		http.Error(w, "roll failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"iface": s.apnIf, "mac": mac})
}
