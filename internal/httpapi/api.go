// Package httpapi is MistUI's single HTTP surface: a small JSON API under
// /api plus the embedded SPA on every other path. It listens on plain HTTP
// and expects nginx (or uhttpd) to terminate TLS in front of it.
package httpapi

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/framefilter/mistui/internal/auth"
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
	api     *http.ServeMux
}

// New builds a Server with sane defaults for the reference hardware.
func New(st *store.Store, conn vpn.Connector) *Server {
	s := &Server{store: st, vpn: conn, wgIface: "wg0", apnIf: "phy0-ap0"}
	s.routes()
	return s
}

func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/health", s.health)
	m.HandleFunc("GET /api/session", s.session)
	m.HandleFunc("POST /api/login", s.login)
	m.HandleFunc("POST /api/vpn/up", s.requireSession(s.vpnUp))
	m.HandleFunc("POST /api/vpn/down", s.requireSession(s.vpnDown))
	m.HandleFunc("GET /api/vpn/status", s.requireSession(s.vpnStatus))
	m.HandleFunc("POST /api/privacy/roll-mac", s.requireSession(s.rollMAC))
	s.api = m
}

// Handler returns the root handler: API under /api, SPA everywhere else.
func (s *Server) Handler(spa fs.FS) http.Handler {
	root := http.NewServeMux()
	root.Handle("/api/", s.api)
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

type loginReq struct {
	CredentialID      string `json:"credentialId"`
	AuthenticatorData []byte `json:"authenticatorData"`
	ClientDataJSON    []byte `json:"clientDataJSON"`
	Signature         []byte `json:"signature"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	cose, err := s.store.Credential(req.CredentialID)
	if err != nil || cose == nil {
		http.Error(w, "unknown credential", http.StatusUnauthorized)
		return
	}
	pub, err := auth.ParseCOSE(cose)
	if err != nil {
		http.Error(w, "bad credential", http.StatusInternalServerError)
		return
	}
	if !auth.VerifyAssertion(pub, req.AuthenticatorData, req.ClientDataJSON, req.Signature) {
		http.Error(w, "denied", http.StatusUnauthorized)
		return
	}
	tok, err := auth.NewToken()
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	exp := time.Now().Add(12 * time.Hour)
	if err := s.store.PutSession(tok, exp); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  exp,
	})
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
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
