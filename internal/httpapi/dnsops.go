// Handlers for encrypted DNS (§5 item 5). Enablement state lives in UCI
// (reboot-safe by construction, like the kill switch); only the provider
// choice and the "a default has been applied" marker live in bbolt.
package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/framefilter/mistui/internal/dns"
	"github.com/framefilter/mistui/internal/vpn"
)

const (
	dnsProviderKey = "dns_provider"
	// dnsDefaultedKey marks that encrypted DNS has been switched on by
	// default (or explicitly toggled by the user) — the default is applied
	// at most once and never overrides a user's choice.
	dnsDefaultedKey = "dns_defaulted"
)

func (s *Server) dnsGet(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	enabled, err := s.dns.Enabled(ctx)
	if err != nil {
		// No uci on this host (dev) or a transient failure: report off
		// rather than erroring the whole dashboard.
		slog.Debug("dns enabled check", "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":   enabled,
		"provider":  s.dns.Fwd.ProviderKey(),
		"providers": dns.Providers(),
		"stats":     s.dns.Fwd.Stats(),
	})
}

func (s *Server) dnsSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if req.Enabled {
		if err := s.dns.Enable(ctx); err != nil {
			slog.Error("dns enable", "err", err)
			http.Error(w, "could not enable encrypted DNS", http.StatusBadGateway)
			return
		}
		// The fail-closed rule rides the kill switch: if it is already on,
		// DoH must be denied the raw WAN from this moment too.
		if on, err := s.vpn.KillSwitch(ctx); err == nil && on {
			if err := s.dns.SetFailClosed(ctx, true); err != nil {
				slog.Error("dns fail-closed", "err", err)
				http.Error(w, "encrypted DNS is on, but the fail-closed rule failed", http.StatusBadGateway)
				return
			}
		}
	} else {
		if err := s.dns.Disable(ctx); err != nil {
			slog.Error("dns disable", "err", err)
			http.Error(w, "could not disable encrypted DNS", http.StatusBadGateway)
			return
		}
	}
	_ = s.store.PutConfig(dnsDefaultedKey, []byte("user"))
	// An explicit toggle during a portal pause outranks the saved posture.
	s.cancelPortalMode("you changed encrypted DNS manually")
	writeJSON(w, http.StatusOK, map[string]any{"enabled": req.Enabled})
}

func (s *Server) dnsProviderSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !dns.ValidProvider(req.Provider) {
		http.Error(w, "unknown DNS provider", http.StatusBadRequest)
		return
	}
	if err := s.store.PutConfig(dnsProviderKey, []byte(req.Provider)); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	_ = s.dns.Fwd.SetProvider(req.Provider) // validated above
	writeJSON(w, http.StatusOK, map[string]any{"provider": req.Provider})
}

// applyDNSDefault switches encrypted DNS on the first time the device gets
// its travel network — the wizard's one mandatory step. §5 item 5 says
// encrypted DNS is the *default*, so it must not depend on the user finding
// a toggle; and it must never fight a user who later turned it off.
func (s *Server) applyDNSDefault(ctx context.Context) {
	if v, _ := s.store.Config(dnsDefaultedKey); v != nil {
		return
	}
	if err := s.dns.Enable(ctx); err != nil {
		slog.Warn("default encrypted DNS not applied", "err", err)
		return
	}
	_ = s.store.PutConfig(dnsDefaultedKey, []byte("auto"))
	slog.Info("encrypted DNS enabled by default", "provider", s.dns.Fwd.ProviderKey())
}

// pinEndpoints resolves hostname VPN endpoints to IPs at import time, over
// the encrypted path. With fail-closed DNS (kill switch on, tunnel down)
// ifup could never resolve the endpoint itself — a chicken-and-egg this
// one-time lookup removes. Best-effort: an unresolvable host is kept
// verbatim rather than failing the import.
func (s *Server) pinEndpoints(ctx context.Context, cfg *vpn.Config) {
	for i := range cfg.Peers {
		host := cfg.Peers[i].EndpointHost
		if host == "" || net.ParseIP(host) != nil {
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := s.dns.Fwd.LookupHost(rctx, host)
		cancel()
		if err != nil {
			slog.Warn("endpoint not pinned; keeping hostname", "host", host, "err", err)
			continue
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				cfg.Peers[i].EndpointHost = a
				slog.Info("endpoint pinned", "host", host, "ip", a)
				break
			}
		}
	}
}
