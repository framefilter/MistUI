// Handlers for the wizard's network features: travel AP, uplink join with
// portal detection, kill switch, and MAC-rotation scheduling. All gated
// behind a session; all applied through UCI (netcfg/vpn own the commands).
package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/framefilter/mistui/internal/netcfg"
)

const (
	macScheduleKey = "mac_schedule"
	macProfileKey  = "mac_profile"
	macLastRollKey = "mac_last_roll"
)

// macScheduleModes: rotation policy for the STA MAC. The opinionated
// default is on-join — a fresh identity for every network, rolled *before*
// association so a portal grant is never invalidated mid-stay (§5.1).
var macScheduleModes = map[string]bool{"off": true, "on-join": true, "daily": true}

func (s *Server) macSchedule() string {
	if v, _ := s.store.Config(macScheduleKey); len(v) > 0 {
		return string(v)
	}
	return "on-join"
}

// macProfile is the device-identity profile the roller mimics (MAC OUI +
// hostname). Default generic: an honest locally-administered random MAC.
func (s *Server) macProfile() string {
	if v, _ := s.store.Config(macProfileKey); len(v) > 0 && netcfg.ValidProfile(string(v)) {
		return string(v)
	}
	return "generic"
}

// --- Wi-Fi ---

func (s *Server) wifiStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.wifi.Status(r.Context())
	if err != nil {
		slog.Error("wifi status", "err", err)
		http.Error(w, "status failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) wifiScan(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	nets, err := s.wifi.Scan(ctx)
	if err != nil {
		slog.Error("wifi scan", "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"networks": nets})
}

func (s *Server) wifiSetAP(w http.ResponseWriter, r *http.Request) {
	var req struct{ SSID, Key string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.wifi.SetAP(ctx, req.SSID, req.Key); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apSsid": req.SSID})
}

func (s *Server) wifiJoinUplink(w http.ResponseWriter, r *http.Request) {
	var req struct{ SSID, Key string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var ident *netcfg.Identity
	if s.macSchedule() != "off" {
		id, err := netcfg.GenerateIdentity(s.macProfile())
		if err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		ident = &id
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if err := s.wifi.JoinUplink(ctx, req.SSID, req.Key, ident); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	resp := map[string]any{"joining": req.SSID}
	if ident != nil {
		_ = s.store.PutConfig(macLastRollKey, []byte(time.Now().Format(time.RFC3339)))
		resp["identity"] = ident
	}
	// Association + DHCP are asynchronous; the UI polls wifi/status.
	writeJSON(w, http.StatusOK, resp)
}

// --- connectivity / portal ---

func (s *Server) netPortal(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, netcfg.ProbePortal(ctx))
}

// --- kill switch ---

func (s *Server) killSwitchGet(w http.ResponseWriter, r *http.Request) {
	on, err := s.vpn.KillSwitch(r.Context())
	if err != nil {
		http.Error(w, "status failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": on})
}

func (s *Server) killSwitchSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.vpn.SetKillSwitch(ctx, req.Enabled); err != nil {
		slog.Error("kill switch", "enabled", req.Enabled, "err", err)
		http.Error(w, "kill switch change failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": req.Enabled})
}

// --- MAC privacy ---

func (s *Server) macScheduleGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"mode": s.macSchedule()})
}

func (s *Server) macScheduleSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !macScheduleModes[req.Mode] {
		http.Error(w, "mode must be off, on-join, or daily", http.StatusBadRequest)
		return
	}
	if err := s.store.PutConfig(macScheduleKey, []byte(req.Mode)); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": req.Mode})
}

func (s *Server) macProfileGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"current":  s.macProfile(),
		"profiles": netcfg.Profiles(),
	})
}

func (s *Server) macProfileSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !netcfg.ValidProfile(req.Profile) {
		http.Error(w, "unknown identity profile", http.StatusBadRequest)
		return
	}
	if err := s.store.PutConfig(macProfileKey, []byte(req.Profile)); err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profile": req.Profile})
}

func (s *Server) rollMAC(w http.ResponseWriter, r *http.Request) {
	ident, err := netcfg.GenerateIdentity(s.macProfile())
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.wifi.ApplySTAIdentity(ctx, ident); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	_ = s.store.PutConfig(macLastRollKey, []byte(time.Now().Format(time.RFC3339)))
	writeJSON(w, http.StatusOK, map[string]any{"identity": ident})
}

// RunMACSchedule is the daemon's daily-rotation loop: hourly wakeups, roll
// when the daily mode is on and 24 h have passed since the last roll.
// Callers run it in a goroutine; it exits when ctx does.
func (s *Server) RunMACSchedule(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s.macSchedule() != "daily" {
			continue
		}
		last, _ := s.store.Config(macLastRollKey)
		if len(last) > 0 {
			if ts, err := time.Parse(time.RFC3339, string(last)); err == nil && time.Since(ts) < 24*time.Hour {
				continue
			}
		}
		ident, err := netcfg.GenerateIdentity(s.macProfile())
		if err != nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = s.wifi.ApplySTAIdentity(cctx, ident)
		cancel()
		if err != nil {
			slog.Debug("scheduled mac roll skipped", "err", err)
			continue
		}
		_ = s.store.PutConfig(macLastRollKey, []byte(time.Now().Format(time.RFC3339)))
		slog.Info("scheduled mac roll", "mac", ident.MAC, "hostname", ident.Hostname)
	}
}
