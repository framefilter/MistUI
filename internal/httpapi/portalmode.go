// Portal mode (§5.1), the automated half: when an uplink turns out to be
// captive, mistd itself pauses the protections a sign-in needs punched
// through — tunnel held down, kill switch off, encrypted DNS off — and
// restores them the moment real connectivity appears (or the window
// expires). The paused posture is recorded in bbolt first, so a daemon
// restart mid-pause resumes the machine instead of stranding the router
// unprotected.
//
// Honesty rules: only what was ON gets paused, exactly that gets restored
// (plus the VPN, which comes up on clear whenever one is configured —
// §5.1 step 3), the window is hard-bounded, and a manual kill-switch or
// DNS toggle during the pause cancels the machine — an explicit user
// action outranks a saved posture.
package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/framefilter/mistui/internal/netcfg"
)

const portalModeKey = "portal_mode"

// Timing knobs; vars so tests can shrink them.
var (
	portalWindow     = 10 * time.Minute // max pause before forced restore
	portalProbeEvery = 8 * time.Second  // re-probe cadence while paused
	portalScoutFor   = 90 * time.Second // how long to probe after a join
	portalScoutEvery = 5 * time.Second
)

// portalRecord is the persisted pause state.
type portalRecord struct {
	Active    bool      `json:"active"`
	Since     time.Time `json:"since"`
	Deadline  time.Time `json:"deadline"`
	PortalURL string    `json:"portalUrl,omitempty"`
	SavedKS   bool      `json:"savedKS"`  // kill switch was on
	SavedDNS  bool      `json:"savedDNS"` // encrypted DNS was on
}

func (s *Server) portalRecord() *portalRecord {
	raw, err := s.store.Config(portalModeKey)
	if err != nil || raw == nil {
		return nil
	}
	var rec portalRecord
	if json.Unmarshal(raw, &rec) != nil || !rec.Active {
		return nil
	}
	return &rec
}

func (s *Server) savePortalRecord(rec *portalRecord) {
	raw, err := json.Marshal(rec)
	if err == nil {
		err = s.store.PutConfig(portalModeKey, raw)
	}
	if err != nil {
		slog.Error("portal record save", "err", err)
	}
}

func (s *Server) setPortalNote(note string) { s.portalNote.Store(&note) }

// enterPortalMode captures the current posture and relaxes it. Re-entering
// while already paused only extends the deadline — it must never record
// the relaxed state as the posture to restore.
func (s *Server) enterPortalMode(ctx context.Context, portalURL string) {
	rec := s.portalRecord()
	if rec == nil {
		ks, _ := s.vpn.KillSwitch(ctx)
		dnsOn, _ := s.dns.Enabled(ctx)
		rec = &portalRecord{Active: true, Since: time.Now(), SavedKS: ks, SavedDNS: dnsOn}
	}
	rec.Deadline = time.Now().Add(portalWindow)
	if portalURL != "" {
		rec.PortalURL = portalURL
	}
	// Record first: a crash between here and the relax steps must restore.
	s.savePortalRecord(rec)
	slog.Warn("portal mode: pausing protections for sign-in",
		"killswitch", rec.SavedKS, "dns", rec.SavedDNS, "until", rec.Deadline.Format(time.RFC3339))

	_ = s.vpn.Down(ctx, s.wgIface) // hold the tunnel down; may not exist
	if rec.SavedKS {
		if err := s.vpn.SetKillSwitch(ctx, false); err != nil {
			slog.Error("portal mode: kill switch pause", "err", err)
		}
	}
	if rec.SavedDNS {
		if err := s.dns.Disable(ctx); err != nil {
			slog.Error("portal mode: dns pause", "err", err)
		}
	}
	s.setPortalNote("")
	s.kickPortalWatch()
}

// exitPortalMode restores the saved posture (and brings the VPN up when
// one is configured — §5.1 step 3), then clears the record.
func (s *Server) exitPortalMode(ctx context.Context, note string) {
	rec := s.portalRecord()
	if rec == nil {
		return
	}
	slog.Warn("portal mode: restoring protections", "reason", note)
	if raw, _ := s.store.Config(vpnSummaryKey); raw != nil {
		if err := s.vpn.Up(ctx, s.wgIface); err != nil {
			slog.Error("portal mode: vpn up", "err", err)
		}
	}
	if rec.SavedKS {
		if err := s.vpn.SetKillSwitch(ctx, true); err != nil {
			slog.Error("portal mode: kill switch restore", "err", err)
		}
	}
	if rec.SavedDNS {
		if err := s.dns.Enable(ctx); err != nil {
			slog.Error("portal mode: dns restore", "err", err)
		}
		if rec.SavedKS {
			if err := s.dns.SetFailClosed(ctx, true); err != nil {
				slog.Error("portal mode: dns fail-closed restore", "err", err)
			}
		}
	}
	_ = s.store.DeleteConfig(portalModeKey)
	s.setPortalNote(note)
}

// cancelPortalMode drops the pause without restoring anything — the user
// changed protections by hand, and their choice stands.
func (s *Server) cancelPortalMode(reason string) {
	if s.portalRecord() == nil {
		return
	}
	_ = s.store.DeleteConfig(portalModeKey)
	s.setPortalNote("portal pause canceled — " + reason)
	slog.Warn("portal mode: canceled", "reason", reason)
}

func (s *Server) kickPortalWatch() {
	select {
	case s.portalKick <- struct{}{}:
	default:
	}
}

// RunPortalWatch is the daemon's §5.1 state machine. Idle until kicked (an
// uplink join, a manual pause) or until a persisted pause is found on
// start; while paused it re-probes until the portal clears or the window
// expires. Callers run it in a goroutine; it exits with ctx.
func (s *Server) RunPortalWatch(ctx context.Context) {
	for {
		rec := s.portalRecord()
		if rec == nil {
			select {
			case <-ctx.Done():
				return
			case <-s.portalKick:
				s.portalScout(ctx)
				continue
			}
		}
		if time.Now().After(rec.Deadline) {
			ectx, cancel := context.WithTimeout(ctx, 60*time.Second)
			s.exitPortalMode(ectx, "sign-in window expired — protections restored (pause again if you still need the portal)")
			cancel()
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, portalProbeEvery)
		p := s.probe(pctx)
		cancel()
		switch {
		case p.Online:
			ectx, cancel := context.WithTimeout(ctx, 60*time.Second)
			s.exitPortalMode(ectx, "you're online — protections restored")
			cancel()
			continue
		case p.Captive && p.PortalURL != "" && p.PortalURL != rec.PortalURL:
			rec.PortalURL = p.PortalURL
			s.savePortalRecord(rec)
		}
		select {
		case <-ctx.Done():
			return
		case <-s.portalKick: // manual re-enter refreshed the record
		case <-time.After(portalProbeEvery):
		}
	}
}

// portalScout runs after an uplink join: association and DHCP are
// asynchronous, so probe patiently; a captive verdict starts the pause,
// a clean online verdict ends the scout.
func (s *Server) portalScout(ctx context.Context) {
	deadline := time.Now().Add(portalScoutFor)
	for time.Now().Before(deadline) {
		if s.portalRecord() != nil {
			return // a pause began meanwhile (manual entry)
		}
		pctx, cancel := context.WithTimeout(ctx, portalScoutEvery)
		p := s.probe(pctx)
		cancel()
		if p.Captive {
			ectx, cancel := context.WithTimeout(ctx, 60*time.Second)
			s.enterPortalMode(ectx, p.PortalURL)
			cancel()
			return
		}
		if p.Online {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(portalScoutEvery):
		}
	}
}

// --- handlers ---

// netPortal reports the probe verdict plus the pause machinery's state.
func (s *Server) netPortal(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	p := s.probe(ctx)
	resp := map[string]any{
		"online": p.Online, "captive": p.Captive,
	}
	if p.PortalURL != "" {
		resp["portalUrl"] = p.PortalURL
	}
	if rec := s.portalRecord(); rec != nil {
		if resp["portalUrl"] == nil && rec.PortalURL != "" {
			resp["portalUrl"] = rec.PortalURL
		}
		resp["pause"] = map[string]any{
			"active":      true,
			"deadline":    rec.Deadline.Format(time.RFC3339),
			"secondsLeft": int(time.Until(rec.Deadline).Seconds()),
			"savedKS":     rec.SavedKS,
			"savedDNS":    rec.SavedDNS,
		}
	}
	if n := s.portalNote.Load(); n != nil && *n != "" {
		resp["note"] = *n
	}
	writeJSON(w, http.StatusOK, resp)
}

// netPortalMode starts or ends a pause on request — the mid-stay
// re-captivation case (hotels re-auth daily) that join-time scouting
// cannot see, and the "I'm done" button.
func (s *Server) netPortalMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Active bool `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if req.Active {
		s.enterPortalMode(ctx, "")
	} else {
		s.exitPortalMode(ctx, "protections restored on request")
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": req.Active})
}

// defaultProbe is the production prober; tests inject their own.
func defaultProbe(ctx context.Context) netcfg.PortalStatus { return netcfg.ProbePortal(ctx) }
