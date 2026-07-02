package httpapi

// Live maintenance verification — same opt-in mechanism as the other live
// tests. The default stages are read-only or reversible (board info, image
// rejection, step-up gating, recovery regenerate). The genuinely
// destructive stages are separately gated because they end with the router
// rebooting (and, for reset, wiped):
//
//	MISTUI_E2E_FLASH=/path/to/sysupgrade.bin   flash that image (keep-settings)
//	MISTUI_E2E_RESET=1                         factory reset the device
//
// Run those one at a time, last, and babysit the reboot.

import (
	"bytes"
	"net/http"
	"net/http/cookiejar"
	"os"
	"testing"
)

func TestLiveMaintenance(t *testing.T) {
	base := os.Getenv("MISTUI_E2E_BASE")
	if base == "" {
		t.Skip("MISTUI_E2E_BASE not set")
	}
	origin := os.Getenv("MISTUI_E2E_ORIGIN")
	if origin == "" {
		origin = base
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Transport: e2eTransport(t, base)}

	res, err := c.Get(base + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	var health struct{ OK, Provisioned bool }
	if err := jsonDecode(res, &health); err != nil || !health.OK {
		t.Fatalf("health: %v %+v", err, health)
	}
	if health.Provisioned {
		t.Fatal("target already provisioned; use a fresh scratch instance")
	}
	f := newFakeAuthenticator(t)
	f.origin = origin
	register(t, c, base, f)

	// Board info comes from the platform, never hardcoded.
	res, err = c.Get(base + "/api/maintenance/board")
	if err != nil {
		t.Fatal(err)
	}
	var board struct {
		Board     struct{ Model, Release, Target string }
		ImageSize int64
	}
	if err := jsonDecode(res, &board); err != nil || board.Board.Model == "" || board.Board.Release == "" {
		t.Fatalf("board: %v %+v", err, board)
	}
	t.Logf("device: %s · OpenWrt %s (%s)", board.Board.Model, board.Board.Release, board.Board.Target)

	// Destructive endpoints without a step-up credit → 428, even with a
	// live session.
	for _, p := range []string{
		"/api/recovery/regenerate",
		"/api/maintenance/factory-reset",
		"/api/maintenance/firmware/flash",
	} {
		if code, _ := post(t, c, base+p, nil); code != http.StatusPreconditionRequired {
			t.Fatalf("%s without step-up: %d, want 428", p, code)
		}
	}

	// Step-up + regenerate: the full §4.2 flow against real hardware.
	stepUp(t, c, base, f)
	code, regen := post(t, c, base+"/api/recovery/regenerate", nil)
	if code != http.StatusOK || regen["recoveryCode"] == "" {
		t.Fatalf("regenerate with step-up: %d %v", code, regen)
	}
	// The credit is spent: a second attempt is 428 again.
	if code, _ := post(t, c, base+"/api/recovery/regenerate", nil); code != http.StatusPreconditionRequired {
		t.Fatalf("step-up credit not one-shot: %d", code)
	}

	// Garbage is not firmware: sysupgrade --test must reject it with words.
	res, err = c.Post(base+"/api/maintenance/firmware", "application/octet-stream",
		bytes.NewReader(bytes.Repeat([]byte("mist"), 4096)))
	if err != nil {
		t.Fatal(err)
	}
	var up struct {
		Valid bool
		Error string
	}
	if err := jsonDecode(res, &up); err != nil || res.StatusCode != http.StatusUnprocessableEntity || up.Valid {
		t.Fatalf("garbage image accepted: %d %+v", res.StatusCode, up)
	}
	t.Logf("garbage image rejected: %s", up.Error)

	// A flash attempt with the invalid image must fail at re-validation,
	// spending its credit but writing nothing.
	stepUp(t, c, base, f)
	if code, _ := post(t, c, base+"/api/maintenance/firmware/flash", nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("flash of invalid image: %d, want 422", code)
	}

	// --- explicitly gated destructive stages ---

	if img := os.Getenv("MISTUI_E2E_FLASH"); img != "" {
		data, err := os.ReadFile(img)
		if err != nil {
			t.Fatal(err)
		}
		res, err := c.Post(base+"/api/maintenance/firmware", "application/octet-stream", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Valid bool
			Error string
		}
		if err := jsonDecode(res, &v); err != nil || !v.Valid {
			t.Fatalf("real image rejected: %+v", v)
		}
		stepUp(t, c, base, f)
		code, body := post(t, c, base+"/api/maintenance/firmware/flash", nil)
		if code != http.StatusOK {
			t.Fatalf("flash: %d %v", code, body)
		}
		t.Log("FLASHING — the device is rebooting; verify by hand")
		return
	}

	if os.Getenv("MISTUI_E2E_RESET") == "1" {
		stepUp(t, c, base, f)
		code, body := post(t, c, base+"/api/maintenance/factory-reset", nil)
		if code != http.StatusOK {
			t.Fatalf("factory reset: %d %v", code, body)
		}
		t.Log("FACTORY RESET — the device is wiping itself; verify by hand")
		return
	}

	t.Logf("live maintenance OK against %s (flash/reset stages skipped)", base)
}
