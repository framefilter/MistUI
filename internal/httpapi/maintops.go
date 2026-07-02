// Handlers for maintenance (§5 item 7). Everything here sits behind a
// session; the destructive endpoints additionally consume a step-up credit
// (§4.2) — see the routes in api.go. Order of the firmware flow matters:
// upload and validation are harmless and happen before the WebAuthn touch;
// only the flash itself spends the credit.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/framefilter/mistui/internal/maint"
)

func (s *Server) maintBoard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	b, err := s.maint.BoardInfo(ctx)
	if err != nil {
		slog.Error("board info", "err", err)
		http.Error(w, "board info failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"board":     b,
		"imageSize": s.maint.ImageSize(),
	})
}

// maintFirmwareUpload receives the raw image bytes and immediately runs
// sysupgrade's validation, so the UI can tell the user whether the file
// fits this device before offering the destructive step.
func (s *Server) maintFirmwareUpload(w http.ResponseWriter, r *http.Request) {
	n, err := s.maint.SaveImage(http.MaxBytesReader(w, r.Body, maint.MaxImageSize))
	if err != nil {
		slog.Error("firmware upload", "err", err)
		http.Error(w, "upload failed", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.maint.TestImage(ctx); err != nil {
		// sysupgrade's own words: wrong device, bad checksum, not an image.
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"valid": false, "size": n, "error": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "size": n})
}

func (s *Server) maintFirmwareFlash(w http.ResponseWriter, r *http.Request) {
	if s.maint.ImageSize() == 0 {
		http.Error(w, "no image uploaded", http.StatusConflict)
		return
	}
	// Re-validate at flash time: the upload may be stale or tampered with,
	// and sysupgrade --test is cheap next to bricking a router.
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.maint.TestImage(ctx); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}
	if err := s.maint.Flash(); err != nil {
		slog.Error("firmware flash", "err", err)
		http.Error(w, "flash failed to start", http.StatusBadGateway)
		return
	}
	slog.Warn("firmware flash started — device will reboot")
	writeJSON(w, http.StatusOK, map[string]any{"flashing": true})
}

func (s *Server) maintFactoryReset(w http.ResponseWriter, r *http.Request) {
	if err := s.maint.FactoryReset(); err != nil {
		slog.Error("factory reset", "err", err)
		http.Error(w, "factory reset failed to start", http.StatusBadGateway)
		return
	}
	slog.Warn("factory reset started — wiping overlay and rebooting")
	writeJSON(w, http.StatusOK, map[string]any{"resetting": true})
}
