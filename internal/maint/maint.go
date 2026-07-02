// Package maint is §5 item 7: factory reset and firmware update, the
// OpenWRT way. Factory reset is jffs2reset (wipe the overlay — config, the
// mistui db, the device CA — back to first boot). Firmware is sysupgrade:
// the uploaded image is validated with `sysupgrade --test` before the
// destructive flash is offered, and the flash keeps settings (sysupgrade's
// default) — /etc/mistui survives via the package's keep.d entry.
//
// Both destructive commands run *detached* (setsid, started not awaited):
// they kill every process including mistd, so the HTTP response must
// already be on the wire and the command must not die with its parent.
package maint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/framefilter/mistui/internal/run"
)

// ImagePath is where the uploaded firmware image waits for validation and
// flashing. tmpfs: big, RAM-backed, gone on reboot either way.
const ImagePath = "/tmp/mistui-firmware.bin"

// MaxImageSize bounds uploads. The Mango's whole flash is 16 MB; even
// generous devices ship images well under this.
const MaxImageSize = 64 << 20

// Service runs maintenance operations.
type Service struct {
	run       run.Runner
	imagePath string
	// detach starts a command that must outlive mistd (see package doc).
	detach func(name string, args ...string) error
}

// NewService returns the production implementation.
func NewService() *Service {
	return &Service{run: run.Exec{}, imagePath: ImagePath, detach: detachExec}
}

// NewServiceWithRunner is the test seam: commands go to r, detached
// commands to detach, and the image lands in imagePath.
func NewServiceWithRunner(r run.Runner, detach func(string, ...string) error, imagePath string) *Service {
	return &Service{run: r, detach: detach, imagePath: imagePath}
}

// detachExec starts name in its own session with stdio detached, so it
// survives mistd's death when the command it runs kills every process.
func detachExec(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap without waiting: the child outlives us by design.
	go func() { _ = cmd.Wait() }()
	return nil
}

// Board describes the device, from ubus system board.
type Board struct {
	Model     string `json:"model"`
	BoardName string `json:"boardName"`
	Release   string `json:"release"`
	Target    string `json:"target"`
}

// BoardInfo asks the platform what it is (never hardcoded — §5).
func (s *Service) BoardInfo(ctx context.Context) (Board, error) {
	out, err := s.run.Run(ctx, "ubus", "call", "system", "board")
	if err != nil {
		return Board{}, err
	}
	var parsed struct {
		Model   string `json:"model"`
		Board   string `json:"board_name"`
		Release struct {
			Version string `json:"version"`
			Target  string `json:"target"`
		} `json:"release"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return Board{}, fmt.Errorf("board parse: %w", err)
	}
	return Board{
		Model: parsed.Model, BoardName: parsed.Board,
		Release: parsed.Release.Version, Target: parsed.Release.Target,
	}, nil
}

// SaveImage streams an uploaded firmware image to disk, replacing any
// previous upload. Returns the byte count.
func (s *Service) SaveImage(r io.Reader) (int64, error) {
	f, err := os.OpenFile(s.imagePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(s.imagePath) // never leave a truncated image around
		return 0, err
	}
	return n, nil
}

// ImageSize reports the pending upload's size, or 0 if there is none.
func (s *Service) ImageSize() int64 {
	st, err := os.Stat(s.imagePath)
	if err != nil {
		return 0
	}
	return st.Size()
}

// TestImage runs sysupgrade's own validation against the pending upload.
// The returned error carries sysupgrade's explanation (wrong device, bad
// checksum, not an image, …).
func (s *Service) TestImage(ctx context.Context) error {
	_, err := s.run.Run(ctx, "sysupgrade", "--test", s.imagePath)
	return err
}

// Flash starts the keep-settings sysupgrade of the pending upload and
// returns immediately; the device reboots on its own. Callers must have
// validated with TestImage and hold a step-up credit.
func (s *Service) Flash() error {
	// A beat of delay lets the HTTP response reach the browser.
	return s.detach("sh", "-c", fmt.Sprintf("sleep 2; exec sysupgrade %s", s.imagePath))
}

// FactoryReset wipes the overlay and reboots — every setting, credential,
// and certificate on the device is destroyed (§4.2's final path). Returns
// immediately; the device goes dark moments later.
func (s *Service) FactoryReset() error {
	return s.detach("sh", "-c", "sleep 2; jffs2reset -y; reboot")
}
