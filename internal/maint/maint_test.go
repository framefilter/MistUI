package maint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recorder struct {
	cmds  []string
	reply string
}

func (r *recorder) Run(_ context.Context, name string, args ...string) (string, error) {
	r.cmds = append(r.cmds, name+" "+strings.Join(args, " "))
	return r.reply, nil
}

func newTestService(t *testing.T, reply string) (*Service, *recorder, *[]string) {
	t.Helper()
	rec := &recorder{reply: reply}
	var detached []string
	detach := func(name string, args ...string) error {
		detached = append(detached, name+" "+strings.Join(args, " "))
		return nil
	}
	img := filepath.Join(t.TempDir(), "fw.bin")
	return NewServiceWithRunner(rec, detach, img), rec, &detached
}

func TestBoardInfo(t *testing.T) {
	s, _, _ := newTestService(t, `{
		"model": "GL.iNet GL-MT300N-V2",
		"board_name": "glinet,gl-mt300n-v2",
		"release": {"version": "25.12.5", "target": "ramips/mt76x8"}
	}`)
	b, err := s.BoardInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b.Model != "GL.iNet GL-MT300N-V2" || b.Release != "25.12.5" || b.Target != "ramips/mt76x8" {
		t.Fatalf("board = %+v", b)
	}
}

func TestImageRoundTrip(t *testing.T) {
	s, rec, _ := newTestService(t, "")
	if got := s.ImageSize(); got != 0 {
		t.Fatalf("empty ImageSize = %d", got)
	}
	n, err := s.SaveImage(strings.NewReader("not a real image"))
	if err != nil || n != 16 {
		t.Fatalf("SaveImage: n=%d err=%v", n, err)
	}
	if got := s.ImageSize(); got != 16 {
		t.Fatalf("ImageSize = %d", got)
	}
	if err := s.TestImage(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "sysupgrade --test " + s.imagePath
	if rec.cmds[len(rec.cmds)-1] != want {
		t.Fatalf("TestImage ran %q, want %q", rec.cmds[len(rec.cmds)-1], want)
	}
}

func TestSaveImageReplacesPrevious(t *testing.T) {
	s, _, _ := newTestService(t, "")
	if _, err := s.SaveImage(strings.NewReader("first-longer-content")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveImage(strings.NewReader("second")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(s.imagePath)
	if err != nil || string(b) != "second" {
		t.Fatalf("image = %q err=%v", b, err)
	}
}

func TestFlashAndResetAreDetached(t *testing.T) {
	s, rec, detached := newTestService(t, "")
	if err := s.Flash(); err != nil {
		t.Fatal(err)
	}
	if err := s.FactoryReset(); err != nil {
		t.Fatal(err)
	}
	if len(rec.cmds) != 0 {
		t.Fatalf("destructive commands went through the awaited runner: %v", rec.cmds)
	}
	all := strings.Join(*detached, "\n")
	if !strings.Contains(all, "sysupgrade "+s.imagePath) {
		t.Errorf("flash missing sysupgrade: %q", all)
	}
	if strings.Contains(all, "sysupgrade -n") {
		t.Errorf("flash must keep settings: %q", all)
	}
	if !strings.Contains(all, "jffs2reset -y") || !strings.Contains(all, "reboot") {
		t.Errorf("factory reset incomplete: %q", all)
	}
}
