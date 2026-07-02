package store

import (
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestSessionRoundTripAndBump(t *testing.T) {
	st := testStore(t)
	issued := time.Now().Add(-time.Hour).Truncate(time.Second)
	seen := issued
	if err := st.PutSession("tok", issued, seen); err != nil {
		t.Fatal(err)
	}

	gotIssued, gotSeen, ok, err := st.Session("tok")
	if err != nil || !ok {
		t.Fatalf("Session: ok=%v err=%v", ok, err)
	}
	if !gotIssued.Equal(issued) || !gotSeen.Equal(seen) {
		t.Fatalf("times: issued=%v seen=%v", gotIssued, gotSeen)
	}

	newSeen := issued.Add(30 * time.Minute)
	if err := st.BumpSession("tok", newSeen); err != nil {
		t.Fatal(err)
	}
	gotIssued, gotSeen, _, _ = st.Session("tok")
	if !gotIssued.Equal(issued) {
		t.Errorf("bump changed issued time: %v != %v", gotIssued, issued)
	}
	if !gotSeen.Equal(newSeen) {
		t.Errorf("bump did not advance seen: %v != %v", gotSeen, newSeen)
	}
}

func TestSessionDeleteAndMissing(t *testing.T) {
	st := testStore(t)
	if _, _, ok, _ := st.Session("nope"); ok {
		t.Error("missing token reported present")
	}
	if _, _, ok, _ := st.Session(""); ok {
		t.Error("empty token reported present")
	}
	now := time.Now()
	_ = st.PutSession("tok", now, now)
	if err := st.DeleteSession("tok"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := st.Session("tok"); ok {
		t.Error("deleted token still present")
	}
}
