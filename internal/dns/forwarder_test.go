package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// sampleQuery is a wire-format query for example.com A (ID 0xABCD, RD).
var sampleQuery = []byte{
	0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
	0x00, 0x01, 0x00, 0x01,
}

// answerFor builds a NOERROR response for a wire-format query: the question
// echoed, plus (for A questions) one A record 192.0.2.1. Additionals in the
// query (EDNS OPT) are dropped; ARCOUNT is zeroed accordingly.
func answerFor(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	// End of QNAME: first zero byte at/after offset 12.
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	qend := i + 5 // zero byte + QTYPE + QCLASS
	if qend > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[i+1 : i+3])

	r := append([]byte(nil), q[:qend]...)
	r[2], r[3] = 0x81, 0x80                 // QR, RD, RA, NOERROR
	binary.BigEndian.PutUint16(r[4:6], 1)   // QDCOUNT
	binary.BigEndian.PutUint16(r[10:12], 0) // ARCOUNT: additionals dropped
	if qtype == 1 {                         // A
		binary.BigEndian.PutUint16(r[6:8], 1) // ANCOUNT
		r = append(r,
			0xC0, 0x0C, // name: pointer to question
			0x00, 0x01, 0x00, 0x01, // TYPE A, CLASS IN
			0x00, 0x00, 0x00, 0x3C, // TTL 60
			0x00, 0x04, 192, 0, 2, 1,
		)
	} else {
		binary.BigEndian.PutUint16(r[6:8], 0)
	}
	return r
}

// newTestForwarder starts a forwarder on ephemeral ports whose upstream is
// the given handler served over TLS.
func newTestForwarder(t *testing.T, upstream http.HandlerFunc) *Forwarder {
	t.Helper()
	ts := httptest.NewTLSServer(upstream)
	t.Cleanup(ts.Close)
	f := NewForwarder("127.0.0.1:0")
	f.url = ts.URL
	f.client = ts.Client()
	if err := f.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go f.Serve(ctx)
	return f
}

func dohEcho(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			t.Errorf("upstream got Content-Type %q", ct)
		}
		q, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answerFor(q))
	}
}

func TestForwarderUDP(t *testing.T) {
	f := newTestForwarder(t, dohEcho(t))
	c, err := net.Dial("udp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(sampleQuery); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxMsg)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	resp := buf[:n]
	if resp[0] != 0xAB || resp[1] != 0xCD {
		t.Fatalf("response ID mismatch: % x", resp[:2])
	}
	if resp[2]&0x80 == 0 || resp[3]&0x0F != 0 {
		t.Fatalf("want NOERROR answer, got flags % x", resp[2:4])
	}
	if got := resp[len(resp)-4:]; got[0] != 192 || got[3] != 1 {
		t.Fatalf("A record rdata = %v", got)
	}
	if st := f.Stats(); st.Queries != 1 || st.Failures != 0 || st.LastOK == 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestForwarderTCP(t *testing.T) {
	f := newTestForwarder(t, dohEcho(t))
	c, err := net.Dial("tcp", f.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	msg := make([]byte, 2+len(sampleQuery))
	binary.BigEndian.PutUint16(msg, uint16(len(sampleQuery)))
	copy(msg[2:], sampleQuery)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0xAB || resp[1] != 0xCD || resp[2]&0x80 == 0 {
		t.Fatalf("bad TCP response: % x", resp[:4])
	}
}

func TestForwarderServfailOnUpstreamError(t *testing.T) {
	f := newTestForwarder(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	c, err := net.Dial("udp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(sampleQuery); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxMsg)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	resp := buf[:n]
	if resp[0] != 0xAB || resp[1] != 0xCD {
		t.Fatalf("response ID mismatch: % x", resp[:2])
	}
	if resp[2]&0x80 == 0 || resp[3]&0x0F != 2 {
		t.Fatalf("want SERVFAIL, got flags % x", resp[2:4])
	}
	if st := f.Stats(); st.Failures != 1 || st.LastError == "" {
		t.Errorf("stats = %+v", st)
	}
}

func TestLookupHost(t *testing.T) {
	f := newTestForwarder(t, dohEcho(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := f.LookupHost(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != "192.0.2.1" {
		t.Fatalf("addrs = %v", addrs)
	}
}

func TestSetProvider(t *testing.T) {
	f := NewForwarder(ListenAddr)
	if f.ProviderKey() != DefaultProvider {
		t.Fatalf("default provider = %q", f.ProviderKey())
	}
	if err := f.SetProvider("mullvad"); err != nil || f.ProviderKey() != "mullvad" {
		t.Fatalf("SetProvider: %v, key %q", err, f.ProviderKey())
	}
	if err := f.SetProvider("nsa"); err == nil {
		t.Fatal("unknown provider accepted")
	}
}
