// The DoH forwarder: a stub resolver on localhost that dnsmasq forwards to.
// DNS messages pass through in wire format (RFC 8484 carries them verbatim
// over HTTPS POST), so no DNS parsing library is needed — the only message
// surgery is synthesizing a SERVFAIL header when the upstream is
// unreachable, which keeps clients failing fast instead of timing out.
package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// ListenAddr is where the forwarder serves and dnsmasq forwards to. Loopback
// only: LAN clients talk to dnsmasq, never to the forwarder directly.
const ListenAddr = "127.0.0.1:5335"

const (
	maxMsg      = 4096 // generous EDNS buffer; upstream sets TC as needed
	exchangeTTL = 6 * time.Second
)

// Stats is the forwarder's health view for the UI.
type Stats struct {
	Queries   uint64 `json:"queries"`
	Failures  uint64 `json:"failures"`
	LastOK    int64  `json:"lastOk,omitempty"`    // unix seconds
	LastError string `json:"lastError,omitempty"` // most recent upstream failure
}

// Forwarder is the embedded DoH client plus its localhost DNS listeners.
type Forwarder struct {
	addr   string
	url    string // test override; empty → current provider's URL
	client *http.Client

	provider atomic.Pointer[Provider]

	pc net.PacketConn
	ln net.Listener

	queries  atomic.Uint64
	failures atomic.Uint64
	lastOK   atomic.Int64
	lastErr  atomic.Pointer[string]
}

// NewForwarder builds a forwarder that will listen on addr. Call Listen
// before Serve.
func NewForwarder(addr string) *Forwarder {
	f := &Forwarder{
		addr: addr,
		client: &http.Client{
			Timeout: exchangeTTL,
			Transport: &http.Transport{
				DialContext:         dialPinned,
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: 5 * time.Second,
				IdleConnTimeout:     90 * time.Second,
				MaxIdleConnsPerHost: 2,
			},
		},
	}
	f.provider.Store(providerByKey(DefaultProvider))
	return f
}

// dialPinned connects to the provider's pinned anycast addresses instead of
// resolving its hostname — resolving it would need the very DNS this
// forwarder provides. TLS verification still uses the hostname from the URL.
func dialPinned(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p := providerByHostname(host)
	if p == nil {
		return nil, fmt.Errorf("no pinned addresses for %q", host)
	}
	d := &net.Dialer{Timeout: 4 * time.Second}
	var lastErr error
	for _, ip := range p.IPs {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// SetProvider switches the upstream resolver. Takes effect on the next query.
func (f *Forwarder) SetProvider(key string) error {
	p := providerByKey(key)
	if p == nil {
		return fmt.Errorf("unknown DNS provider %q", key)
	}
	f.provider.Store(p)
	return nil
}

// ProviderKey returns the active resolver's key.
func (f *Forwarder) ProviderKey() string { return f.provider.Load().Key }

// CloseUpstream drops pooled upstream connections. The fail-closed firewall
// rule only governs *new* connections (fw4 accepts established flows before
// rules run), so an already-warm DoH connection would tunnel right through
// it — the rule's owner calls this right after installing it.
func (f *Forwarder) CloseUpstream() { f.client.CloseIdleConnections() }

// Stats returns a snapshot of forwarder health.
func (f *Forwarder) Stats() Stats {
	s := Stats{
		Queries:  f.queries.Load(),
		Failures: f.failures.Load(),
		LastOK:   f.lastOK.Load(),
	}
	if e := f.lastErr.Load(); e != nil {
		s.LastError = *e
	}
	return s
}

// Listen binds the UDP and TCP listeners. Split from Serve so callers (and
// tests using :0) know the port is held before anything depends on it.
func (f *Forwarder) Listen() error {
	pc, err := net.ListenPacket("udp", f.addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", f.addr)
	if err != nil {
		pc.Close()
		return err
	}
	f.pc, f.ln = pc, ln
	return nil
}

// Addr is the bound UDP address (or the configured one before Listen).
func (f *Forwarder) Addr() string {
	if f.pc != nil {
		return f.pc.LocalAddr().String()
	}
	return f.addr
}

// Serve answers stub queries until ctx is done. Callers run it in a
// goroutine after a successful Listen.
func (f *Forwarder) Serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		f.pc.Close()
		f.ln.Close()
	}()
	go f.serveTCP(ctx)
	f.serveUDP(ctx)
}

func (f *Forwarder) serveUDP(ctx context.Context) {
	sem := make(chan struct{}, 32) // small router: bound in-flight upstreams
	buf := make([]byte, maxMsg)
	for {
		n, raddr, err := f.pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			if resp := f.handle(ctx, q); resp != nil {
				_, _ = f.pc.WriteTo(resp, raddr)
			}
		}()
	}
}

func (f *Forwarder) serveTCP(ctx context.Context) {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go f.serveConn(ctx, c)
	}
}

func (f *Forwarder) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	for {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(l[:])
		if n == 0 || n > maxMsg {
			return
		}
		q := make([]byte, n)
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		resp := f.handle(ctx, q)
		if resp == nil || len(resp) > 0xFFFF {
			return
		}
		binary.BigEndian.PutUint16(l[:], uint16(len(resp)))
		if _, err := c.Write(append(l[:], resp...)); err != nil {
			return
		}
	}
}

// handle forwards one wire-format query and returns the wire-format answer,
// or a synthesized SERVFAIL when the upstream is unreachable.
func (f *Forwarder) handle(ctx context.Context, q []byte) []byte {
	if len(q) < 12 { // shorter than a DNS header: not a query
		return nil
	}
	f.queries.Add(1)
	ctx, cancel := context.WithTimeout(ctx, exchangeTTL)
	defer cancel()
	resp, err := f.exchange(ctx, q)
	if err != nil {
		f.failures.Add(1)
		msg := err.Error()
		f.lastErr.Store(&msg)
		return servfail(q)
	}
	f.lastOK.Store(time.Now().Unix())
	return resp
}

func (f *Forwarder) exchange(ctx context.Context, q []byte) ([]byte, error) {
	url := f.url
	if url == "" {
		url = f.provider.Load().URL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	res, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh upstream: %s", res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 0xFFFF))
	if err != nil {
		return nil, err
	}
	if len(body) < 12 {
		return nil, fmt.Errorf("doh upstream: short response (%d bytes)", len(body))
	}
	return body, nil
}

// servfail turns the query into a minimal SERVFAIL response: same ID and
// question, QR set, RCODE 2.
func servfail(q []byte) []byte {
	r := append([]byte(nil), q...)
	r[2] = (r[2] | 0x80) &^ 0x06 // QR=1, clear AA/TC, keep opcode+RD
	r[3] = (r[3] &^ 0x0F) | 0x02 // RCODE=SERVFAIL
	return r
}

// LookupHost resolves through the forwarder itself — i.e. over DoH. Used for
// the import-time pinning of VPN endpoint hostnames: with fail-closed DNS a
// hostname endpoint could never resolve while the tunnel is down, so the
// lookup happens once, here, and the IP goes into UCI.
func (f *Forwarder) LookupHost(ctx context.Context, host string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			addr := f.Addr()
			if network == "tcp" && f.ln != nil {
				addr = f.ln.Addr().String()
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	return r.LookupHost(ctx, host)
}
