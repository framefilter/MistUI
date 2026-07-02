// Captive-portal detection — §5.1's probe step. A plain-HTTP request whose
// expected body we know: a redirect or a rewritten body means something is
// intercepting, and the redirect target is the portal to hand the user.
package netcfg

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// The Firefox probe endpoint: plain HTTP (portals can't intercept HTTPS
// without cert errors), stable, and returns exactly "success\n".
const (
	probeURL  = "http://detectportal.firefox.com/success.txt"
	probeWant = "success"
)

// PortalStatus is the probe verdict.
type PortalStatus struct {
	Online    bool   `json:"online"`              // real internet reachable
	Captive   bool   `json:"captive"`             // something is intercepting
	PortalURL string `json:"portalUrl,omitempty"` // where to sign in, if known
}

// ProbePortal checks connectivity from the router itself.
func ProbePortal(ctx context.Context) PortalStatus {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // surface redirects, don't follow
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return PortalStatus{}
	}
	res, err := client.Do(req)
	if err != nil {
		// No route / DNS dead / timeout: offline, but not provably captive.
		return PortalStatus{}
	}
	defer res.Body.Close()

	if loc := res.Header.Get("Location"); res.StatusCode >= 300 && res.StatusCode < 400 && loc != "" {
		return PortalStatus{Captive: true, PortalURL: loc}
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode == http.StatusOK && strings.HasPrefix(strings.TrimSpace(string(body)), probeWant) {
		return PortalStatus{Online: true}
	}
	// 200 with the wrong body = a DNS-hijack portal that didn't redirect.
	return PortalStatus{Captive: true}
}
