// Package dns is MistUI's encrypted-DNS path (§5 item 5): a tiny
// DNS-over-HTTPS forwarder embedded in mistd, plus the UCI/firewall wiring
// that points dnsmasq at it and closes the plaintext port-53 leak — the
// router-originated OUTPUT traffic the kill switch's FORWARD lever never
// governed.
//
// Resolver endpoints are IP-pinned: the DoH client dials the provider's
// anycast addresses directly (TLS still verifies the provider hostname), so
// there is never a plaintext bootstrap query to leak.
package dns

// Provider is one curated DoH resolver. Only key and label are exposed to
// the API; the wire details stay server-side.
type Provider struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Hostname string   `json:"-"` // TLS server name (the URL host)
	URL      string   `json:"-"` // RFC 8484 endpoint
	IPs      []string `json:"-"` // pinned anycast addresses, dialed in order
}

// DefaultProvider is the opinionated default: a privacy-focused nonprofit
// with malware blocking and no logging of personal data.
const DefaultProvider = "quad9"

var providers = []Provider{
	{
		Key: "quad9", Label: "Quad9 — nonprofit, blocks malware",
		Hostname: "dns.quad9.net", URL: "https://dns.quad9.net/dns-query",
		IPs: []string{"9.9.9.9", "149.112.112.112"},
	},
	{
		Key: "cloudflare", Label: "Cloudflare (1.1.1.1) — fastest",
		Hostname: "cloudflare-dns.com", URL: "https://cloudflare-dns.com/dns-query",
		IPs: []string{"1.1.1.1", "1.0.0.1"},
	},
	{
		Key: "mullvad", Label: "Mullvad — no logging, no filtering",
		Hostname: "dns.mullvad.net", URL: "https://dns.mullvad.net/dns-query",
		IPs: []string{"194.242.2.2"},
	},
}

// Providers lists the curated resolvers for the UI picker.
func Providers() []Provider { return providers }

// ValidProvider reports whether key names a curated resolver.
func ValidProvider(key string) bool { return providerByKey(key) != nil }

func providerByKey(key string) *Provider {
	for i := range providers {
		if providers[i].Key == key {
			return &providers[i]
		}
	}
	return nil
}

func providerByHostname(host string) *Provider {
	for i := range providers {
		if providers[i].Hostname == host {
			return &providers[i]
		}
	}
	return nil
}

// AllResolverIPs is the union of every curated provider's pinned addresses —
// the deny-list the fail-closed kill-switch rule blocks on the raw WAN, so
// switching providers never needs a firewall resync.
func AllResolverIPs() []string {
	var out []string
	for _, p := range providers {
		out = append(out, p.IPs...)
	}
	return out
}
