// wg-quick config parsing. The [Interface]/[Peer] file is the lingua franca
// every VPN provider exports, so it is MistUI's import format — but it is
// *only* an import format: the parsed result is applied as OpenWRT UCI
// config (proto wireguard), because wg-quick itself needs bash and doesn't
// exist on OpenWRT.
package vpn

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Peer is one [Peer] section.
type Peer struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []string
	EndpointHost        string
	EndpointPort        string
	PersistentKeepalive string
}

// Config is a parsed wg-quick file: one [Interface], one or more [Peer]s.
type Config struct {
	PrivateKey string
	Addresses  []string
	DNS        []string
	MTU        string
	Peers      []Peer
}

// Summary is what the API may expose: everything a user needs to recognize
// their config, and no key material of any kind.
type Summary struct {
	Addresses  []string `json:"addresses"`
	DNS        []string `json:"dns,omitempty"`
	Endpoints  []string `json:"endpoints"`
	AllowedIPs []string `json:"allowedIPs"`
}

// Summary derives the exposable view of c.
func (c *Config) Summary() Summary {
	s := Summary{Addresses: c.Addresses, DNS: c.DNS}
	for _, p := range c.Peers {
		if p.EndpointHost != "" {
			s.Endpoints = append(s.Endpoints, net.JoinHostPort(p.EndpointHost, p.EndpointPort))
		}
		s.AllowedIPs = append(s.AllowedIPs, p.AllowedIPs...)
	}
	return s
}

// ParseConfig parses and validates a wg-quick configuration file.
func ParseConfig(text string) (*Config, error) {
	cfg := &Config{}
	var section string
	var peer *Peer

	for ln, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			switch section {
			case "interface":
				if cfg.PrivateKey != "" || len(cfg.Addresses) > 0 {
					return nil, fmt.Errorf("line %d: multiple [Interface] sections", ln+1)
				}
			case "peer":
				cfg.Peers = append(cfg.Peers, Peer{})
				peer = &cfg.Peers[len(cfg.Peers)-1]
			default:
				return nil, fmt.Errorf("line %d: unknown section [%s]", ln+1, section)
			}
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", ln+1)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if val == "" {
			return nil, fmt.Errorf("line %d: empty value for %s", ln+1, key)
		}

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				cfg.PrivateKey = val
			case "address":
				cfg.Addresses = append(cfg.Addresses, splitList(val)...)
			case "dns":
				cfg.DNS = append(cfg.DNS, splitList(val)...)
			case "mtu":
				cfg.MTU = val
			// wg-quick script-hook keys are a code-execution surface and
			// meaningless under UCI; refuse rather than silently drop.
			case "preup", "postup", "predown", "postdown", "saveconfig", "table":
				return nil, fmt.Errorf("line %d: %s is not supported (wg-quick script options don't apply)", ln+1, key)
			default:
				return nil, fmt.Errorf("line %d: unknown [Interface] key %q", ln+1, key)
			}
		case "peer":
			switch key {
			case "publickey":
				peer.PublicKey = val
			case "presharedkey":
				peer.PresharedKey = val
			case "allowedips":
				peer.AllowedIPs = append(peer.AllowedIPs, splitList(val)...)
			case "endpoint":
				host, port, err := net.SplitHostPort(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: bad Endpoint %q: %v", ln+1, val, err)
				}
				peer.EndpointHost, peer.EndpointPort = host, port
			case "persistentkeepalive":
				peer.PersistentKeepalive = val
			default:
				return nil, fmt.Errorf("line %d: unknown [Peer] key %q", ln+1, key)
			}
		default:
			return nil, fmt.Errorf("line %d: key outside any section", ln+1)
		}
	}
	return cfg, cfg.validate()
}

func (c *Config) validate() error {
	if err := checkKey("PrivateKey", c.PrivateKey, true); err != nil {
		return err
	}
	if len(c.Addresses) == 0 {
		return fmt.Errorf("[Interface] has no Address")
	}
	for _, a := range c.Addresses {
		if _, _, err := net.ParseCIDR(a); err != nil && net.ParseIP(a) == nil {
			return fmt.Errorf("bad Address %q", a)
		}
	}
	if c.MTU != "" {
		if n, err := strconv.Atoi(c.MTU); err != nil || n < 576 || n > 9200 {
			return fmt.Errorf("bad MTU %q", c.MTU)
		}
	}
	if len(c.Peers) == 0 {
		return fmt.Errorf("no [Peer] section")
	}
	for i, p := range c.Peers {
		if err := checkKey("PublicKey", p.PublicKey, true); err != nil {
			return fmt.Errorf("peer %d: %v", i+1, err)
		}
		if p.PresharedKey != "" {
			if err := checkKey("PresharedKey", p.PresharedKey, true); err != nil {
				return fmt.Errorf("peer %d: %v", i+1, err)
			}
		}
		if len(p.AllowedIPs) == 0 {
			return fmt.Errorf("peer %d: no AllowedIPs", i+1)
		}
		for _, a := range p.AllowedIPs {
			if _, _, err := net.ParseCIDR(a); err != nil {
				return fmt.Errorf("peer %d: bad AllowedIPs entry %q", i+1, a)
			}
		}
		if p.PersistentKeepalive != "" {
			if n, err := strconv.Atoi(p.PersistentKeepalive); err != nil || n < 0 || n > 65535 {
				return fmt.Errorf("peer %d: bad PersistentKeepalive %q", i+1, p.PersistentKeepalive)
			}
		}
	}
	return nil
}

// checkKey validates a WireGuard key: base64 of exactly 32 bytes.
func checkKey(name, val string, required bool) error {
	if val == "" {
		if required {
			return fmt.Errorf("missing %s", name)
		}
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(val)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("%s is not a valid WireGuard key", name)
	}
	return nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
