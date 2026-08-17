# Investigation — Cloudflare WARP as a VPN alternative

**Status:** investigation only. Nothing is implemented; no decision is made.
**Question:** can WARP stand in for "bring your own WireGuard provider"
(DESIGN §5 item 4), so that a user without a VPN subscription still gets a
tunnel?

## 1. Summary

**WARP is not a substitute for a VPN. It is a substitute for _no_ VPN** —
and that is the interesting part, because right now the wizard's third step
offers exactly two outcomes: paste a wg-quick config, or press *Skip*. Every
user without a VPN subscription takes the second door and ends up on hotel
Wi-Fi with no tunnel at all. WARP closes that gap for free, with no account,
no payment, and nothing to paste.

What it does **not** do is replace a real VPN for anyone who has one: WARP
egresses from a Cloudflare IP deliberately geolocated near you, so it hides
you from the local network and from your ISP, but not from Cloudflare, and it
will not make you look like you are at home. Framing it as "the VPN option"
would be dishonest; framing it as "protection when you don't have one" is
accurate.

Technically it is close to free to adopt (see §4): a WARP profile already
imports today, unmodified, and one-click enrollment needs no new
dependencies. The blocker is **not** engineering. It is §5.1 — whether
Cloudflare's terms permit a third-party product to register free WARP
accounts on a user's behalf. That has to be answered before any of this
ships.

## 2. What WARP actually is

Cloudflare's consumer WARP ("1.1.1.1 with WARP") is a free tunnel from the
device to Cloudflare's edge. Against MistUI's threat model (DESIGN §2, §5.1
— untrusted hotel and café networks) it maps like this:

| Goal | Real VPN | WARP |
|---|---|---|
| Hide traffic from the local network / other guests | ✅ | ✅ |
| Hide traffic + destinations from the venue's ISP | ✅ | ✅ |
| Hide your source IP from the sites you visit | ✅ | ✅ (Cloudflare egress IP) |
| Appear to be somewhere else (geo-shifting) | ✅ | ❌ by design |
| Hide your traffic from the tunnel operator | depends on provider | ❌ Cloudflare sees it |
| Cost / signup | subscription | free, no account |

The third and fourth rows are the ones people conflate. WARP *does* replace
your visible IP — the destination sees a Cloudflare address. But Cloudflare
picks that egress address to match your real region (city-level where it
can), because the product is built to keep local search results and
streaming working, not to relocate you. Anyone whose reason for a VPN is
"look like I'm at home" gets nothing from WARP.

For the traveler MistUI is actually built for — someone on a hotel network
who does not want the network operator, or the guy in room 214, reading
their traffic — WARP covers the whole requirement.

It is also a real trust trade-off worth stating plainly. DESIGN §5 item 5
defaults encrypted DNS to Quad9, a nonprofit, in preference to the largest
available provider. Routing *all* traffic through Cloudflare cuts against
that instinct: it concentrates DNS and transport at one company. That is a
defensible choice for a user with no alternative, and a bad default for a
user who has one.

## 3. Does it work on this hardware

Yes, and there is less to build than expected.

**The official client is not an option.** `warp-cli` has no `mipsle` build
and is far outside a 16 MB flash budget (DESIGN §2). The route in is the
WireGuard-protocol path: register a device against Cloudflare's client API,
receive a peer public key, an endpoint, and a `172.16.0.x` address, and drive
it as an ordinary WireGuard tunnel. This is what `wgcf` does.

**A WARP profile already imports, with zero code changes.** Verified against
`vpn.ParseConfig` with a real wgcf-shaped profile — dual `Address` lines,
`DNS = 1.1.1.1`, `MTU = 1280`, `AllowedIPs = 0.0.0.0/0` and `::/0`,
`Endpoint = engage.cloudflareclient.com:2408`. It parses and produces a
correct summary. So the fully manual path (run `wgcf` on a laptop, paste the
output into the existing box) **works on today's build** and costs a
documentation paragraph.

**Key generation needs no new dependency.** WireGuard keys are X25519, and
stdlib `crypto/ecdh` produces them. Verified: `ecdh.X25519().GenerateKey`
and an explicitly clamped re-derivation yield an identical public key, so
there is no clamping pitfall when `wg` later sets the private key. `net/http`
and `crypto/tls` are already linked by the DoH forwarder, so the binary-size
delta for native enrollment is close to noise.

**Not verified: live registration.** `api.cloudflareclient.com` is blocked
by this environment's egress proxy, so the registration call was never
exercised end to end. That is the one thing a proof-of-concept must do
first, on real hardware.

**Ecosystem health, as of August 2026.** `wgcf` is actively used and the
WireGuard registration path still functions, but it is now the *legacy*
path: Cloudflare's own client defaults to MASQUE over HTTP/3, explicitly
because networks block WireGuard. Recent `wgcf` issues show new registrations
coming back IPv4-only where older profiles had IPv6, and an open August 2026
report of successful handshakes followed by timeouts to non-Cloudflare hosts.
Neither is fatal; both say this is an unofficial path that moves under you.

## 4. Integration options

### A. Document it (zero code)

A README/docs section: "no VPN provider? generate a free Cloudflare WARP
profile with `wgcf` and paste it into step 3." Works today. Costs nothing,
carries no ToS exposure for the project, and helps only users comfortable
running a CLI — i.e. not the person in DESIGN §1's north star.

### B. Native one-click enrollment (~250–350 LOC, no new dependencies)

A new `internal/vpn/warp.go`:

1. Generate an X25519 keypair (`crypto/ecdh`).
2. `POST https://api.cloudflareclient.com/<ver>/reg` with the public key and
   a ToS timestamp; keep the returned account id and token.
3. `PATCH .../reg/<id>` setting `warp_enabled: true` — registration alone
   leaves the account with WARP off.
4. Synthesise a `*vpn.Config` from the response (peer public key, endpoint,
   assigned addresses, `MTU 1280`, `AllowedIPs 0.0.0.0/0`) and hand it to the
   existing `Import`.

Everything downstream — UCI, the `vpn` firewall zone, the kill switch, portal
mode — is reused unchanged. UI is one button in wizard step 3 and one on the
dashboard VPN card, next to the existing paste box, never replacing it.

Three integration details that are easy to get wrong:

- **Pin the registration endpoint.** `api.cloudflareclient.com` must be
  IP-pinned the way DoH resolvers are (`internal/dns/providers.go`).
  Otherwise, with the kill switch on and the tunnel down, the fail-closed
  rule blocks DoH on the raw WAN, the hostname will not resolve, and
  enrolment deadlocks — the same chicken-and-egg `pinEndpoints` already
  solves for peer endpoints.
- **The profile's `DNS = 1.1.1.1` is redundant here.** dnsmasq is pointed at
  the embedded DoH forwarder regardless (DESIGN §5 item 5). Either drop the
  line on synthesis or accept that it is inert, but do not let it read as a
  second, contradictory DNS setting in the UI.
- **Store the account token.** Without it the registration cannot be
  deleted or re-queried later, and factory reset should wipe it with the
  rest of `/etc/mistui`.

### C. MASQUE (rejected)

Reimplementing WARP's MASQUE transport (as `usque` does) means QUIC and
HTTP/3 in the binary. That is a large dependency on a 16 MB device, and it
throws away the kernel WireGuard datapath for a userspace one on a
MediaTek MT7628. Out of budget. If Cloudflare ever retires the WireGuard
path, the answer is to drop the feature, not to chase it.

## 5. Risks

### 5.1 Terms of service — the blocker

The 1.1.1.1 mobile app is licensed as a "non-exclusive, personal, revocable,
non-transferable license to use the Mobile Application on the mobile device
for which it is provided." A third-party router firmware that programmatically
registers WARP devices and NATs a whole LAN behind one registration is not
obviously inside that grant.

`wgcf` has operated openly for years without visible enforcement, which is
evidence about Cloudflare's tolerance but not permission — and the exposure
is different for a widely distributed product than for an individual's
script. **This was not resolved during the investigation:** `cloudflare.com`
and `developers.cloudflare.com` are both blocked by this environment's egress
proxy, so the current full terms were never read.

Required before shipping option B, in order of preference:

1. Read the current WARP / 1.1.1.1 terms end to end.
2. Ask Cloudflare directly. A free, privacy-preserving travel router putting
   more users on WARP is plausibly something they are happy about; a two-line
   answer removes all of this.
3. Failing both, ship option A and let the user make the call themselves.

### 5.2 The other risks

- **Hotel networks block the ports.** WARP's default UDP 2408 (fallbacks
  500, 1701, 4500) is exactly what a captive network is likely to drop —
  Cloudflare's own stated reason for moving to MASQUE. Mitigation: WARP's
  anycast endpoints accept a large pool of alternate UDP ports, so the
  connect path should probe several rather than failing on 2408. This is
  work option B has to do that a pasted profile does not.
- **Cloudflare egress IPs are widely rate-limited.** Sites — including many
  behind Cloudflare — serve CAPTCHAs and blocks to WARP addresses. On a
  router this hits every device on the LAN at once, and users will read it
  as "the router broke the internet." The UI has to say what is happening.
- **The path is unofficial and can vanish.** Cloudflare owes no compatibility
  to a reverse-engineered registration API. Any implementation must fail
  gracefully to "WARP is unavailable; import a config instead," never leave
  the wizard stuck.
- **Support surface.** Cloudflare cannot help these users and neither can a
  VPN provider. Every WARP problem becomes a MistUI issue.

## 6. Recommendation

1. **Ship option A now.** A documented `wgcf` path costs one paragraph,
   works on the current build, and gives the "no VPN" user something today.
2. **Resolve §5.1 before writing option B.** The engineering is small enough
   that it should not start until the legal question has an answer; getting
   that answer is the highest-value next step by a wide margin.
3. **If cleared, build option B as a labelled third choice** in wizard step 3
   — alongside "paste a config" and "skip", never in place of them, and
   described honestly: *"Free basic protection from Cloudflare. Encrypts your
   traffic off this network. It does not hide you from Cloudflare and will
   not change your apparent location."*
4. **Do not chase MASQUE.**

## Sources

- [ViRb3/wgcf](https://github.com/ViRb3/wgcf) — unofficial WARP CLI; issue
  tracker consulted for current registration behaviour (Jun–Aug 2026)
- [Zero Trust WARP: tunneling with a MASQUE](https://blog.cloudflare.com/zero-trust-warp-with-a-masque/)
  — Cloudflare on why it moved off WireGuard
- [Diniboy1123/usque](https://github.com/Diniboy1123/usque) — open MASQUE
  reimplementation (option C reference)
- [hillz2/openwrt_cloudflare_warp](https://github.com/hillz2/openwrt_cloudflare_warp)
  — OpenWRT + WARP over WireGuard, MTU 1280
- [vernette/warpscout](https://github.com/vernette/warpscout) — WARP endpoint
  and alternate-port scanner
- [Cloudflare Privacy Proxy — Geolocation](https://developers.cloudflare.com/privacy-proxy/concepts/geolocation/)
  — region-matched egress IPs
- [1.1.1.1 Mobile Application Terms of Use](https://www.cloudflare.com/public-resolver-mobile-terms)
  — licence grant (not fully readable from this environment; see §5.1)
