# Investigation — Cloudflare WARP as a VPN alternative

**Status:** investigation only. Nothing is implemented; no decision is made.
Permission to test is being sought from Cloudflare (§6.1).

**Goal.** A **temporary fallback** — a switch the user can flip when their
own VPN is being blocked by the network they're on, engaging after the
captive-portal machinery (DESIGN §5.1) has done its work. Not a VPN replacement,
and not the primary tunnel for anybody who has one.

## 1. Summary

The fallback framing is the right one, and it is a much better fit than
"free VPN for people who don't have one" — it is bounded, user-initiated,
obviously temporary, and it slots into an existing gap in the portal state
machine rather than competing with the paste-a-config path. It is also an
easier thing to ask Cloudflare for.

Two findings shape it:

**It slots in cleanly, and the slot already needs filling.** `exitPortalMode`
brings the tunnel up on clear (§5.1 step 3) but never checks that it
*handshakes* — and `/api/vpn/status` reports "up" whenever `wg show` prints
anything, which it does as soon as the interface exists. So a user whose
WireGuard is blocked by the hotel today gets: interface up, UI saying
"connected", kill switch restored, and no internet. Detecting that is
the fallback's trigger, and it is worth fixing regardless of WARP (§5.1).

**But WARP-over-WireGuard survives only some of the blocking it is meant to
answer.** It is the same protocol on a UDP port. It gets past
port-blocklists and commercial-VPN IP blocklists; it does not get past
"all UDP except 53" or WireGuard protocol fingerprinting (§5.3). The irony
worth carrying into the Cloudflare conversation: Cloudflare moved its own
client to MASQUE *precisely because* networks block WireGuard, so the path
available here is Cloudflare's weakest one against exactly this problem.
The mitigation — probing WARP's alternate UDP ports rather than only 2408 —
stops being a nice-to-have and becomes the feature (§5.4).

Engineering cost stays small (§4): a WARP profile already imports today
unmodified, and enrolment needs no new dependencies. The blocker remains
§6.1, the terms.

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
mode — is reused unchanged. Where the switch surfaces, and on what interface,
is §5; enrolment itself is the same code either way.

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

## 5. As a fallback: the design

### 5.1 The trigger, and a bug it exposes

Portal mode already ends in the right place. `exitPortalMode` restores the
saved posture and, when a VPN is configured, calls `vpn.Up` — DESIGN §5.1
step 3. What it does not do is confirm the tunnel came *alive*: `ifup`
succeeding means netifd accepted the interface, not that a handshake
completed. `/api/vpn/status` has the same weakness — it reports `up` when
`wg show` produces any output at all, and `wg show` prints as soon as the
interface exists, peers or no peers.

The consequence on a network that blocks WireGuard, today, with no WARP
involved:

1. Portal clears, `exitPortalMode` runs.
2. `ifup wg0` succeeds. No handshake ever completes.
3. Kill switch restored — LAN traffic may only use the tunnel.
4. The tunnel is a black hole. **No internet**, and the UI says
   "connected" and "protections restored."

That is the honesty rule in the portal-mode header comment being broken by
a liveness check that isn't there. It should be fixed on its own merits:
`wg show <iface> latest-handshakes` gives a per-peer unix timestamp, `0`
meaning never, so "handshaked within the last N seconds" is a one-command
check. `/api/vpn/status` should distinguish *up* from *carrying traffic*,
and `exitPortalMode` should wait briefly for a handshake before declaring
victory.

Fix that, and the fallback trigger is free: **no handshake within the
timeout ⇒ this network is blocking your VPN ⇒ offer the switch.** No new
detection machinery, and the offer appears at the exact moment the user is
staring at a dead connection.

Whether the switch auto-flips or only gets offered is a real product
choice. Offering it is the more honest default — silently rerouting a
privacy-conscious user's traffic to a company they didn't choose is the
kind of surprise this project avoids elsewhere.

### 5.2 Keeping "temporary" true

Three properties, none of which come for free:

- **Use a separate interface.** The fallback must not overwrite the user's
  imported `wg0` UCI config — that would make a "temporary" switch
  destructive. Put WARP on `wg1`, add it to the existing `vpn` firewall
  zone, and the swap is `ifdown wg0` / `ifup wg1`. The kill switch never
  has to open, because the zone (not the interface) is what `lan→vpn`
  forwards to, so there is no window where traffic can take the raw WAN.
- **Revert automatically.** Keep probing the real tunnel on a slow cadence;
  when it handshakes, switch back and say so. A fallback that quietly
  becomes permanent is the failure mode — a user who flips it in one hotel
  should not still be on Cloudflare a month later.
- **Say which tunnel is carrying traffic, always.** The dashboard VPN card
  currently has one state. With a fallback it needs two, visibly distinct:
  *"Fallback: Cloudflare WARP — your VPN is blocked on this network"* is
  not the same claim as *"Connected."*

The kill switch stays **on** throughout. The fallback is a different
tunnel, not an absence of one, so the "tunnel or nothing" guarantee holds
across the swap — which is most of why this is a defensible feature at all.

### 5.3 What the fallback actually rescues

The blocking mode determines whether WARP-over-WireGuard helps, and the
answer is genuinely mixed:

| How the network blocks you | Does WARP help? |
|---|---|
| Blocks known VPN ports (51820 etc.), UDP otherwise fine | ✅ different port |
| Blocklists commercial VPN provider IP ranges | ✅ probably — Cloudflare anycast |
| Your provider is down or blocked regionally | ✅ |
| Blocks all UDP except DNS | ❌ same transport |
| DPI fingerprints the WireGuard handshake | ❌ same protocol |

So it rescues the lazy and commercial cases, which are the common ones, and
fails the deliberate anti-VPN cases, which are the ones a user is most
likely to be angry about. The UI has to be honest when the fallback also
fails to handshake: *"Cloudflare WARP is blocked here too — this network is
blocking VPNs, not just yours."* That is a genuinely useful thing to be
told, and it costs nothing, since the same liveness check from §5.1 detects
it.

### 5.4 Port probing is now the feature

If the reason for falling back is "blocked," trying only UDP 2408 is close
to pointless — it is a well-known WARP port and a network blocking VPNs
plausibly has it. WARP's anycast endpoints answer on a large pool of
alternate UDP ports (500, 1701, 4500 and dozens of others), and cycling
through a handful of them is what converts the first row of the §5.3 table
from "maybe" to "usually."

This is the one piece of real engineering the fallback needs beyond
enrolment: try an endpoint, wait for a handshake, move to the next port,
give up after a bounded number of attempts. It is also the piece a pasted
profile cannot do for itself, and therefore the strongest argument for
building option B rather than staying with option A.

### 5.5 The MASQUE tension, restated

§4C rejected MASQUE on binary-size grounds and that still holds for a 16 MB
Mango. But it should be said plainly that the fallback use case is exactly
where MASQUE's value is highest: HTTP/3 to port 443, indistinguishable from
ordinary web traffic, defeating both of the ❌ rows above. The honest
position is that MistUI is choosing the weaker transport because the
stronger one does not fit the hardware — not because the weaker one is
adequate. Worth mentioning to Cloudflare; they may have views.

## 6. Risks

### 6.1 Terms of service — the blocker

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

### 6.2 The other risks

- **The fallback is blocked by the same networks** that block the tunnel it
  is standing in for, in two of five blocking modes — see §5.3, and §5.4 for
  the port-probing mitigation that decides how often this bites.
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

## 7. Recommendation

1. **Ship option A now** — done, `docs/no-vpn-provider.md`. Costs a page,
   works on the current build, carries no ToS exposure for the project.
2. **Fix the tunnel-liveness gap (§5.1) independently of all of this.** It
   is a real bug in the portal machinery's honesty guarantees, it is a
   handful of lines, and it is the fallback's trigger for free. Do it
   whatever Cloudflare says.
3. **Resolve §6.1 before writing option B.** The engineering is small
   enough that it should not start until the terms question has an answer.
4. **If cleared, build the fallback, not a third VPN option.** Offered when
   the real tunnel fails to handshake, on its own interface, auto-reverting,
   labelled distinctly on the dashboard, kill switch on throughout, and
   honest when WARP is blocked too. Port probing (§5.4) is part of the
   feature, not a later refinement.
5. **Do not chase MASQUE** — while noting §5.5, that this means accepting
   the weaker transport for hardware reasons rather than technical ones.

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
  — licence grant (not fully readable from this environment; see §6.1)
