# MistUI — Design

## 1. Purpose

MistUI gives people **better, user-friendly privacy options** on small,
inexpensive travel routers. It runs on vanilla OpenWRT — no vendor firmware,
no LuCI — and targets hardware the heavier control panels exclude.

The north star: a non-technical traveler can flash stock OpenWRT, install
one package, and get a clean UI for "connect my VPN, keep me private," with
nothing to configure by hand.

## 2. Hardware target

Reference device: **GL.iNet GL-MT300N-V2 ("Mango")** — MediaTek MT7628,
**16 MB flash, 128 MB RAM, single 2.4 GHz radio**, `ramips/mt76x8`
(`mipsle`, softfloat). This is the floor; anything larger is easier.

Implications, all forced by the hardware:

- **One static binary.** Four daemons don't fit; `mistd` is a single
  CGO-free Go binary, ~7 MB raw / ~1.8 MB in a squashfs image.
- **No SQLite.** `modernc.org/sqlite` has no MIPS port. The store is
  `go.etcd.io/bbolt` (pure Go).
- **No heavyweight WebAuthn.** A full WebAuthn library is ~11 MB. MistUI
  verifies login assertions with stdlib crypto and treats registration as
  trust-on-first-use (no attestation). See §4.
- **Single-radio reality.** AP and STA share one 2.4 GHz radio, so the
  "rebroadcast a hotel network" mode lives on the upstream's channel. The
  UX is designed around that rather than assuming dual-band.

## 3. Architecture

```
Browser (SPA)
   │  HTTPS (leaf signed by the on-device CA, name-constrained to mist.lan)
   ▼
mistd (:443, native TLS — no proxy in front)
   ├─ bbolt   (/etc/mistui/mistui.db)
   ├─ uci / ifup / wg (WireGuard via netifd proto wireguard)
   └─ ip link         (MAC roll)
```

`mistd` terminates TLS itself with Go's stdlib — an earlier draft put nginx
in front, but a proxy that exists only to terminate TLS is a daemon, a
config surface, and ~1 MB of image the 16 MB tier doesn't have to spend.

`mistd` never speaks DSA or switch config. It manipulates named UCI
interfaces and shells out to standard OpenWRT tools; OpenWRT owns topology.
That is what lets one package work across every supported device.

## 4. Authentication & access model

The access *policy* is inherited from BubbleUI §5.1/§6.7; the *mechanism* is
MistUI's own minimal WebAuthn (sized for small flash). The one deliberate
divergence from BubbleUI is **no LuCI** — see the sole-surface point below.

### 4.1 Access policy (the boundary)

- **All management access requires a hardware-backed credential.** No
  anonymous status page, no password fallback, no remote root, no support
  backdoor.
- **No passwords anywhere** — not for the web UI, not for SSH. Auth is
  purely hardware-backed (WebAuthn).
- **MistUI is the *sole* management surface.** *This is the divergence from
  BubbleUI*, which keeps LuCI installed for power users. MistUI's product
  image ships **without LuCI/uhttpd**; mistd, serving TLS itself on :443,
  is the only web UI. Consequence: MistUI must own all essential device
  config (§5) — there is no LuCI fallback.
- **SSH is an off-by-default, user-enable option.** When the user turns it on
  *from within MistUI*, dropbear runs **key-based only** (`PasswordAuth no`,
  root login gated, user-managed keys) — never a password login surface.
  Enabling it is itself gated behind a MistUI login.
- **Physical recovery is preserved.** OpenWrt failsafe (hold-reset) and
  U-Boot reflash are physical-access-only and intentionally kept for
  un-bricking. The policy governs *network* access.

### 4.2 Mechanism (minimal WebAuthn)

- **Passwordless WebAuthn (FIDO2).** A registered passkey / platform
  authenticator (Touch ID, Android, security key). Multiple credentials
  allowed; any one suffices.
- **Trust-on-first-use registration.** Store the credential's COSE public
  key without verifying attestation — drops the heavy half of WebAuthn,
  keeps the binary small. Allowed only while the device is unprovisioned.
- **Cheap login.** Verify the ES256 assertion over
  `authenticatorData ‖ SHA-256(clientDataJSON)` (`internal/auth`).
- **Recovery:** a single 128-bit recovery code, shown once, hashed at rest,
  single-use, regenerable. No password recovery / email reset / backdoor —
  lose every credential *and* the code and the only path is factory reset.
- Sessions: random 128-bit tokens in bbolt, `HttpOnly; Secure;
  SameSite=Strict` cookies. **Short-lived by design**: a 15-minute idle
  timeout (slid forward on each authenticated request) plus a 12-hour
  absolute cap, and a logout endpoint that revokes server-side. Because
  re-auth is a single WebAuthn touch, sessions are cheap to expire — an
  unattended browser loses access in minutes, not hours. Passive checks
  (`/api/session`) do not slide the timeout, so polling cannot keep a
  session alive.
- **Step-up re-auth:** destructive actions — factory reset, flashing
  firmware, rotating the recovery code, and (future) enabling SSH — require
  a *fresh* WebAuthn assertion, not merely a live session. A step-up
  ceremony grants the session exactly **one** short-lived credit
  (in-memory, 2-minute TTL); each gated endpoint consumes it. Endpoints
  answer 428 when the credit is missing and the UI re-runs the ceremony,
  so an expired credit or daemon restart costs one extra touch, never a
  dead end. Recovery-code sessions hold no passkey and so cannot step up
  until a new one is registered — which the recovery flow demands anyway.
- **Hostname & TLS.** WebAuthn requires a secure context and a DNS-name
  RP ID (an IP is not a valid RP ID), so the UI lives at **`https://mist.lan`**:
  dnsmasq resolves `mist.lan` to the router's LAN address (uci-defaults).
  Browsers refuse WebAuthn on sites with *any* certificate error — clicking
  through the warning is not enough — so a warning-and-proceed cert can't
  work. Instead the device mints its own CA at first boot
  (`internal/certgen`), **name-constrained to `mist.lan`** so trusting it
  grants no authority over any other site, and serves it at `/ca.pem`.
  The user installs that CA once per client device (the wizard's
  "trust this device" step); the TLS leaf is signed by it and auto-renewed.
  All of it dies with a factory reset.
- Ceremony hygiene: server-issued single-use challenges (2-min TTL,
  in-memory), and clientDataJSON origin + type checks and the
  authenticator-data RP-hash/user-present checks on every ceremony.

## 5. MVP features

Because MistUI is the sole management surface (§4.1), the MVP must cover
everything needed to make the device usable as a travel router — anything
missing is something the user simply *cannot* configure (no LuCI fallback).

1. **First-boot wizard** — provision the first passkey, then walk uplink →
   travel SSID → VPN. The only path to a working device.
2. **Secure login** — minimal WebAuthn (§4.2), plus the key-only SSH toggle.
3. **Network / uplink** — join an upstream/hotel Wi-Fi (STA), set the travel
   SSID + password (AP), WAN/LAN basics. Single 2.4 GHz radio on the Mango,
   so AP+STA share the band (§2). Includes captive-portal handling (§5.1) —
   hotel networks are the primary use case, and most of them gate access.
4. **WireGuard** — import a config, connect/disconnect, kill switch.
5. **DNS** — encrypted DNS (DoH) on by default: dnsmasq forwards every
   lookup — LAN clients' and the router's own — to a DoH client embedded in
   `mistd` (curated resolvers, Quad9 default; endpoints IP-pinned so there
   is no plaintext bootstrap query). The firewall rejects plaintext port 53
   toward the WAN (OUTPUT and FORWARD), DNATs hardcoded client DNS into the
   encrypted path, and — while the kill switch is on — rejects DoH on the
   raw WAN too, so "tunnel or nothing" includes name lookups.
6. **MAC privacy** — roll the uplink identity the hotel network sees. Not
   just the MAC: a bare locally-administered random MAC advertises itself
   as spoofed (the LA bit) and pairs oddly with the router's hostname. So
   the roll is an *identity profile* — a real vendor OUI plus a matching
   DHCP hostname, applied together to the STA before association. Profiles:
   Generic (honest LA-random, no hostname) / Apple iPhone / Samsung Galaxy
   / Google Pixel, user-selectable. Schedule: on-join (default) / daily /
   off. Ported from BubbleUI.
7. **Maintenance** — factory reset (jffs2reset: wipes settings, passkeys,
   VPN config, the device CA — back to first boot) and firmware update
   (upload a sysupgrade image, validated with `sysupgrade --test` before
   the flash is offered; settings kept, `/etc/mistui` preserved via the
   package's keep.d entry). Both gated behind step-up re-auth (§4.2).

Interface names (radio/AP/`lan`/`wan`) are read from `board.json`/UCI, never
hardcoded — they vary per device (the Mango is swconfig: `eth0.1`/`eth0.2`,
`wlan0`), the same "ask the platform" pattern BubbleUI uses.

### 5.1 Captive portals: portal mode, not a proxy

No proxying is needed and none is built. The router joins the hotel network
as a STA, so the portal sees *the router's* MAC; when any client behind NAT
completes the sign-in, the authorization lands on the router and unlocks the
uplink for everyone behind it. The portal page itself flows through NAT like
any other page. What actually breaks portals is MistUI's own posture: the
kill switch (portals need raw pre-VPN traffic), encrypted DNS (portals
announce themselves by hijacking plaintext DNS), and MAC randomization
(rolling after sign-in discards the authorization).

So `mistd` runs an explicit **portal-mode state machine** on every uplink
join:

1. **Probe.** HTTP request expecting 204 (plus RFC 8910's DHCP option when
   present). A redirect ⇒ captive, and the redirect target is the portal URL.
2. **Portal mode.** VPN held down, direct WAN allowed, encrypted-DNS
   enforcement relaxed so the hijack can work. The UI says plainly: "this
   network requires a sign-in; your traffic is unprotected until it's done"
   — with the detected portal link. No pretense of filtering portal traffic;
   an honest, bounded window instead.
3. **Clear.** Re-probe until connectivity is real, then bring up the VPN and
   kill switch and exit portal mode.

Corollary policy: the STA MAC is rolled *before* joining an uplink, never
while one is authorized.

## 6. Milestones

- **M0 — walking skeleton (current).** One binary, builds host + `mipsle`,
  serves the SPA, login + WireGuard + MAC-roll endpoints. ✅
- **M1 — on hardware. ✅** Runs on a stock-OpenWRT Mango; login end to end
  from a real browser; WireGuard import (wg-quick *format*, applied as UCI
  `proto wireguard` — wg-quick itself needs bash and doesn't exist on
  OpenWRT). Verified by an opt-in live E2E test (`MISTUI_E2E_BASE`) that
  drives registration → login → import → ifup → ifdown against the device.
- **M2 — wizard + privacy. ✅** First-boot flow (travel SSID → uplink with
  scan + captive-portal detection → VPN import), MAC rotation (on-join
  default / daily / off — always rolled *before* association, §5.1), and
  the kill switch (wg0 in its own `vpn` zone; the switch is the presence
  of the lan→wan forwarding, so state lives in the firewall config and
  survives reboot by construction — plus, since M2.5, a conntrack flush on
  engage, because fw4 accepts established flows before zone rules run and
  a rule change alone would let live connections keep leaking). Portal handling ships the detection +
  guided-sign-in half of §5.1; automatic kill-switch relaxing during
  portal mode is deferred (landed in M2.7) — the UI instead tells the
  user to toggle it, which is honest and one line. Live-verified via
  TestLiveM2Network.
- **M2.5 — encrypted DNS. ✅** The §5-item-5 stack, with no new packages:
  a DoH forwarder inside `mistd` (127.0.0.1#5335), dnsmasq `noresolv` +
  forward, and port-53 REJECTs on the wan zone — closing the kill switch's
  documented router-originated DNS leak (OUTPUT, which its FORWARD lever
  never governed). A LAN redirect hijacks hardcoded client DNS into the
  encrypted path. The fail-closed rule rides the kill switch and is
  tunnel-aware for free: fw4 classifies OUTPUT by egress zone, so DoH rides
  wg0 when the tunnel is up and is rejected on the raw wan when it is down
  (warm upstream connections are cut when the rule lands — established
  flows bypass fw4 rules). Hostname VPN endpoints are resolved over DoH and
  pinned at import time, so fail-closed DNS can never strand `ifup`. On by
  default from the wizard's AP step; switching it off is honest about the
  leak returning. Live-verified via TestLiveDNS (uncached-name oracle
  against the router's own resolver).
- **M2.6 — maintenance + step-up. ✅** §4.2's step-up re-auth shipped
  (one-shot credits, 428 contract), gating recovery-code rotation, factory
  reset, and firmware update (§5 item 7). Live-verified on the Mango the
  hard way: a real keep-settings flash of the stock 25.12.5 image (the
  `/etc/mistui` keep.d marker survived; apk-installed packages did not —
  §8's the-image-is-the-product point, demonstrated) and a real factory
  reset (overlay verifiably wiped: config, credentials, CA, keys all gone).
- **M2.7 — portal-mode automation. ✅** The deferred half of §5.1: mistd
  itself scouts every uplink join, pauses exactly the protections that
  are on (tunnel held down, kill switch, encrypted DNS — the posture is
  recorded in bbolt *first*, so a daemon restart mid-pause resumes the
  machine rather than stranding the router unprotected), and restores
  them — plus the VPN, when one is configured — the moment the probe sees
  real connectivity. The window is hard-bounded (10 min, then forced
  restore); a manual pause/restore endpoint covers mid-stay
  re-captivation (hotel daily re-auth); and a manual kill-switch or DNS
  toggle during a pause cancels the machine — an explicit user action
  outranks a saved posture. Live-verified on the Mango by blinding the
  probe with a temporary egress rule, observing the paused posture, then
  unblinding and watching the automatic restore.
- **M3 — images.** Ready-to-flash factory/sysupgrade images for a small,
  curated set of supported models, composed via the Image Builder with
  LuCI/uhttpd left out (see §8); the per-arch `.apk`/`.ipk` is the build
  artifact feeding them, not a separate product. Optionally publish a feed
  for the OpenWRT firmware selector / ASU (its package list is also
  composition-time, so the sole-surface guarantee can hold there).

## 7. Relationship to BubbleUI

Shared: visual language, UX patterns, the "above-UCI, vanilla-OpenWRT"
philosophy, and the **access *policy*** (§4.1: WebAuthn gates everything, no
passwords, key-only SSH as a user option) — inherited from BubbleUI §5.1/§6.7.

Not shared: (1) the backend — MistUI re-decides every backend choice for the
small tier (see README table); and (2) the **access *posture*** — BubbleUI
keeps LuCI installed for power users and is "a focused UI, not a replacement
OS"; MistUI removes LuCI and is the *sole* management surface (§4.1).

Improvements that are size-neutral (e.g. the minimal-WebAuthn approach) may
flow back upstream.

## 8. Distribution

**Principle: subtraction happens at image-composition time, never at
runtime.** The product image is *composed without* LuCI/uhttpd and anything
else the access model (§4.1) forbids; packages are never removed on a live
device. On squashfs, removing a baked-in package reclaims no flash — it
burns overlay space writing whiteout markers and leaves config residue —
and a rip-out script is neither atomic nor verifiable. No MistUI install
step may depend on removing packages at runtime.

**The flashable image is the product.** For a small, curated set of
supported models we publish factory / sysupgrade images with MistUI baked
in and the unwanted surfaces absent: flash once, no OpenWRT knowledge
required. This is appropriate *because* the model list is deliberately
short — a large per-device matrix is what turns a package into a
distribution, so we keep the list small on purpose.

The `.apk`/`.ipk` package still exists, but as a **build artifact, not an
end-user channel**: the Image Builder consumes packages, so producing one is
simply how the images get made. Installing it on top of an existing OpenWRT
system is *not* a supported path — it cannot remove that system's baked-in
LuCI and therefore cannot honor the sole-management-surface guarantee
(§4.1). Experts may do it anyway; the caveat gets documented, not engineered
around.

**How the images are built — and why DSA never bites.** Images come from the
official **OpenWRT Image Builder** for each device profile, with the MistUI
package dropped into a local feed and pulled in via `PACKAGES="mistui"`. The
Image Builder inherits the device's DSA / board.json / kmod set from the
official target, so we never author switch topology — the same reason the
live-dev loop avoids it. (BubbleUI's CI already does this for one device;
MistUI generalizes it to a short profile matrix.)

Practicalities: images track one OpenWRT release at a time; unsigned at first
(flash via vendor recovery or `sysupgrade -n`), with signing a post-MVP item;
artifacts are published on GitHub Releases.
