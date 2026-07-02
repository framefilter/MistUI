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
   │  HTTPS
   ▼
nginx  ──TLS terminate──►  mistd (127.0.0.1:8080, plain HTTP)
                              │
                              ├─ bbolt   (/etc/mistui/mistui.db)
                              ├─ wg-quick / wg   (WireGuard)
                              └─ ip link         (MAC roll)
```

`mistd` never speaks DSA, switch config, or TLS. It manipulates named UCI
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
  image ships **without LuCI/uhttpd**; MistUI (behind nginx) is the only web
  UI. Consequence: MistUI must own all essential device config (§5) — there
  is no LuCI fallback.
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
  SameSite=Strict` cookies.

## 5. MVP features

Because MistUI is the sole management surface (§4.1), the MVP must cover
everything needed to make the device usable as a travel router — anything
missing is something the user simply *cannot* configure (no LuCI fallback).

1. **First-boot wizard** — provision the first passkey, then walk uplink →
   travel SSID → VPN. The only path to a working device.
2. **Secure login** — minimal WebAuthn (§4.2), plus the key-only SSH toggle.
3. **Network / uplink** — join an upstream/hotel Wi-Fi (STA), set the travel
   SSID + password (AP), WAN/LAN basics. Single 2.4 GHz radio on the Mango,
   so AP+STA share the band (§2).
4. **WireGuard** — import a config, connect/disconnect, kill switch.
5. **DNS** — encrypted DNS (DoH/DoT) default.
6. **MAC privacy** — randomize the Wi-Fi MAC; on-demand now, scheduled next.
7. **Maintenance** — factory reset, firmware update.

Interface names (radio/AP/`lan`/`wan`) are read from `board.json`/UCI, never
hardcoded — they vary per device (the Mango is swconfig: `eth0.1`/`eth0.2`,
`wlan0`), the same "ask the platform" pattern BubbleUI uses.

## 6. Milestones

- **M0 — walking skeleton (current).** One binary, builds host + `mipsle`,
  serves the SPA, login + WireGuard + MAC-roll endpoints. ✅
- **M1 — on hardware.** Runs on a stock-OpenWRT Mango; wire login end to end
  from a browser; real `wg-quick` config import.
- **M2 — wizard + privacy.** First-boot flow, scheduled MAC rotation,
  kill switch.
- **M3 — packaging + distribution.** Per-arch `.apk`/`.ipk`, plus
  ready-to-flash images for a small, curated set of supported models
  (see §8). Optionally publish a feed for the OpenWRT firmware selector / ASU.

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

MistUI ships through two channels and — unlike BubbleUI — embraces pre-built
images:

1. **Ready-to-flash images (primary path for the audience).** For a small,
   curated set of supported models we publish factory / sysupgrade images
   with MistUI already baked in: flash once, no OpenWRT knowledge required.
   This is appropriate *because* the model list is deliberately short — a
   large per-device matrix is what turns a package into a distribution, so
   we keep the list small on purpose.
2. **`.apk` / `.ipk` (for existing OpenWRT users).** Install on top of a
   stock OpenWRT the user already runs, or select it via the firmware
   selector / ASU with a custom feed.

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
