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

## 4. Authentication

- **Passwordless, WebAuthn-based.** A registered passkey / platform
  authenticator (Touch ID, Android, security key) is the credential.
- **Trust-on-first-use registration.** We store the credential's COSE
  public key without verifying its attestation statement — deliberately
  dropping the heavy, rarely-load-bearing half of WebAuthn.
- **Cheap login.** Verify the ES256 assertion signature over
  `authenticatorData ‖ SHA-256(clientDataJSON)`. That is the whole crypto
  cost (`internal/auth`).
- **Recovery:** a single random recovery token (planned), hashed at rest.
- Sessions are random 128-bit tokens in bbolt, set as `HttpOnly; Secure;
  SameSite=Strict` cookies.

## 5. MVP features

1. **WireGuard** — import a config, connect/disconnect, kill switch
   (connect/disconnect wired; import + kill switch next).
2. **Secure login** — minimal WebAuthn as above.
3. **MAC privacy** — randomize the Wi-Fi MAC on demand; scheduled rotation
   planned.
4. **First-boot wizard** — provision a passkey, set the travel SSID, import
   a VPN config. (Planned.)

## 6. Milestones

- **M0 — walking skeleton (current).** One binary, builds host + `mipsle`,
  serves the SPA, login + WireGuard + MAC-roll endpoints. ✅
- **M1 — on hardware.** Runs on a stock-OpenWRT Mango; wire login end to end
  from a browser; real `wg-quick` config import.
- **M2 — wizard + privacy.** First-boot flow, scheduled MAC rotation,
  kill switch.
- **M3 — packaging + distribution.** Per-arch `.apk`/`.ipk`; publish a feed
  so the package can be selected via the OpenWRT firmware selector / ASU.

## 7. Relationship to BubbleUI

Shared: visual language, UX patterns, the "above-UCI, vanilla-OpenWRT"
philosophy. Not shared: the backend. MistUI re-decides every backend choice
for the small tier (see README table). Improvements that are size-neutral
(e.g. the minimal-WebAuthn approach) may flow back upstream.
