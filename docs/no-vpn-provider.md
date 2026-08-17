# No VPN provider? Use a free Cloudflare WARP profile

MistUI's VPN step wants a WireGuard config, and the usual way to get one is
a paid VPN subscription. If you don't have one, the wizard's only other
option is *Skip* — which leaves you on the hotel network with no tunnel at
all.

There is a free middle ground. Cloudflare's WARP service hands out
WireGuard credentials for nothing, no account and no payment, and MistUI
imports them like any other config. This page shows how, and is honest
about what it does and doesn't buy you.

## What you get, and what you don't

WARP encrypts everything between your router and Cloudflare. Against the
threat MistUI is built for — an untrusted hotel or café network — that is
the whole job:

| | |
|---|---|
| Hides your traffic from the venue's network and other guests | ✅ |
| Hides your traffic and the sites you visit from the venue's ISP | ✅ |
| Replaces your IP address as websites see it | ✅ — with a Cloudflare one |
| Makes you appear to be in another country | ❌ **no** |
| Hides your traffic from the tunnel operator | ❌ Cloudflare can see it |
| Costs anything | free |

The two ❌ rows are the ones to be clear about. Cloudflare deliberately
picks an exit address near your real location, so WARP will not get you
past a geographic block or make you look like you're at home — if that's
why you want a VPN, WARP is not it. And you are trading "the hotel can see
my traffic" for "Cloudflare can see my traffic," which is a real
improvement on a strange network and not the same as a no-logs VPN.

If you already pay for a VPN, use that instead. This page is for people who
otherwise wouldn't have a tunnel at all.

## Getting a profile

You'll need a laptop or desktop for this part — the profile is generated
once and pasted into MistUI, so nothing needs to be installed on the router.

**1. Get `wgcf`.** It's a single binary, available for Linux, macOS and
Windows from [github.com/ViRb3/wgcf/releases](https://github.com/ViRb3/wgcf/releases).
It is an unofficial community tool, not a Cloudflare product.

**2. Register a free device.** In a terminal, in the directory where you
downloaded it:

```sh
wgcf register
```

This asks you to accept Cloudflare's terms and writes `wgcf-account.toml`.
Keep that file if you want to manage or delete the registration later —
Cloudflare allows five linked devices at a time.

**3. Generate the WireGuard config:**

```sh
wgcf generate
```

This writes `wgcf-profile.conf`. It looks like any other WireGuard config:

```ini
[Interface]
PrivateKey = ...
Address = 172.16.0.2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = ...
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = engage.cloudflareclient.com:2408
```

**4. Paste it into MistUI.** Open `wgcf-profile.conf` in a text editor, copy
the whole thing, and paste it into the VPN step of the first-boot wizard —
or, later, into **Import config** on the dashboard's VPN card. Then connect
as normal.

The `MTU = 1280` line matters; leave it alone. The `DNS = 1.1.1.1` line is
harmless but has no effect — MistUI sends every lookup through its own
encrypted DNS regardless, and you can pick that resolver separately in the
UI.

## Checking it works

From any device behind the router, visit:

```
https://1.1.1.1/cdn-cgi/trace
```

Look for `warp=on`. If it says `warp=off`, traffic is not going through the
tunnel. `warp=plus` means a paid WARP+ subscription is attached, which you
don't need.

## When it doesn't work

**Connects at home, fails at the hotel.** WARP uses UDP port 2408 by
default, and locked-down guest networks often block it. There is no fix
inside MistUI today; a paid VPN provider that offers TCP or port-443
fallback will get through where WARP won't. This is the most common failure
and the main practical reason not to rely on WARP as your only option.

**Sites show CAPTCHAs or block you.** Lots of traffic exits from Cloudflare's
addresses, so some sites treat them with suspicion. Everything behind the
router is affected at once. Disconnect the tunnel if a site is unusable.

**The sign-in page for the hotel Wi-Fi doesn't appear.** That's not WARP —
MistUI handles captive portals by holding the tunnel down until you've
signed in, then bringing it up. Follow the prompt in the UI.

**IPv6 problems.** Recent registrations have been handed IPv4-only service
even though the profile still contains an IPv6 address. If you see odd
stalls on IPv6-capable sites, delete the IPv6 `Address` line and the `::/0`
from `AllowedIPs`, and re-import.

## The fine print

MistUI does not register WARP accounts for you, and doesn't bundle `wgcf`.
This is a thing you can choose to do with a free service, documented here
because it's genuinely useful — not a feature of the router.

`wgcf` talks to Cloudflare's client API without being Cloudflare's client.
It has worked for years, but it's unofficial and could stop working at any
time, and whether Cloudflare's terms cover this use is not settled. Read
[Cloudflare's terms](https://www.cloudflare.com/public-resolver-mobile-terms)
and decide for yourself.

Background on why this isn't a built-in button:
[docs/cloudflare-warp.md](./cloudflare-warp.md).
