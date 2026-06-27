# MistUI

A small, friendly web UI for travel routers — built for the lightweight
hardware that the bigger control panels leave behind.

MistUI exists so that more people can get **better, user-friendly privacy
options** on the cheap, ubiquitous travel routers they already own: a clean
WireGuard control, passwordless login, and automatic MAC-address
randomization, all on top of **vanilla OpenWRT** — no vendor firmware, no
LuCI required.

It is the lightweight sibling of [BubbleUI](https://github.com/framefilter/BubbleUI).
Where BubbleUI targets capable routers (128 MB+ flash) with a four-daemon
backend, MistUI collapses to **one tiny static binary** that fits on
16 MB-flash MIPS devices like the GL.iNet GL-MT300N-V2 ("Mango").

## Why a separate project

The constraint that drives everything: a 16 MB-flash, single-radio MIPS
router can't run BubbleUI's stack (SQLite has no MIPS port; the WebAuthn
library alone is ~11 MB). MistUI re-picks each backend choice for the small
tier:

| Concern | BubbleUI | MistUI |
|---|---|---|
| Process model | four Go daemons | one binary (`mistd`) |
| Store | SQLite (modernc) | bbolt (pure-Go, MIPS-friendly) |
| Login | full WebAuthn library | minimal WebAuthn (trust-on-first-use, assertion verify only) |
| Footprint (mipsle) | doesn't compile | ~7 MB raw, ~1.8 MB in a squashfs image |

The Svelte design language and UX ideas are shared; the backend is not.

## Status

Early — **M0 walking skeleton**. The daemon builds (host + `mipsle`),
serves the embedded SPA, and exposes login / WireGuard / MAC-roll endpoints.
Hardware bring-up, the first-boot wizard, and config import come next.

## Layout

```
cmd/mistd/            the daemon — main entrypoint
internal/store/       bbolt-backed credential/session store
internal/auth/        minimal WebAuthn (COSE parse + assertion verify)
internal/vpn/         wg-quick connector
internal/netcfg/      MAC randomization
internal/httpapi/     HTTP API + embedded SPA mount
web/                  the SPA (vanilla, embedded via go:embed)
package/mistui/       OpenWRT package (Makefile, procd init, uci-defaults, nginx)
scripts/dev-deploy.sh build for a target + deploy to a live router
```

## Quick start (dev)

```sh
go test ./...
go run ./cmd/mistd -addr 127.0.0.1:8080 -db /tmp/mistui.db
# browse http://127.0.0.1:8080
```

## Build for a router

Flash stock OpenWRT first (the official image has the correct DSA / board
config for the device — MistUI never touches the switch topology, only UCI).
Then:

```sh
./scripts/dev-deploy.sh                       # build mipsle binary
ROUTER=192.168.1.1 ./scripts/dev-deploy.sh    # build + scp + restart
```

## License

GPL-3.0-or-later. See [LICENSE](./LICENSE).
