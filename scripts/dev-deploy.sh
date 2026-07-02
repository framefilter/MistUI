#!/usr/bin/env bash
# Cross-compile mistd for a target router and (optionally) deploy it live.
#
# The whole dev loop without ever building an OpenWRT image: flash stock
# OpenWRT on the router (DSA/board.json already correct), then build here and
# scp the binary over. Defaults target the GL-MT300N-V2 "Mango" (mipsle).
#
#   ./scripts/dev-deploy.sh                 # just build for mipsle
#   ROUTER=192.168.1.1 ./scripts/dev-deploy.sh   # build + deploy + restart
#
# Override ARCH/GOMIPS for other targets, e.g. ARCH=arm64 GOMIPS= for AXT1800.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-/tmp/mistui-bin}"
ARCH="${ARCH:-mipsle}"
GOMIPS="${GOMIPS:-softfloat}"
ROUTER="${ROUTER:-}"

mkdir -p "$OUT"
echo ">> building mistd for linux/$ARCH (GOMIPS=$GOMIPS)"
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" GOMIPS="$GOMIPS" \
	go build -ldflags="-s -w" -o "$OUT/mistd" ./cmd/mistd )

ls -lh "$OUT/mistd"

if [ -n "$ROUTER" ]; then
	# Transfer over an ssh pipe, NOT scp: OpenWRT's dropbear has no SFTP
	# subsystem, so modern (SFTP-based) scp just closes the connection.
	# Binary lands in /tmp (tmpfs) so dev iteration never wears the tiny
	# flash overlay; it does not survive a reboot, which is fine for dev.
	echo ">> transferring mistd to $ROUTER:/tmp/mistd (ssh pipe)"
	ssh "root@$ROUTER" 'cat > /tmp/mistd && chmod +x /tmp/mistd' < "$OUT/mistd"

	echo ">> (re)starting mistd on 0.0.0.0:8080"
	ssh "root@$ROUTER" '
		mkdir -p /tmp/mistui
		killall mistd 2>/dev/null
		start-stop-daemon -S -b -x /tmp/mistd -- -addr 0.0.0.0:8080 -db /tmp/mistui/mistui.db
	'
	echo ">> deployed & running — browse to http://$ROUTER:8080/ (plain HTTP; dev only)"
fi
