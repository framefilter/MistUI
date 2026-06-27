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
	echo ">> deploying to root@$ROUTER"
	scp "$OUT/mistd" "root@$ROUTER:/usr/bin/mistd"
	ssh "root@$ROUTER" '/etc/init.d/mistd restart || mistd -addr 127.0.0.1:8080 &'
	echo ">> deployed; browse to https://$ROUTER/"
fi
