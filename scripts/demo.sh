#!/usr/bin/env bash
# the whole pipeline against the fake shop: logs, probe, plan, replay,
# configs, and a canary through caddy if there is a caddy with the cache
# handler around (make caddy builds one into bin/).
set -euo pipefail

cd "$(dirname "$0")/.."
bin=$PWD/bin
out=${DEMO_DIR:-$PWD/demo}
n=${DEMO_REQUESTS:-500000}
shop_port=18081
edge_port=18082
mkdir -p "$out"
cd "$out"

pids=()
cleanup() {
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
}
trap cleanup EXIT

step() { printf '\n\033[1m$ %s\033[0m\n' "$*"; }

if [ ! -f access.json ]; then
	echo "writing $n requests of fake logpush traffic"
	"$bin/fakeshop" logs -n "$n" -format cloudflare > access.json
fi
"$bin/fakeshop" serve -addr "127.0.0.1:$shop_port" > shop.log 2>&1 &
pids+=($!)
sleep 0.5

step keyfold routes access.json
"$bin/keyfold" routes access.json

step keyfold probe -origin http://127.0.0.1:$shop_port -rate 200 access.json
"$bin/keyfold" probe -origin "http://127.0.0.1:$shop_port" -rate 200 -concurrency 8 -o probe.json access.json 2> probe.log

step keyfold synth probe.json
"$bin/keyfold" synth -o plan.json probe.json

step keyfold sim -plan plan.json access.json
"$bin/keyfold" sim -plan plan.json access.json

for t in cloudflare caddy nginx; do
	"$bin/keyfold" gen -plan plan.json -target $t -o "keyfold.$t" 2>> gen.log
done
echo
echo "configs: $out/keyfold.cloudflare, keyfold.caddy, keyfold.nginx"

caddy=${KEYFOLD_CADDY:-$bin/caddy}
if [ ! -x "$caddy" ] || ! "$caddy" list-modules 2>/dev/null | grep -q '^http.handlers.cache$'; then
	echo "no caddy with the cache handler (make caddy), skipping the canary"
	exit 0
fi
# the demo caddy shouldn't fight other caddies for the admin port
awk '$0 == "\tcache {" && !done { print "\tadmin off"; done = 1 } { print }' keyfold.caddy > keyfold.demo.caddy
cat > Caddyfile <<CADDY
import keyfold.demo.caddy

http://:$edge_port {
	import keyfold_cache
	reverse_proxy 127.0.0.1:$shop_port
}
CADDY
HOME=$out XDG_DATA_HOME=$out XDG_CONFIG_HOME=$out "$caddy" run --config Caddyfile --adapter caddyfile > caddy.log 2>&1 &
pids+=($!)
sleep 1

step keyfold canary record -plan plan.json -target http://127.0.0.1:$shop_port
"$bin/keyfold" canary record -plan plan.json -target "http://127.0.0.1:$shop_port" -rate 100 -o snapshot.json 2> canary.log

step keyfold canary verify -snapshot snapshot.json -target http://127.0.0.1:$edge_port
"$bin/keyfold" canary verify -snapshot snapshot.json -target "http://127.0.0.1:$edge_port" -origin "http://127.0.0.1:$shop_port" -rate 100
