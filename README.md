# keyfold

A CDN decides whether two requests can share a cached response by comparing their cache keys, and by default the key is the full URL with every query parameter in it. So `/products/blue-mug?utm_source=newsletter` and `/products/blue-mug?fbclid=IwAR...` are two cache entries and two origin fetches for the same page. Add cookies and `Vary` headers and one page can end up as thousands of entries.

keyfold works out which parts of a request actually change the response, builds the smallest cache key that still serves the right page, and replays your real access logs through a cache simulator to show what that key would do to your hit ratio and origin traffic. Then it writes the Cloudflare, Caddy or nginx config and checks the rollout from the outside.

It's one Go binary with no dependencies outside the standard library.

```
access logs -> routes -> probe (your origin) -> synth -> plan.json -> sim
                                                             |
                                                             +-> gen -> canary record / verify
```

## Quick start

The repo has a fake shop origin with known quirks (tracking params that do nothing, a currency cookie with no `Vary`, `X-Forwarded-Host` reflected into the page, a jQuery cache buster on the API) and a traffic generator for it. The demo runs the whole pipeline against it:

```bash
make build
```

```bash
./scripts/demo.sh
```

If you also run `make caddy` first, which builds Caddy with the cache handler into `bin/`, the demo ends with a canary run through a real cache.

For 500,000 requests of generated Logpush traffic (a day's worth) it printed this, trimmed:

```
$ keyfold routes access.json
route                     requests  cdn hit  urls    paths  urls/path  params (distinct values)
/products/{slug}          220941    16%      119756  2045   58.6       color (5), utm_campaign (42), utm_medium (4), utm_source (7), size (5), +4 more
/api/v1/items/{int}       59633     5%       38427   4648   8.3        _ (32784), fields (2), callback (1157)
/                         39611     41%      16118   1      16118.0    utm_campaign (42), utm_medium (4), utm_source (7), fbclid (6126), utm_content (12), +2 more
...

$ keyfold synth probe.json
route                     keep               drop                                 unverified  sorted  also keyed on
/products/{slug}          color,size         fbclid,gclid,ref,utm_campaign +3     -           yes     language,cookie currency
/api/v1/items/{int}       callback,fields    _                                    -           yes     header origin
/                         -                  fbclid,gclid,ref,utm_campaign +3     -           yes     device
/static/{asset}.js        v                  -                                    -           no      -
...
  [high] /products/{slug} vary-cookie: cookie currency changes the response (body differs: 16 56 91 €15).
         the origin doesn't send vary: cookie, so any cache keyed on the url mixes these up today
  [high] /products/{slug} unkeyed-input: the origin reflects x-forwarded-host into the page ...
  [info] /static/{asset}.js version-param: v probed as noise, but it reads like a cache-busting
         version param. dropping it would keep serving old assets after a deploy, so it stays

$ keyfold sim -plan plan.json access.json
distinct keys: 211648 now, 92790 planned (2.3x fewer)
working set:   10.5 GiB now, 5.0 GiB planned
hit ratio the cdn logged: 28.9%

   policy  size   capacity  hit ratio       byte hit ratio   origin traffic
                                  now  planned     now  planned     now   planned
      lru    2%  214.4 MiB      23.4%    31.6%   42.8%    49.9%   19.5 GiB  17.1 GiB
   s3fifo    2%  214.4 MiB      24.6%    32.4%   45.4%    51.8%   18.7 GiB  16.5 GiB
   s3fifo   10%    1.0 GiB      26.1%    34.3%   48.2%    55.3%   17.7 GiB  15.3 GiB
      inf     -  unbounded      27.4%    35.5%   50.7%    57.8%   16.8 GiB  14.4 GiB

per route, s3fifo at 10%:
                                      route  requests  hit now  planned  origin traffic saved
                         shop.example.com /     39611    38.1%    93.3%               1.4 GiB
          shop.example.com /products/{slug}    220941    13.6%    16.9%             503.5 MiB

$ keyfold canary verify -snapshot snapshot.json -target http://127.0.0.1:18082
95 match, 0 mismatch, 0 drifted, 0 errors
60 of 60 urls that should share a cache entry were served from cache
```

The product pages only move from 13.6% to 16.9% because they have a five minute TTL and a long tail of 2,000 products; most of them aren't requested twice in five minutes under any key. The home page goes from 38% to 93% because nothing on it depends on the query string. That gap between routes is the reason the simulator reports per route.

## Running it on your traffic

Everything starts from access logs. keyfold reads Cloudflare Logpush (`http_requests` dataset, NDJSON), Caddy's JSON access log and nginx. For nginx the default is the `combined` format; pass your own `log_format` string with `-nginx-format` and it's compiled into a matcher, so `$host`, `$upstream_cache_status`, `$http_accept_language` or `$cookie_currency` get picked up if you log them. Gzipped files are fine, and so is a list of rotated files.

```bash
keyfold routes access.log.*.gz
```

`routes` groups paths into patterns like `/products/{slug}`. Numbers, UUIDs, dates and hashed asset names get placeholders straight away; after that, any position in the path with more than 20 distinct literal values gets folded into `{slug}`, unless one of them carries a tenth of the traffic (that's usually a real section of the site, like `/products` next to a pile of one-off pages).

```bash
keyfold probe -origin http://10.0.3.7:8080 -o probe.json access.log.*.gz
```

The probe takes the busiest cacheable routes, picks sample URLs from the logs and re-requests them against your origin with one thing changed at a time. Point it at the origin, not the CDN: a cache in front answers every variant with the same stored copy and everything looks like noise. If the origin has its own cache, `-cache-buster kfcb` adds a random param to every request. It sends about 10 requests a second by default (`-rate`). It only ever sends GET, and it never replays cookie values whose names look like sessions or tokens.

If your logs don't record cookies, the probe doesn't know they exist. Pass the ones you know about with `-cookie currency=EUR` and they get probed like the rest.

```bash
keyfold synth -o plan.json probe.json
```

`synth` turns the evidence into a plan: per route, which params to keep, which to drop, whether param order matters, and which headers and cookies have to be in the key. The default `safe` mode drops only params that were proven to be noise, so a new param that shows up next month stays in the key. `-mode tight` keeps only what was proven to matter, which is smaller but will ignore a new param that does change the page.

```bash
keyfold sim -plan plan.json access.log.*.gz
```

`sim` replays every cacheable GET through LRU, FIFO, SIEVE, S3-FIFO and W-TinyLFU at a few cache sizes, once with today's key and once with the plan's, plus an unbounded cache as the ceiling. Sizes are a share of today's working set by default; `-sizes 512MB,4GiB` works too. TTLs come from the `max-age` the probe saw for each route. Origin cost is projected over 30 days from `-egress` (dollars per GB, 0.09 by default) and optionally `-per-million` requests.

```bash
keyfold gen -plan plan.json -target cloudflare -o rules.json
keyfold gen -plan plan.json -target caddy -o keyfold.caddy
keyfold gen -plan plan.json -target nginx -o keyfold.conf
```

```bash
keyfold canary record -plan plan.json -target http://10.0.3.7:8080 -o snapshot.json
keyfold canary verify -snapshot snapshot.json -target https://www.example.com -origin http://10.0.3.7:8080
```

`verify` exits 1 when anything mismatches, so it can gate a deploy.

## How the probe decides

For each sample URL it fetches the unchanged request three times. Bodies are normalised first: nonces, CSRF fields, HTML comments, request-id style JSON keys and timestamps within three days of now are masked. Anything else that differs between those identical requests (a rotating "deal of the hour", a load balancer member name) is learned as noise for that URL, as a bag of tokens.

Then come the variants. Each query param gets dropped and swapped for another value seen in the logs for that param (a real value, because made-up ones tend to 404 and then everything looks like it matters). The query gets reversed to test whether order matters. Cookies get dropped, swapped and added. `Accept-Language` and `User-Agent` each get two probes: one with a value of the same class (`en-GB` instead of `en-US`, Firefox instead of Chrome) and one across classes (German, an iPhone). If only the cross-class one changes the page, the key can use a normalised language or device type instead of the raw header, which is the difference between three cache entries and thousands. `X-Forwarded-Host` and `Origin` are sent too, because an origin that reflects a header the CDN doesn't key on can be poisoned by a single request.

A variant counts as "changes the response" only if the status, `Location`, content type, `Content-Language` or CORS header differ, or if its body has tokens that none of the baselines had. Then it has to reproduce: the variant is fetched again and fresh baselines go into the noise model, two rounds for stable pages and five for pages that were already wobbling. Every mistake this makes leans the same way. Keeping a param that could have gone costs some hit ratio; dropping one that matters serves the wrong page.

Before the plan is written, every difference the probe recorded is checked against the final key. A difference the key wouldn't tell apart shows up as an `uncovered` flag instead of a quietly wrong plan.

Two things get kept even when they probe as noise. `?v=`, `?ver=` and friends look like noise at any single moment, but they exist to bust caches after a deploy, and dropping them means serving last week's CSS after the next release. And anything seen in the logs but never covered by a probe stays in, with a warning if it's on more than 1% of requests.

## Config output

Cloudflare's custom cache keys (choosing query params, headers and cookies) are an Enterprise feature. With `-cf-plan` set lower, keyfold writes what those plans support (param order, ignoring the query string entirely where the plan allows it) and prints a warning for each route it can't express, rather than writing a key that leaves out something the probe saw change the page. Paths are matched with `strict wildcard`, and since a `*` there also matches `/`, each rule carries a second wildcard with one more slash than the pattern so `/products/*` can't apply to `/products/x/reviews`. With `-cf-regex` (Business and up) it uses `matches` instead. When the origin reflects `X-Forwarded-Host`, the output also has a request header transform rule that strips it. The output is the body for `PUT /zones/{zone_id}/rulesets/phases/{phase}/entrypoint`, one entry per phase, and that call replaces the existing rules in the phase, so merge first if you have some.

The Caddy output needs Caddy built with [cache-handler](https://github.com/caddyserver/cache-handler) (`make caddy` does it). In safe mode it strips dropped params with `uri query` before the cache sees the request; in tight mode it builds the key from a template that names only the kept params. Header and cookie key parts become `X-Keyfold-*` request headers that the cache handler adds to the key, and client-sent copies of those headers are deleted first.

The nginx output is a chain of `map` blocks ending in `$keyfold_cache_key`. Plain nginx can't sort a query string, so param order still splits entries there.

`-canary` gates every rule on an `X-Keyfold-Canary: 1` request header and puts that header in the key, so you can try the new key in production without touching what users get.

## The canary

`record` takes each planned route's sample URLs with the dropped params removed, plus siblings the new key should fold into them (dropped params with real values, a reversed query) and siblings it must keep apart (a kept param, the language, the device or a keyed cookie changed). It stores a fingerprint of each response. Record against the origin, or against the edge before the change.

`verify` replays them through the edge after the rollout, base URL first. A sibling that wrongly shares the base's key comes back with the base's page from cache and fails its hash. With `-origin` it re-fetches mismatches from the origin too, to tell a key mistake from content that changed since the snapshot. It also reports how many of the should-merge siblings the edge served from cache; zero usually means the rules aren't live.

## Tests

`go test ./...` runs everything that doesn't need extra binaries. A few things worth knowing:

The fake shop is the ground truth. The probe, synth and canary tests run the full loop against it and compare the plan with what's known about the shop. The canary tests also verify through a toy cache keyed by the plan, and through real Caddy (with the cache handler) and real nginx running the generated configs. Each one has to pass with the synthesised plan and fail when `color` is removed from the product key. Those last two run when `caddy` and `nginx` are on the `PATH` or `KEYFOLD_CADDY` and `KEYFOLD_NGINX` point at them, and the generated configs also go through `caddy validate` and `nginx -t`. CI installs both.

The eviction policies are checked for the byte budget after every access, for index consistency, against an infinite cache (no policy may beat it, and every policy has to match it when everything fits) and on a scan: with a hot set that fits plus a stream of one-hit wonders, LRU keeps 52% of hot-set hits and SIEVE, S3-FIFO and W-TinyLFU keep 97 to 98%.

The log parsers have fuzz targets (`go test ./internal/logs -fuzz FuzzNginxLine`).

On a 4-core VM, parsing runs at about 160k Logpush lines a second, and the simulator did the 42 replays above (492k requests each) in 2.9 seconds.

## Known gaps

The probe changes one thing at a time. If a param only matters when another one is present, it's caught only when a sample URL happens to carry both.

It only looks at GET. GraphQL over POST and anything keyed on the body are out of scope.

The simulator models a cache that keys on exactly what the plan says and ignores `Vary`, which is how Cloudflare behaves. Caddy's cache handler and nginx honour `Vary` on top of the key, so for them the "now" numbers on routes with `Vary` are a bit pessimistic. It also uses the origin's `max-age` and nothing else: no stale-while-revalidate, no edge TTL overrides, no tiered cache.

Header and cookie key parts can only be simulated if the logs recorded those headers and cookies. When they didn't, `sim` says which parts it had to treat as constant.

I haven't run the Cloudflare output against an Enterprise zone, only checked it against the rulesets API docs. The Caddy and nginx output is tested against the real servers.

## Layout

```
cmd/keyfold        the cli
cmd/fakeshop       demo origin and log generator
internal/logs      cloudflare, caddy and nginx parsers
internal/routes    path patterns, param stats, the route matcher
internal/normalize response fingerprints and the token-diff noise model
internal/probe     the variance prober
internal/synth     probe evidence to plan
internal/plan      the plan format and the key function everything shares
internal/cache     lru, fifo, sieve, s3-fifo, w-tinylfu
internal/sim       trace building and replay
internal/gen       cloudflare, caddy and nginx config
internal/canary    record and verify
internal/fakeshop  the shop itself
```

[docs/design.md](docs/design.md) has the reasoning behind some of the less obvious choices.

## License

MIT
