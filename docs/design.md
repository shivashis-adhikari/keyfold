# Design notes

Things that aren't obvious from the code, and a few that only became obvious after something broke.

## Probing the origin, one change at a time

The idea is differential testing: hold a real request fixed, change one part, compare. It's the same move Burp's Param Miner makes when it hunts for unkeyed inputs, and James Kettle's cache poisoning research is why the probe also sends `X-Forwarded-Host` and `Origin` even though nobody puts those in a cache key on purpose.

Going through the CDN defeats the whole thing. A cache that already keys on the full URL answers each variant from its own entry, fine, but a cache that already ignores a param answers the variant with the stored copy and the param looks like noise. So the probe talks to the origin and sends the public `Host` header.

Mutated values come from the logs. A made-up value like `color=redx` tends to fall through to a default variant or a 404, and that says something about the origin's validation and nothing about whether `color` matters for the values people actually send. Swapping in another value seen in the logs answers the real question. Made-up values are only the fallback when the logs have a single value for a param.

## Noise

The normaliser masks very little on purpose: nonces, CSRF form fields and meta tags, HTML comments, JSON keys named like request ids or timings, and timestamps within three days of now (dates further away are probably content, like a publish date). Every extra regex is a chance to mask a real difference.

Everything else is learned per URL. The unchanged request is fetched three times, and any token whose count differs between two of those is noise for that URL. A variant is compared against whichever baseline it's closest to, so a page with a rotating banner matches the baseline that showed the same banner.

That wasn't enough at first. The fake shop's home page flips a "deal of the hour" on every request, and with several workers probing at once a sample could see the same deal on all its baselines and then the other one on the variant. Two changes to the probe fixed most of it: the variant is fetched a second time and whatever moves between those two fetches is noise too, and a page that has shown any instability gets five rounds of fresh baselines before a difference is believed, instead of two. The rest was on the fake shop's side. Its rotation used one counter shared by every route, so concurrent workers could phase-lock onto a single value, which real rotating content doesn't do; now each rotating handler has its own counter. Before, the probe test got a verdict wrong in about one run out of eight. Afterwards 25 runs in a row got every verdict right.

Errors only go one way. When the evidence is unclear the verdict is "changes" or "unknown", never "noise", and both keep the part in the key.

## Language and device

A raw `Accept-Language` header in a cache key is close to useless: browsers send `en-US,en;q=0.9`, `en-GB,en;q=0.8`, `en` and so on, and each string is its own entry. What usually matters is the primary language. So each of `Accept-Language` and `User-Agent` gets a same-class probe (`en-GB` for `en-US`, Firefox for Chrome) and an other-class probe (German, an iPhone). Other-class only means the key can use Cloudflare's `lang` or `device_type` options, or the normalised maps the Caddy and nginx output build. Same-class as well means the origin really does look at the raw header, and that gets flagged, because keying on a raw user agent makes a route close to uncacheable.

## From evidence to a key

A query param is dropped when every probe that touched it said noise and there were at least two of them (one sample gives two: drop and swap). Otherwise it's kept. The plan also records which params were kept without evidence ("unverified"), because "kept because it matters" and "kept because nobody checked" are different conversations.

Cookies are keyed on presence only when there's positive evidence the value doesn't matter: dropping the cookie changed the page, swapping its value didn't. A probe that only added a cookie can't tell those apart, so it keys on the value.

At the end every recorded difference is checked against the finished key (`synth.Covers`). The only expected gap is `X-Forwarded-Host`, which should be stripped at the edge, not keyed.

## Routes

Route inference is two passes over the shape of the paths, one pass over the log. First every segment gets a cheap classification: digits become `{int}`, UUIDs `{uuid}`, bundler-hashed file names `{asset}.js`. Stats accumulate per resulting pre-template. Then the pre-templates go into a trie per host, and any node with more than 20 literal children of the same extension folds them into `{slug}` (or `{name}.png`), bottom up, merging their subtrees. A child with at least a tenth of its parent's traffic is left alone, which keeps `/products` from being folded together with `/about` and `/contact` just because the site has a lot of top-level pages.

Distinct-value counts use an exact set up to 2,048 entries and a 4 KB HyperLogLog after that. Memory per route stays flat, which matters for params like `fbclid` that are unique on every request.

## The simulator

The trace is five parallel slices (time, size, both key hashes, route), about 40 bytes a request, so a day of traffic for a busy site fits in memory and the policy-size grid can replay it in parallel without re-parsing.

All five policies work in bytes, not objects, and that changes a few details the papers state in object counts:

- S3-FIFO's small queue is 10% of the bytes, and the ghost queue gets a byte budget equal to the main queue's capacity where the paper says "as many entries as main". An object moves from small to main after two hits, its counter resets on the move, and main reinserts anything hit since its last pass.
- W-TinyLFU's window is 1% of the bytes and protected is 80% of main. A big candidate may need several victims gone; it gets in only if it beats each one on estimated frequency, which is how Caffeine handles weighted entries.
- SIEVE needs no changes. Eviction just keeps moving the hand until enough bytes are free.

All of them keep entries in one slice with int32 links instead of pointers, because a replay with a million live objects otherwise spends a good part of its time in the garbage collector.

An expired entry is refetched in place: same slot, new size and expiry, counted as a miss. That's what revalidation looks like to an eviction policy.

The unbounded cache is there as a ceiling. If a policy ever beats it there's a bug, and a test checks exactly that, on random traces with random sizes, along with the byte budget after every single access.

One thing that surprised me in the per-route output of a smaller test run: the static asset routes have the same key before and after, yet their hit ratio moved by 0.1 points. That's correct. The cache is shared, and freeing space elsewhere changes what gets evicted everywhere.

## Cloudflare

Custom cache keys (picking query params, headers and cookies) are Enterprise only. Below that, the only query option is ignoring the query entirely, plus sorting it. keyfold writes what the tier supports and warns about the rest. It never writes a rule that drops more than the plan says, because a key that loses a part that matters is worse than no rule.

Paths use `strict wildcard`, where `*` also matches `/`. On its own, `/products/*` would apply to `/products/x/reviews` too. The guard is a second wildcard of `/*` repeated one more time than the pattern has slashes, negated. A path with exactly as many slashes as the pattern can only line the slashes up one to one, so each `*` stays inside its segment. A path with more slashes matches the guard and is excluded.

Cloudflare doesn't key on `Vary` (apart from `Accept-Encoding` and its opt-in image variants), so an origin that sends `Vary: Accept-Language` and relies on it is broken there today. That's why the synthesiser flags those headers even when the origin does send `Vary`.

## Caddy

Caddy has no cache of its own; the cache-handler module (Souin underneath) provides one. I read its Caddyfile parser and key builder instead of trusting the README, which turned up `sort_query`, per-path `cache_keys` overrides and a `template` option, and showed that `cache_keys` patterns are matched against the request URI including the query string. So a path regex like `^/products/[^/]+$` has to become `^/products/[^/?]+([?]|$)` there.

Running the output through `caddy validate` turned up a problem the source didn't make obvious. With a pattern containing a backslash it failed with `invalid character '?' in string escape code`, coming from the module's own JSON encoding of `cache_keys`. Since the same regexes also end up in nginx strings and JSON, each with its own escaping rules, route regexes are now generated without backslashes at all (`[.]` instead of `\.`).

In safe mode the Caddy output strips the dropped params with `uri query` before the cache handler sees the request. Caddy re-encodes the query after that, sorted, so the default key is already the planned key. Header and cookie parts go through `X-Keyfold-*` request headers that the cache handler includes in its key, and the snippet deletes any client-sent `X-Keyfold-*` header first. Otherwise a client could choose its own cache entry.

## nginx

nginx has no way to delete one query param without Lua or njs, but a chain of `map` blocks can do it: each map removes the first occurrence of one dropped param from the previous map's output with a regex, and a last map trims a leading `&`. The regex requires `=`, `&` or the end right after the name, so dropping `utm_source` leaves `utm_source2` alone. Sorting is still out of reach, so param order keeps splitting entries in nginx.

## The canary

The order of requests is the point. `verify` fetches the base URL first, then the siblings that should fold into it. If the new key merges something it shouldn't, the sibling is served the base's cached page and fails its fingerprint. Recording against the origin rather than the old edge is the better default, since the old edge may already be serving mixed-up content, which is often why you're changing the key in the first place.

Pages that differ between identical requests can't be compared by hash. The snapshot keeps their tokens and the noise learned from two or three fetches. That still failed on the fake shop's API, whose responses carry a fresh request id every time: a new id is never in the noise set. So for noise tokens containing digits the snapshot also stores their shape (`h16` for sixteen hex characters, `d1` for one digit), and a later token with a recorded shape is ignored. Tokens without digits don't get a shape, so a changed word, like a colour or a currency name, is never written off this way.

## Speed

JSON decoding was about 40% of the time spent reading Logpush files and the path classifier's UUID and date regexes about 10%. Parsing now runs on every core in batches of 2,048 lines that are handed back in file order, so nothing downstream has to care, and the classifier checks UUIDs and dates byte by byte. 500,000 Logpush lines went from 8.6 to 3.1 seconds on a 4-core VM.
