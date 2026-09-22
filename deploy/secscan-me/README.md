# Deploying secscan.me — the public benchmark target

Scope of this document: **Tier 1 only** — the stable, always-on, detectable-but-not-
weaponizable target that scanners point at. Tier 2 (an ephemeral, genuinely
exploitable range, per-session, network-isolated) is designed in the top-level
project plan but not built; do not deploy real exploitability publicly until it
exists as its own isolated infrastructure. Deploying Tier 1 with Tier 2's claims
attached is the fastest way to lose the credibility this whole project depends on.

---

## Before you start — this order is not arbitrary

Two mistakes are easy to make and expensive to undo here:

1. **Deploying before confirming the host's terms allow it.** A deliberately
   vulnerable, publicly-scannable app is a normal and precedented thing to host
   (`testphp.vulnweb.com`, `scanme.nmap.org`, OWASP Juice Shop's public demo
   instance all do it) but it is not universally covered by a generic hosting
   ToS. **Confirm in writing with the provider before step 3**, not after. If
   Railway is the target platform, this is the same account secscan.us runs on
   — get it wrong and the risk is not just secscan.me, it's the product's own
   hosting relationship.
2. **Pointing DNS at the box before the SSRF allowlist and authorisation notice
   are both live.** The gap between "resolves" and "actually safe" is exactly
   the window a mass-scanning bot needs to find and abuse the open endpoint —
   see the SSRF section below. Steps 5 and 6 happen before step 7, always.

What you should have in hand:

- The `secscan.me` domain, registered and NOT yet pointed anywhere
- Confirmation from your hosting provider (see above)
- A Cloudflare account, kept **entirely separate** from the one secscan.us uses
- A place to run the collector for the SSRF-proof callback (see below) — this
  can be a second tiny service on the same platform, or literally a third-party
  request-bin-style endpoint; it does not need to be secscan.me's own origin

---

## 1. What ships, and what does not

| | This deployment | Explicitly NOT this deployment |
|---|---|---|
| Faults | Simulated exploitation, real detection surface (see `artifacts/vuln-fixture/README.md` — no real database, no real file read, provably fake secret literals) | Genuine RCE, real credential theft, anything a Tier-2 exploitation range would carry |
| Lifetime | Permanent, stable URL | Ephemeral, per-session instances |
| Network | Isolated project, isolated Cloudflare account, zero shared credentials with secscan.us | Anything reachable from, or reaching into, the product's own infrastructure |
| Egress | Locked to one allowlisted collector host, everything else refused | Open outbound — this is the one endpoint (`/api/webhook-preview`) that is genuinely dangerous unconstrained, see below |

## 2. Build the image

```bash
docker build -f artifacts/vuln-fixture/Dockerfile -t secscan-me:latest .
```

The Dockerfile (see its own header comment) produces a container holding
**only** this one workspace package and its one dependency (`express`) — no
api-server, no vibescan, no database driver, nothing that could leak a real
secret even if this image were somehow mis-deployed onto shared infrastructure.
It runs as a dedicated non-root user with no home directory.

Verify before pushing anywhere:

```bash
docker run --rm -p 127.0.0.1:4100:4100 \
  -e SSRF_PROBE_ALLOWLIST=your-collector-host.example \
  secscan-me:latest
curl -s http://127.0.0.1:4100/ | grep -o '<nav>.*</nav>'   # nav links present
```

## 3. Egress — the part the image itself cannot do

The Dockerfile hardens the container; it does not and cannot lock down the
network path out of it. That has to happen at the platform layer:

- **Fly.io / a VPS you control**: a firewall rule (iptables/nftables, or the
  platform's network policy) denying all outbound except DNS and the one
  collector host's IP.
- **Railway / most PaaS**: outbound is generally unrestricted by default and
  there is often no first-class "deny all egress" control. If that is the
  platform, the SSRF allowlist (step 4) becomes the ONLY control on that
  endpoint, and it must be verified working before DNS goes live, not assumed.

Either way: **`SSRF_PROBE_ALLOWLIST` is not optional for this deployment.** It
is the one thing standing between `/api/webhook-preview` and being an open
proxy into whatever the container's network can reach — cloud metadata
endpoints, other tenants on the same platform, or simply becoming
infrastructure for someone else's attack, attributed to this domain.

## 4. Configure the SSRF allowlist

```bash
# The exact host (and port, if not 80/443) that receives the SSRF-proof
# callback. A comma-separated list if you need more than one.
SSRF_PROBE_ALLOWLIST=collector.secscan.me
```

See the comment on `/api/webhook-preview` in `artifacts/vuln-fixture/src/server.ts`
for exactly what this does and does not restrict: unset is fully open for
local/CI runs — but with `NODE_ENV=production` (which the Dockerfile sets) the
server **refuses to start** without it, so a forgotten variable is a failed
deploy, not an open proxy. `SSRF_PROBE_UNRESTRICTED=true` overrides that, and
must never be set on anything reachable from outside. Set, it refuses every host except the exact
match, and refuses with the SAME response shape as a genuine network failure —
an attacker probing this endpoint from outside cannot distinguish "blocked by
the allowlist" from "that host is actually unreachable", which is what keeps
the allowlist from becoming a network-mapping oracle in its own right.

**Verify it before going further:**

```bash
# Must be blocked (502, generic error):
curl "https://secscan.me/api/webhook-preview?url=http://169.254.169.254/"
curl "https://secscan.me/api/webhook-preview?url=http://10.0.0.1/"
# Must ALSO be blocked — the redirect bypass. The fixture's own "/" is a
# planted open redirect. Expect 502: secscan.me itself must NOT be on the
# allowlist. If it were, this would bounce the fetch into cloud metadata.
curl "https://secscan.me/api/webhook-preview?url=https%3A%2F%2Fsecscan.me%2F%3Fnext%3Dhttp%3A%2F%2F169.254.169.254%2F"
# Redirects are never followed (fetch uses redirect: "manual"), so even an
# allowlisted host that redirects returns {"status":30x,...} — the redirect
# itself, not the page it points to.
# Must succeed (the whole point of the fault):
curl "https://secscan.me/api/webhook-preview?url=https://collector.secscan.me/probe-test"
```

## 5. Cloudflare — isolation, rate limiting, the authorisation notice

- **A Cloudflare account secscan.me's DNS alone uses.** Never the account
  secscan.us runs on — a misconfigured rule or a compromised token should not
  be able to touch both.
- **Rate limiting** tuned to permit one normal scanner's pace (ZAP's full
  active scan, Nuclei's default concurrency) and throttle a flood. Get the
  numbers from a real scan run against a staging copy before setting the
  production limit — see the benchmark's own scan durations in
  `scripts/benchmark/README.md` as a starting point.
- **The authorisation notice.** Two of the planted faults are "security.txt is
  missing" and "robots.txt discloses sensitive paths" — the two conventional
  places to put a "you may scan this" notice would each break a fault the
  manifest promises. Instead:
  - A visible banner on the homepage itself.
  - A dedicated `/about` page (not `/robots.txt`, not `/security.txt`) stating
    plainly that this host exists to be scanned, linking the manifest and this
    project's plan.
  - A DNS TXT record at the apex, for anyone who checks DNS before they probe:
    `secscan.me. TXT "This host is a public security-scanner benchmark target. Scanning is authorised. See https://secscan.me/about"`

## 6. Publish the manifest

```bash
npx tsx artifacts/api-server/scripts/benchmark/generate-manifest.ts \
  --app-version <the git tag or commit you deployed> \
  --out artifacts/vuln-fixture/public/manifest.json
```

Served at `https://secscan.me/manifest.json`. Bump `--app-version` on every
deploy that changes `server.ts` in a way that could move a fault; the
`contentHash` field lets a reader confirm the manifest they fetched matches the
app they scanned without needing to trust the version string alone.

## 7. Go live, then verify from the OUTSIDE

DNS last, after 1–6 are all confirmed. Then, from a machine that is not this
deployment's own network:

```bash
DATABASE_URL=postgres://x:x@127.0.0.1:1/x \
  npx tsx artifacts/api-server/scripts/live-scan.ts --active https://secscan.me
```

This requires adding `secscan.me` to that script's owned-domain allowlist
first — see the comment above `OWNED_DOMAINS` in `live-scan.ts`, and do that as
its own deliberate, reviewed change, the same way loopback was added for the
local benchmark.

Confirm:

- Every route in the published manifest is reachable and behaves as documented
- The SSRF allowlist blocks/permits exactly as in step 4, from outside
- The homepage nav still links every organically-discoverable fault (re-run
  `verify-vuln-fixture.ts`'s ground truth against the public URL, not just
  locally)

## 8. Ongoing

- **Assume constant attack.** Public vulnerable targets get found by mass
  scanners within hours of DNS propagating. That is fine given the above; it
  is not fine if any of the above was skipped.
- **Re-run the full three-scanner benchmark against the public host**, not
  localhost, before publishing any numbers that claim to describe
  `secscan.me` — a number measured against a loopback instance describes that
  instance, not the public one, even if the code is identical.
- **Version bumps.** Any change to `server.ts` that could move a fault needs a
  new `--app-version`, a regenerated manifest, and ideally a re-run of the
  published benchmark before the old numbers are treated as still current.
