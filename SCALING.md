# Scaling the scanner

How to serve more simultaneous scans, what actually limits it, and what breaks
if you scale the wrong thing. Written so a change is a lookup rather than a
re-derivation.

Every number here is tunable by environment variable. Nothing below needs a code
change until the "beyond 60" section.

---

## The model

Three services, and only one of them is safe to replicate today.

| Service | Runs | Replicate? |
|---|---|---|
| `web` | HTTP API, the frontend, **the in-process rate limiter** | **No — see below** |
| `secscan` | Scan worker + the monitor scheduler | **Yes** |
| `Postgres` | Data + the pg-boss job queue | Vertical / pooling |

**Parallel scans = `secscan` replicas x `SCAN_WORKER_CONCURRENCY`.**

Submission and execution are separate. Accepting a scan is an insert plus an
enqueue — measured at ~500 ms for a burst of 20, so the API is not the limit.
Execution is what queues: pg-boss hands each job to exactly one worker, and
anything past the parallel ceiling waits its turn rather than failing.

---

## Current target: 50 simultaneous scans

```bash
railway variables --service secscan --set "SCAN_WORKER_CONCURRENCY=10"
railway scale --service secscan --replicas 5
```

5 replicas x 10 = **50 parallel**. A backlog of 100 drains in roughly two
rounds — about **2-3 minutes**, against ~12 minutes on a single worker at 8.

### Why this shape rather than another

Fewer, fatter replicas cost fewer connections; more, thinner replicas isolate
memory. 5 x 10 sits where both are comfortable. The alternative that also
reaches ~50 — 7 replicas x 7 — costs 91 connections and blows the budget below.

---

## The connection budget — the thing that actually binds

Every process holds two pools: the app's (`DB_POOL_MAX`, default 10) and
pg-boss's (fixed at 3). Postgres defaults to `max_connections = 100` and
reserves a few for superusers, so treat **~95 as usable**.

```
(web replicas + secscan replicas) x (DB_POOL_MAX + 3)  <  95
```

At the target above:

| | Pool | pg-boss | Total |
|---|---:|---:|---:|
| `web` x 1 | 10 | 3 | 13 |
| `secscan` x 5 | 50 | 15 | 65 |
| | | | **78 / 95** |

A connection is held for the length of a *query*, not the length of a scan — a
scan makes a few dozen short queries across roughly a minute — so a pool of 10
comfortably serves 10 concurrent scans. The pool exists to survive bursts, like
several scans finishing and writing reports at the same instant.

**This ceiling is quiet when you hit it.** Requests wait for a connection
instead of failing, so the symptom is slow scans, not errors. `DB_POOL_MAX` sets
a 10-second connection timeout precisely so exhaustion eventually names itself.

---

## Do not replicate `web`

The rate limiter keeps its counters **in process**. Its own source says so:

> each replica limits independently, so running more than one app container
> needs shared storage instead

Two `web` replicas means every user silently gets double their scan allowance,
and the per-IP abuse ceiling doubles with it. That is a billing and abuse
problem, not a performance one, and nothing in the system will report it.

`web` is not a throughput constraint anyway — submission is cheap and one
container serves far more than this workload. It *is* a single point of failure
for accepting new scans. Fixing that means moving the limiter's counters into
Postgres, after which `web` replicates freely. Until then: one.

---

## Memory, and why concurrency is not free

A scan only launches a browser when the target renders as a single-page app
(`isSpa(html)`). For this product's audience — React, Next, Lovable and Bolt
apps — assume that is the common case, not the rare one.

Each replica runs **one** chromium (a singleton) and opens a context per
rendering scan, closing it in a `finally`. So per replica, plan for
`SCAN_WORKER_CONCURRENCY` concurrent contexts. Container args already include
`--disable-dev-shm-usage`, which is the flag that stops `/dev/shm` exhaustion in
a container.

Raising concurrency on one replica is cheaper in connections; adding replicas is
cheaper in memory. If a replica starts OOMing, lower its concurrency and add a
replica rather than doing the reverse.

---

## Scaling beyond ~60 parallel

Connections bind first, at about 6 replicas. Past that, adding containers stops
helping and starts starving the pool.

**Enable Postgres connection pooling** (`railway postgres` exposes it). A pooler
in transaction mode multiplexes many client connections onto few server ones,
which suits this workload exactly — short, sparse queries. After that,
`max_connections` stops being the ceiling and replicas scale on memory and cost.

Do that *before* the next big step up, not during an incident.

---

## Verifying a scale-up

Do not go straight to 5. Scale to **2** first and confirm two things in
`railway logs --service secscan`:

1. **Both replicas take work** — `Scan job started` lines from two different
   `hostname` values.
2. **Scheduled jobs still fire once.** `boss.schedule()` upserts by queue name,
   so N replicas produce one schedule row and one worker runs each job. Confirm
   exactly one `Running CVE check` per hour, not one per replica. If that
   ever doubles, every monitored customer gets duplicate alert emails.

Then go to 5.

## What to watch after

| Signal | Where | Means |
|---|---|---|
| `Scan worker concurrency` at boot | worker logs | the replica picked up the env var |
| Scans slow with no errors | timings | connection pool is the ceiling |
| `AI analysis could not be completed` | reports | AI provider is rate-limiting under load |
| `TLS configuration check could not complete` | worker logs | the target's port 443 did not answer a handshake within 8 s; the scan carries on without it |
| SSL Labs timeouts | worker logs | only when `SSLLABS_ENABLED=true`; expected under load, and the report simply has no SSL Labs grade |
| Replica restarts | Railway metrics | memory — lower concurrency, add a replica |

---

## Quick reference

| Goal | Replicas | Concurrency | Parallel | Connections |
|---|---:|---:|---:|---:|
| Today's default | 1 | 8 | 8 | 26 |
| **Target** | **5** | **10** | **50** | **78** |
| Practical ceiling without pooling | 6 | 10 | 60 | 91 |
| Beyond that | — | — | — | needs a pooler |
