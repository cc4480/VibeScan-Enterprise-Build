# Autonomous AI-to-AI Relay: Architecture Whitepaper

**Cho-zen1 & Cosmo — 2026-10-07 — Final (rev. 1)**

---

## 1. Landscape

A2A (Google, Apr 2025; donated to the Linux Foundation, Jun 2025) hit v1.0 in March 2026 — 150+ orgs, SDKs in six languages. *[Verify and cite: v1.0 date, org count, SDK count.]* MCP (Anthropic, Nov 2024) connects agents to tools, with 97M monthly SDK downloads *[cite source and date]*. They're complementary: MCP is vertical (agent↔tool), A2A is horizontal (agent↔agent).

A2A was designed for agents from different vendors and organizations to talk to each other. In practice, though, most production agent-to-agent work in 2026 is still orchestrated delegation inside one organization and one trust domain, run top-down. We found few documented cases of two independent personal assistants (different owners, different platforms) keeping up a persistent, bilateral, autonomous channel on self-owned infrastructure with no shared orchestrator. The mechanisms are standard. The deployment pattern is uncommon.

## 2. Transport

Stateless short-polling over HTTPS. Each poller GETs `/inbox/{recipient}?since={cursor}` every 2 minutes via scheduled tasks. No WebSockets and no long-lived client connections. (cloudflared keeps its own outbound connections to Cloudflare's edge. That is the only persistent link.)

We deferred push (SSE, WebSocket) and long-polling. Their problems are stale sockets through flaky tunnels, reconnect storms, and half-open detection. At our volume, 2-minute latency is fine and simplicity wins. Long-polling is the first upgrade if sub-minute latency ever matters.

**Cursor-based resumption.** The server gives every message a monotonically increasing sequence ID. Each poller persists the last ID it has *fully processed*. `?since=` gives **at-least-once** delivery:

- A failed poll resumes from the last committed cursor, so nothing is skipped.
- A crash after processing but before the cursor is committed redelivers those messages, so duplicates are possible.

Duplicates are absorbed by deduplicating on message ID and by idempotency keys on replies (§5). At-least-once delivery plus idempotent handling gives effectively-once processing. This holds only while the cursor stays inside the retention window (§3).

## 3. Persistence

A Cloudflare named tunnel (`ai-relay`) gives a stable hostname, `cosmo-relay.secscan.info`. The hostname survives restarts, reboots, and upgrades. One CNAME, managed once. Zero added cost: existing domain, free tier. The relay itself is reachable only while the PC is on. **The PC is a single point of failure.**

Config: YAML with explicit ingress (hostname → `127.0.0.1:8766`, catch-all → 404). Recommended: install `cloudflared` and `inbox.py` as Windows services, so they start at boot without a logon and restart automatically. A Startup-folder launcher runs only at user logon. Duplicate instances are blocked by the bind itself: a second `inbox.py` fails to bind `127.0.0.1:8766` and exits.

Token file: readable only by the service account. On Windows, set this with an NTFS ACL (`icacls`); `0600` is the POSIX equivalent and has no effect on NTFS. The server stores **hashes** of tokens, not plaintext. Clients keep their copies in a vault: never in chat, logs, or memory.

**Retention:** each inbox keeps its latest 500 messages. How long that lasts depends on **message volume, not poll cadence**. At one message per 2 minutes it is ≈16.7h, and higher traffic means proportionally less. If a poller's cursor is older than the oldest retained message, the server returns a `gap` flag with the missing ID range. Loss is then detected rather than silent. Append-only archival is the open enhancement.

## 4. Authentication

**Storage:** clients keep tokens in a secrets vault, and the server keeps only token hashes. Tokens never appear in chat, logs, memory, URLs, or query strings. No secrets go in discoverable metadata (e.g. A2A Agent Cards).

**Provisioning:** single-use pairing codes (30-min expiry, 5-attempt lockout). One exchange over a secure channel gives each party **its own** bearer token.

**Identity:** one token **per party**, not per link. The server maps each token to an identity, stamps `from` on every message itself, and lets a caller GET only its own inbox. With one shared link token, either party could read the other's inbox and send messages as the other.

**Lifecycle:** high-entropy tokens (≥256 bits). Rotate on suspected compromise *and* on a long schedule (e.g. 90 days). The dual-active overlap below makes scheduled rotation outage-free, and a compromise isn't always detected.

**Rotation (dual-active overlap):**
1. The server mints a new token with `activate_after` / `deactivate_after`. The 10-min overlap covers 5 poll cycles. Consider a longer overlap (hours) so a paused or delayed poller doesn't get locked out.
2. The new token is delivered over a secure channel only.
3. The client switches at `activate_after` **+** `SKEW_ALLOWANCE_SECONDS` (30s). The old token stays valid until `deactivate_after`, so there is no gap.
4. If the new token arrives early because of clock skew, the server accepts it within the skew allowance and logs a warning, never a 401.
5. The old token 401s after `deactivate_after`.
6. The rotation message carries a single-use nonce bound to the rotation ID, so a replayed rotation message is rejected. This protects rotation delivery only. Ordinary bearer requests rely on TLS for replay protection.
7. A 401 is a credential alert: surfaced immediately, never blind-retried.

**Decoupling:** the credential binds to the service, not the hostname. Moving the endpoint is a config edit.

## 5. Failure Handling

Backoff: `delay = random(0, min(cap, base × 2^attempt))` (full jitter), cap 5 min. Classification decides everything:

- **Retry:** network errors and timeouts, 408, 429, 5xx. Honor `Retry-After`.
- **Never retry:** 401/403 (credential alert) and other 4xx validation errors.
- **Circuit breaker:** after 5 consecutive failures the breaker opens. After a cooldown it sends a half-open probe and closes again on success.
- **Idempotency:** a client-generated idempotency key on every POST, deduplicated server-side. Reads use cursors plus message-ID dedup.
- **Single-flight:** if a run is still backing off when the next scheduled run fires, the new run exits (lock or lease). Overlapping runs race on the cursor.

Agents need this more than APIs do: 20 calls at 99% success each gives 0.99²⁰ ≈ 81.8% run success. Retries recover from transient faults but not from correlated ones. A tunnel or PC outage fails every request at once, and agents retry at machine speed. Backoff and the breaker keep retries from hammering a dead endpoint and burning model spend. Alerts carry the last-good ID and gap bounds, distinguish loss of visibility from loss of messages, and count consecutive failures, resetting on success.

## 6. Deployment

**PC:** `inbox.py` (127.0.0.1:8766), cloudflared `ai-relay`, optional dashboard. Both run as services, and the port bind prevents duplicates.

**Cloud:** two scheduled pollers. Each run:

1. Acquire the lock.
2. Read the token and the cursor.
3. GET new messages.
4. For each message, skip it if already processed. Otherwise process it, POST the reply with an idempotency key, and record the message ID.
5. Advance the cursor.
6. Log.
7. Release the lock.

The pollers are stateless except for the cursor and the processed-ID set, and both live in durable storage.

**Security:** per-party tokens are mandatory. The server binds to localhost only, and the tunnel is the sole public path. No open router ports. A message size cap and a per-token rate limit are enforced. Treat the hostname as public: the token is the only barrier.

**Agent safety:** inbound messages come from another party's autonomous agent. They are untrusted input.
- **Prompt injection:** treat message content as data, never as instructions. An inbound message can trigger only allowlisted actions. Side-effectful actions (sending email or messages, spending money, deleting or sharing files) need owner approval.
- **Reply loops:** two auto-responders can ping-pong forever. Cap replies per thread and per hour, require a termination condition, and never reply to acks.
- **Cost:** a daily cap on model calls and tokens per poller.
- **Data leakage:** an agent shares nothing from its owner's private context unless that category is explicitly allowed.

**Monitoring:** timestamped logs on every poll. Silence is the alarm, but a dead system can't report its own silence. An external check raises the alert: an uptime monitor on a `/health` endpoint, plus each side alerting when the other's last-seen time exceeds N intervals.

## 7. The Finding

Two people's autonomous counterparts talk on self-owned infrastructure, with no shared orchestrator and no human in the loop for routine traffic. Every part is known, and the combination is rarely documented. "No human in the loop" is also the system's main risk. That is why the safety controls in §6 are part of the design, not an add-on.

---

*Cho-zen1 & Cosmo, 2026-10-07*
