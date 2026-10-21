/**
 * Shared HTTP client for every request the scanner makes *at a target*.
 *
 * Before this module each probe called `fetch` directly — around 30 call sites
 * across 27 modules, each re-implementing its own AbortController timeout and
 * picking one of three different User-Agent strings (or none at all). That is
 * survivable while every request is anonymous, but it leaves nowhere to hang
 * per-scan state, which authenticated scanning needs.
 *
 * The important rule this module exists to enforce:
 *
 *   Credentials attach ONLY to requests aimed at the scan target.
 *
 * The scanner also talks to third parties — api.deepseek.com, osv.dev,
 * cloudflare-dns.com, api.resend.com, endoflife.date. Those calls must never
 * carry a customer's session, and "remember not to do that" is not a control.
 * Scope is therefore checked here, on every request and on every redirect hop,
 * rather than trusted to callers. Third-party modules keep calling `fetch`
 * directly and are structurally unable to receive credentials.
 *
 * Context travels through AsyncLocalStorage rather than a parameter threaded
 * through ~11 module entry points and the 13 probe functions behind
 * `runAllProbes`. A scan is an ambient, per-async-task concern — the same shape
 * as a request context — and each pg-boss job already runs as its own task, so
 * the isolation is exactly right. With no context active (a monitor rescan, a
 * unit test) requests still work; they simply run anonymous.
 */

import { checkUrlSafe } from "./ssrfGuard";
import { scanDispatcher } from "./pinnedDispatcher";
import { SCANNER_USER_AGENT } from "./appOrigin";
import { DEFAULT_TIMEOUT_MS, MAX_REDIRECT_HOPS, type HttpResult, type ScanFetchOptions, type Outcome } from "./httpTypes";
import { storage, tryReauthenticate, throttle } from "./httpContext";
import { buildHeaders, readBodyBounded, readResponse } from "./httpBody";
export { DEFAULT_TIMEOUT_MS } from "./httpTypes";
export { ScanScope, runWithScanHttp, oncePerScan, sessionWasLost, getScanHttpContext } from "./httpContext";
export type { ScanCredentials, HttpResult, ScanHttpInit, ScanHttpContext, IdentityOverride, ScanFetchOptions } from "./httpTypes";

export { SCANNER_USER_AGENT };

export async function scanFetch(
  url: string,
  options: ScanFetchOptions = {},
): Promise<HttpResult | null> {
  const outcome = await perform(url, options);
  return outcome.ok ? outcome.result : null;
}

/**
 * Same as `scanFetch` but throws instead of returning null.
 *
 * Only for the request whose failure means the scan itself cannot proceed —
 * the first fetch of the target. There the underlying reason ("getaddrinfo
 * ENOTFOUND …") is what the user needs to see, and collapsing it to null would
 * turn a diagnosable error into a blank one.
 */
export async function scanFetchOrThrow(
  url: string,
  options: RequestInit & { timeoutMs?: number } = {},
): Promise<HttpResult> {
  const outcome = await perform(url, options);
  if (!outcome.ok) throw new Error(outcome.error);
  return outcome.result;
}

async function perform(url: string, options: ScanFetchOptions): Promise<Outcome> {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    redirect = "follow",
    headers: callerHeaders,
    as: identity,
    maxBodyBytes,
    ...rest
  } = options;
  // Distinguishes "no override" from an explicit null meaning "send anonymous".
  const identityGiven = "as" in options;
  const ctx = storage.getStore();

  let current = url;
  let redirected = false;
  // Guards the re-authentication retry so a target that always looks signed
  // out cannot bounce one request around the loop indefinitely.
  let reauthRetried = false;

  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
    // Checked per hop, not once up front. The URL submitted to /api/scans is
    // validated there too, but a target can redirect us to an internal address,
    // or re-answer DNS with one between the two checks — so the last word has
    // to belong to the code that is about to open the socket.
    if (ctx?.signal?.aborted) return { ok: false, error: "scan abandoned" };

    // The request timer starts before the DNS check, not after it: the lookup inside checkUrlSafe can
    // itself stall, and the per-request budget has to cover it.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const safety = await checkUrlSafe(current, { allowOptOut: true });
    if (!safety.ok) {
      clearTimeout(timer);
      return { ok: false, error: `blocked target address: ${safety.reason}` };
    }

    await throttle(ctx, current);

    // Which session this request goes out with. Parallel probes share one
    // context, so by the time a reply says "signed out" another probe may
    // already have signed back in — see the session-expiry block below.
    const credentialsSent = ctx?.credentials;

    // A caller may supply its own signal — reprobe.ts shares a single budget
    // across several parallel probes. Honour both: whichever fires first wins,
    // rather than silently discarding the caller's.
    const { signal: callerSignal, ...init } = rest;
    const signal = AbortSignal.any(
      [controller.signal, callerSignal, ctx?.signal].filter((x): x is AbortSignal => x != null),
    );

    let res: Response;
    try {
      res = await fetch(current, {
        ...init,
        // Always manual: following is done below so each hop is scope-checked.
        redirect: "manual",
        // Opens the socket only to an address vetted at connect time, so a name that
        // re-resolves to a private address between the check above and here is refused.
        dispatcher: scanDispatcher,
        signal,
        headers: buildHeaders(current, ctx, callerHeaders, identity, identityGiven),
      });
    } catch (err) {
      const reason =
        controller.signal.aborted
          ? `timed out after ${timeoutMs}ms`
          : err instanceof Error
            ? err.message
            : String(err);
      clearTimeout(timer);
      return { ok: false, error: reason };
    }
    // The timer stays armed while the body is read below. It used to be cleared here, as soon as
    // the headers arrived, and the body was then read with no timer at all: a stalled or
    // never-ending reply (a streaming chat endpoint) held the caller until the scan-level timeout,
    // so "timeoutMs" bounded only time-to-headers.

    const isRedirect = res.status >= 300 && res.status < 400;
    const location = isRedirect ? (res.headers?.get("location") ?? null) : null;

    // Stop when the caller asked to see redirects, when this is not one, or
    // when it is one the server left un-followable.
    if (redirect === "manual" || !isRedirect || !location) {
      const result = await readResponse(res, redirected, maxBodyBytes);
      clearTimeout(timer);
      // res.url is empty on a manual-mode response in some runtimes; fall back
      // to the URL actually requested so callers always get a usable value.
      if (!result.finalUrl) result.finalUrl = current;

      // ── Session expiry mid-scan ──────────────────────────────────────────
      // A session that dies partway through is worse than never having one:
      // every later probe reports "nothing found" for pages it was silently
      // bounced off. Detect it, sign back in if we can, and retry this request
      // once so the caller gets the authenticated response it expected.
      if (
        !reauthRetried &&
        // An override identity is the caller's business — a deliberate
        // anonymous probe looking signed out is the expected answer, not a
        // reason to re-authenticate the scan.
        !identityGiven &&
        ctx?.credentials &&
        ctx.scope.includes(current) &&
        ctx.detectSignedOut?.(result.body, result.finalUrl, url)
      ) {
        ctx.sessionWasLost = true;
        // Sent with a session that has since been replaced: that reply says
        // nothing about the NEW session. Retry with it instead of signing in
        // again — otherwise a slow reply arriving after another probe's
        // re-login spends a second one of the scan's two re-auth attempts,
        // and on a slow target the scan can run out of them.
        if (ctx.credentials !== credentialsSent) {
          reauthRetried = true;
          continue;
        }
        if (await tryReauthenticate(ctx)) {
          reauthRetried = true;
          continue;
        }
      }

      return { ok: true, result };
    }

    // Drain the redirect body so the socket can be reused, still under the request timer.
    await readBodyBounded(res);
    clearTimeout(timer);

    let next: string;
    try {
      next = new URL(location, current).toString();
    } catch {
      return { ok: false, error: `unparseable redirect target: ${location}` };
    }

    current = next;
    redirected = true;
  }

  // More hops than MAX_REDIRECT_HOPS — a loop, or a site determined not to
  // settle. Treat as unreachable rather than reporting a misleading result.
  return { ok: false, error: `exceeded ${MAX_REDIRECT_HOPS} redirects` };
}