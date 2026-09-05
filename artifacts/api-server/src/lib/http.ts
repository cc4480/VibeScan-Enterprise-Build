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

import { AsyncLocalStorage } from "node:async_hooks";
import { checkUrlSafe } from "./ssrfGuard";

/** One canonical identity, replacing the three strings that were in use. */
import { SCANNER_USER_AGENT } from "./appOrigin";
export { SCANNER_USER_AGENT };

export const DEFAULT_TIMEOUT_MS = 8_000;
const MAX_REDIRECT_HOPS = 5;

export interface ScanCredentials {
  /** Value for the Cookie header, e.g. "sid=abc; theme=dark". */
  cookie?: string;
  /** Extra headers such as Authorization. Sent only in scope. */
  headers?: Record<string, string>;
}

export interface HttpResult {
  status: number;
  body: string;
  headers: Record<string, string>;
  /**
   * Set-Cookie headers kept individually. Collapsing them into `headers` joins
   * them on ", ", which corrupts any cookie whose Expires date contains a comma
   * — and the cookie flag checks parse these.
   */
  setCookies: string[];
  finalUrl: string;
  /** True when at least one redirect was followed to reach finalUrl. */
  redirected: boolean;
}

export interface ScanHttpInit {
  /** The URL being scanned. Defines what counts as in scope. */
  targetUrl: string;
  credentials?: ScanCredentials;
  /** Minimum gap between requests to the same host. 0 disables throttling. */
  minRequestIntervalMs?: number;
  /**
   * Recognise a response as "you are signed out". Injected rather than imported
   * so this module stays free of scanner dependencies.
   */
  detectSignedOut?: (body: string, finalUrl: string, requestedUrl: string) => boolean;
  /**
   * Obtain a fresh session after the current one stops working. Returning null
   * means re-authentication is not possible — a pasted cookie cannot be renewed
   * — and the scan continues signed out.
   */
  onSessionLost?: () => Promise<ScanCredentials | null>;
}

/** How many times one scan will try to sign back in before giving up. */
const MAX_REAUTH_ATTEMPTS = 2;

export interface ScanHttpContext {
  scope: ScanScope;
  credentials?: ScanCredentials;
  minRequestIntervalMs: number;
  /** Last request time per host, for throttling. */
  lastRequestAt: Map<string, number>;
  detectSignedOut?: (body: string, finalUrl: string, requestedUrl: string) => boolean;
  onSessionLost?: () => Promise<ScanCredentials | null>;
  reauthAttempts: number;
  /**
   * Shared across concurrent probes so twenty parallel requests noticing the
   * same dead session trigger one sign-in, not twenty.
   */
  reauthInFlight: Promise<ScanCredentials | null> | null;
  /** True once a session was lost, whether or not re-authentication worked. */
  sessionWasLost: boolean;
}

const storage = new AsyncLocalStorage<ScanHttpContext>();

// ─────────────────────────────────────────────────────────────────────────────
// Scope
// ─────────────────────────────────────────────────────────────────────────────

export class ScanScope {
  readonly host: string;

  constructor(targetUrl: string) {
    this.host = new URL(targetUrl).hostname.toLowerCase();
  }

  /**
   * In scope means the target host itself or a subdomain of it. Protocol is
   * deliberately not compared: a scan legitimately probes http:// to check that
   * it redirects to https://, and both are the same origin as far as the
   * customer is concerned.
   *
   * A bare-host suffix check would treat "notmyhost.com" as a subdomain of
   * "myhost.com", so the dot is required.
   */
  includes(url: string): boolean {
    let host: string;
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      return false;
    }
    return host === this.host || host.endsWith(`.${this.host}`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Context
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Run `fn` with a scan context active. Every `scanFetch` beneath it — however
 * deep — picks the context up automatically.
 */
export function runWithScanHttp<T>(init: ScanHttpInit, fn: () => Promise<T>): Promise<T> {
  const ctx: ScanHttpContext = {
    scope: new ScanScope(init.targetUrl),
    ...(init.credentials ? { credentials: init.credentials } : {}),
    minRequestIntervalMs: init.minRequestIntervalMs ?? 0,
    lastRequestAt: new Map(),
    ...(init.detectSignedOut ? { detectSignedOut: init.detectSignedOut } : {}),
    ...(init.onSessionLost ? { onSessionLost: init.onSessionLost } : {}),
    reauthAttempts: 0,
    reauthInFlight: null,
    sessionWasLost: false,
  };
  return storage.run(ctx, fn);
}

/**
 * Whether the session dropped at any point during the scan.
 *
 * Worth reporting: a scan that silently lost its session covers less of the app
 * than the user asked for, and every "no finding" after that point means "not
 * looked at" rather than "looked at and clean".
 */
export function sessionWasLost(): boolean {
  return storage.getStore()?.sessionWasLost ?? false;
}

/**
 * Sign back in, at most once at a time and a few times per scan.
 *
 * Returns true when fresh credentials are now in place.
 */
async function tryReauthenticate(ctx: ScanHttpContext): Promise<boolean> {
  if (!ctx.onSessionLost) return false;

  if (ctx.reauthInFlight) {
    // Another probe is already signing in — wait for that rather than piling on.
    const creds = await ctx.reauthInFlight;
    return creds !== null;
  }

  if (ctx.reauthAttempts >= MAX_REAUTH_ATTEMPTS) return false;
  ctx.reauthAttempts += 1;

  ctx.reauthInFlight = ctx.onSessionLost().catch(() => null);
  try {
    const fresh = await ctx.reauthInFlight;
    if (fresh) {
      ctx.credentials = fresh;
      return true;
    }
    return false;
  } finally {
    ctx.reauthInFlight = null;
  }
}

export function getScanHttpContext(): ScanHttpContext | undefined {
  return storage.getStore();
}

// ─────────────────────────────────────────────────────────────────────────────
// Throttle
// ─────────────────────────────────────────────────────────────────────────────

async function throttle(ctx: ScanHttpContext | undefined, url: string): Promise<void> {
  if (!ctx || ctx.minRequestIntervalMs <= 0) return;

  let host: string;
  try {
    host = new URL(url).host;
  } catch {
    return;
  }

  const last = ctx.lastRequestAt.get(host);
  const now = Date.now();
  if (last !== undefined) {
    const wait = last + ctx.minRequestIntervalMs - now;
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  }
  ctx.lastRequestAt.set(host, Date.now());
}

// ─────────────────────────────────────────────────────────────────────────────
// Request
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Which identity a request should use.
 *
 * `undefined` means the scan's own credentials. An explicit value overrides
 * them, and `null` means send none at all — access-control testing has to ask
 * for the same URL as a second user and as nobody, and compare the answers.
 */
export type IdentityOverride = ScanCredentials | null | undefined;

function buildHeaders(
  url: string,
  ctx: ScanHttpContext | undefined,
  caller: RequestInit["headers"],
  identity: IdentityOverride,
  identityGiven: boolean,
): Record<string, string> {
  const headers: Record<string, string> = {
    "User-Agent": SCANNER_USER_AGENT,
    // Matches the previous behaviour of probes.ts safeGet: a cached response
    // would report the state of the site at some earlier time, which is
    // precisely what a scan must not do.
    "Cache-Control": "no-cache, no-store",
    Pragma: "no-cache",
  };

  // Credentials only ever go to the target. This is the whole point of the
  // module, so it is checked here rather than assumed of the caller — and the
  // scope check applies to an overriding identity exactly as it does to the
  // scan's own.
  const effective = identityGiven ? identity : ctx?.credentials;
  if (effective && ctx?.scope.includes(url)) {
    if (effective.cookie) headers["Cookie"] = effective.cookie;
    Object.assign(headers, effective.headers ?? {});
  }

  // Caller headers win, so an individual probe can still set Content-Type or
  // deliberately spoof an Origin.
  if (caller) {
    new Headers(caller).forEach((value, key) => {
      headers[key] = value;
    });
  }

  return headers;
}

async function readResponse(res: Response, redirected: boolean): Promise<HttpResult> {
  const body = await res.text().catch(() => "");
  const headers: Record<string, string> = {};
  // Defensive: scanFetch's contract is "returns null on failure, never throws",
  // and reading the response happens outside the fetch try/catch. A runtime that
  // hands back a response without a headers collection would otherwise escape
  // that contract and abort a whole probe.
  res.headers?.forEach((v, k) => {
    headers[k.toLowerCase()] = v;
  });

  const getSetCookie = (res.headers as { getSetCookie?: () => string[] } | undefined)?.getSetCookie;
  const setCookies = typeof getSetCookie === "function" ? getSetCookie.call(res.headers) : [];

  return { status: res.status, body, headers, setCookies, finalUrl: res.url, redirected };
}

/**
 * Perform a request against the scan target.
 *
 * Returns `null` on any network error, timeout or malformed URL — matching the
 * best-effort contract the probes were already written against, where a failed
 * check must never fail the scan.
 *
 * `redirect: "manual"` returns the 3xx itself with Location readable, which
 * open-redirect detection depends on. `redirect: "follow"` (the default) walks
 * the chain here rather than delegating to fetch, so scope can be re-checked at
 * every hop: a redirect off the target host continues, but without credentials.
 */
export type ScanFetchOptions = RequestInit & {
  timeoutMs?: number;
  /**
   * Send as a specific identity instead of the scan's own. `null` sends none.
   * Named `as` rather than `credentials` because RequestInit already has a
   * `credentials` field meaning something entirely different.
   */
  as?: IdentityOverride;
};

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

type Outcome = { ok: true; result: HttpResult } | { ok: false; error: string };

async function perform(url: string, options: ScanFetchOptions): Promise<Outcome> {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    redirect = "follow",
    headers: callerHeaders,
    as: identity,
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
    const safety = await checkUrlSafe(current, { allowOptOut: true });
    if (!safety.ok) {
      return { ok: false, error: `blocked target address: ${safety.reason}` };
    }

    await throttle(ctx, current);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    // A caller may supply its own signal — reprobe.ts shares a single budget
    // across several parallel probes. Honour both: whichever fires first wins,
    // rather than silently discarding the caller's.
    const { signal: callerSignal, ...init } = rest;
    const signal = callerSignal
      ? AbortSignal.any([callerSignal, controller.signal])
      : controller.signal;

    let res: Response;
    try {
      res = await fetch(current, {
        ...init,
        // Always manual: following is done below so each hop is scope-checked.
        redirect: "manual",
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
      return { ok: false, error: reason };
    } finally {
      clearTimeout(timer);
    }

    const isRedirect = res.status >= 300 && res.status < 400;
    const location = isRedirect ? (res.headers?.get("location") ?? null) : null;

    // Stop when the caller asked to see redirects, when this is not one, or
    // when it is one the server left un-followable.
    if (redirect === "manual" || !isRedirect || !location) {
      const result = await readResponse(res, redirected);
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
        if (await tryReauthenticate(ctx)) {
          reauthRetried = true;
          continue;
        }
      }

      return { ok: true, result };
    }

    let next: string;
    try {
      next = new URL(location, current).toString();
    } catch {
      return { ok: false, error: `unparseable redirect target: ${location}` };
    }

    // Drain the redirect body so the socket can be reused.
    await res.text().catch(() => "");

    current = next;
    redirected = true;
  }

  // More hops than MAX_REDIRECT_HOPS — a loop, or a site determined not to
  // settle. Treat as unreachable rather than reporting a misleading result.
  return { ok: false, error: `exceeded ${MAX_REDIRECT_HOPS} redirects` };
}
