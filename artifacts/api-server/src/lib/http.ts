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

/** One canonical identity, replacing the three strings that were in use. */
export const SCANNER_USER_AGENT =
  "Mozilla/5.0 (compatible; Seclayer-Security-Bot/1.0; +https://seclayer.io/bot)";

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
}

export interface ScanHttpContext {
  scope: ScanScope;
  credentials?: ScanCredentials;
  minRequestIntervalMs: number;
  /** Last request time per host, for throttling. */
  lastRequestAt: Map<string, number>;
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
  };
  return storage.run(ctx, fn);
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

function buildHeaders(
  url: string,
  ctx: ScanHttpContext | undefined,
  caller: RequestInit["headers"],
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
  // module, so it is checked here rather than assumed of the caller.
  if (ctx?.credentials && ctx.scope.includes(url)) {
    if (ctx.credentials.cookie) headers["Cookie"] = ctx.credentials.cookie;
    Object.assign(headers, ctx.credentials.headers ?? {});
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
export async function scanFetch(
  url: string,
  options: RequestInit & { timeoutMs?: number } = {},
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

async function perform(
  url: string,
  options: RequestInit & { timeoutMs?: number },
): Promise<Outcome> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, redirect = "follow", headers: callerHeaders, ...rest } = options;
  const ctx = storage.getStore();

  let current = url;
  let redirected = false;

  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
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
        headers: buildHeaders(current, ctx, callerHeaders),
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
