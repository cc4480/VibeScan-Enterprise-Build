/** The per-scan context: scope, credentials, re-authentication and throttling. */
import { AsyncLocalStorage } from "node:async_hooks";
import { MAX_REAUTH_ATTEMPTS, type ScanHttpContext, type ScanHttpInit } from "./httpTypes";

export const storage = new AsyncLocalStorage<ScanHttpContext>();

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
    ...(init.signal ? { signal: init.signal } : {}),
    reauthAttempts: 0,
    reauthInFlight: null,
    sessionWasLost: false,
    memo: new Map(),
  };
  return storage.run(ctx, fn);
}

/**
 * Run `fn` once per scan for `key`; every later caller in the same scan shares its result. Outside a
 * scan context it simply runs. The page's scripts were downloaded three times per scan (secret
 * scanning, API discovery, the prompt-injection probe), up to eight files of half a megabyte each.
 */
export function oncePerScan<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const ctx = storage.getStore();
  if (!ctx) return fn();
  const hit = ctx.memo.get(key) as Promise<T> | undefined;
  if (hit) return hit;
  const started = fn();
  ctx.memo.set(key, started);
  return started;
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
export async function tryReauthenticate(ctx: ScanHttpContext): Promise<boolean> {
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

export async function throttle(ctx: ScanHttpContext | undefined, url: string): Promise<void> {
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
