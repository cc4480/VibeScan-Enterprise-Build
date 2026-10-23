/** Shapes and limits of the scan HTTP client. */
import { ScanScope } from "./httpContext";

export const DEFAULT_TIMEOUT_MS = 8_000;

export const MAX_REDIRECT_HOPS = 5;

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
  /** Set when the body read was cut short (timeout or reset): `body` is only what arrived. */
  truncated?: boolean;
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
  /** Aborted when the scan is abandoned (its deadline passed): in-flight and later requests fail. */
  signal?: AbortSignal;
}

/** How many times one scan will try to sign back in before giving up. */
export const MAX_REAUTH_ATTEMPTS = 2;

export interface ScanHttpContext {
  scope: ScanScope;
  credentials?: ScanCredentials;
  minRequestIntervalMs: number;
  /** Last request time per host, for throttling. */
  lastRequestAt: Map<string, number>;
  detectSignedOut?: (body: string, finalUrl: string, requestedUrl: string) => boolean;
  onSessionLost?: () => Promise<ScanCredentials | null>;
  signal?: AbortSignal;
  reauthAttempts: number;
  /**
   * Shared across concurrent probes so twenty parallel requests noticing the
   * same dead session trigger one sign-in, not twenty.
   */
  reauthInFlight: Promise<ScanCredentials | null> | null;
  /** True once a session was lost, whether or not re-authentication worked. */
  sessionWasLost: boolean;
  /** Work done once per scan and shared by every probe that asks for it. See oncePerScan. */
  memo: Map<string, Promise<unknown>>;
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
  /**
   * Most decoded bytes of the response to keep, where the default (MAX_BODY_BYTES, 5 MiB) is too small for what the
   * caller needs to read whole: a source map with embedded source grows with the application and passes 5 MiB in
   * an ordinary app, and a truncated map is not valid JSON.
   */
  maxBodyBytes?: number;
};

export type Outcome = { ok: true; result: HttpResult } | { ok: false; error: string };
