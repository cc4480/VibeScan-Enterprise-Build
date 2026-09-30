/**
 * Request filter for the headless browsers.
 *
 * Chromium follows redirects and runs the page's own JavaScript, so a scan target could answer 302 to
 * http://169.254.169.254/ (the cloud metadata service) or an internal address and have our browser
 * fetch it from inside our network, or make the page's script do the same. The HTTP client already
 * refuses those addresses on every hop; this gives the browser the same rule on every request it
 * makes, and stops it handing the customer's credentials to every host the page happens to load
 * (analytics, CDNs, a redirect to another site) by attaching them only to requests in scope.
 *
 * Known limit: the check resolves the name once and Chromium resolves it again, so a DNS server that
 * answers differently the second time can still slip through. Closing that needs a resolving proxy.
 */
import { checkUrlSafe } from "./ssrfGuard";

export type UrlAllowed = (url: string) => Promise<boolean>;

/** The real rule: public http(s) addresses only, unless the operator opted in to private targets. */
const defaultAllowed: UrlAllowed = async (url) => (await checkUrlSafe(url, { allowOptOut: true })).ok;

let override: UrlAllowed | null = null;
/** Tests only: substitute the address rule so redirects between local hosts can be told apart. */
export function __setBrowserUrlRule(fn: UrlAllowed | null): void {
  override = fn;
}

interface FetchedLike { status(): number; headers(): Record<string, string> }
interface RouteLike {
  request(): { url(): string; headers(): Record<string, string> };
  abort(reason?: string): Promise<void>;
  fallback(): Promise<void>;
  fetch(opts?: { url?: string; headers?: Record<string, string>; maxRedirects?: number }): Promise<FetchedLike>;
  fulfill(opts: { response: FetchedLike }): Promise<void>;
}
interface WebSocketLike {
  url(): string;
  close(opts?: { code?: number; reason?: string }): Promise<void>;
  connectToServer(): unknown;
}
interface RoutableLike {
  route(url: string, handler: (route: RouteLike) => Promise<void> | void): Promise<void>;
  routeWebSocket?(url: string, handler: (ws: WebSocketLike) => Promise<void> | void): Promise<void>;
}

export interface BrowserGuardOptions {
  /** Headers (Cookie, Authorization...) that may go only to URLs for which `inScope` is true. */
  credentialHeaders?: Record<string, string>;
  inScope?: (url: string) => boolean;
  /** Called once for each request that was refused, for the caller's log. */
  onBlocked?: (url: string) => void;
}

const MAX_HOPS = 10;

/**
 * Installs the filter on a browser context. Each request is fetched here and the answer handed to the
 * browser. Redirects are followed HERE, one hop at a time, each hop checked, because Playwright does
 * not run the filter again for the redirect hops of a request it lets through (a 302 to an internal
 * address would go unchecked), and it ignores a Cookie override on such a request. The browser is only
 * ever given the final, non-redirect answer. Credentials go on a hop only if that hop is in scope, so a
 * redirect to another site does not carry them along.
 */
export async function guardBrowser(target: RoutableLike, opts: BrowserGuardOptions = {}): Promise<void> {
  const allowed = override ?? defaultAllowed;
  const creds = opts.credentialHeaders && Object.keys(opts.credentialHeaders).length > 0 ? opts.credentialHeaders : null;

  const permits = async (url: string): Promise<boolean> => {
    try {
      return await allowed(url);
    } catch {
      return false; // could not tell: not safe
    }
  };

  await target.route("**/*", async (route) => {
    const req = route.request();
    const base = req.headers();
    let url = req.url();
    // A WebSocket handshake cannot be fetched and fulfilled like a page; the WebSocket rule below owns it.
    if (/^wss?:/i.test(url)) {
      await route.fallback().catch(() => undefined);
      return;
    }
    try {
      for (let hop = 0; ; hop++) {
        if (!(await permits(url))) {
          opts.onBlocked?.(url);
          await route.abort("blockedbyclient").catch(() => undefined);
          return;
        }
        const headers = creds && opts.inScope?.(url) ? { ...base, ...creds } : base;
        const response = await route.fetch({ ...(hop > 0 ? { url } : {}), headers, maxRedirects: 0 });
        const status = response.status();
        const location = status >= 300 && status < 400 ? response.headers()["location"] : undefined;
        if (!location) {
          await route.fulfill({ response });
          return;
        }
        if (hop >= MAX_HOPS) throw new Error("too many redirects");
        url = new URL(location, url).toString();
      }
    } catch {
      await route.abort("failed").catch(() => undefined);
    }
  });

  // A page's script can open a WebSocket to an internal service as easily as it can fetch() one.
  await target.routeWebSocket?.("**/*", async (ws) => {
    if (!(await permits(ws.url()))) {
      opts.onBlocked?.(ws.url());
      await ws.close({ code: 1008, reason: "blocked" }).catch(() => undefined);
      return;
    }
    ws.connectToServer();
  });
}
