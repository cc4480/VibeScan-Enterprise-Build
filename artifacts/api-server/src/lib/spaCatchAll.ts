/**
 * SPA / multi-tenant catch-all routing detection.
 *
 * Many platforms return HTTP 200 for essentially any path — SPAs with
 * client-side routing (React/Vite/Next.js custom 404 handlers), and
 * multi-tenant sites like GitHub/npm/PyPI where a single path segment is
 * interpreted as a username/package and rendered as a normal 200 page even
 * when nothing matches. Path-existence probes (checking for admin panels,
 * exposed docs, etc.) must fingerprint this behavior first, or every probed
 * path looks "exposed."
 *
 * Fingerprints a guaranteed-nonexistent path, then lets callers check whether
 * a given response matches that same shell (by body size or <title>).
 */

import { scanFetch } from "./http";

const NONCE_TIMEOUT_MS = 8_000;

export interface CatchAllFingerprint {
  /** Length of the baseline body with every echo of the requested path removed. */
  bodyLength: number;
  title: string;
}

/**
 * A body with every copy of the requested path taken out. Catch-alls that say
 * "could not find /x" or answer {"error":"not found","path":"/x"} change length
 * with each path, so comparing raw lengths reads each one as different content.
 * JSON encoders that escape "/" as "\/" are covered too.
 */
function withoutEcho(body: string, path: string | undefined): string {
  if (!path || path === "/") return body;
  return body.split(path).join("").split(path.replace(/\//g, "\\/")).join("");
}

function pathOf(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try { return new URL(url).pathname; } catch { return undefined; }
}

async function safeGetForFingerprint(
  url: string,
): Promise<{ status: number; body: string } | null> {
  const res = await scanFetch(url, { timeoutMs: NONCE_TIMEOUT_MS });
  return res ? { status: res.status, body: res.body } : null;
}

/**
 * Fetches a random, guaranteed-nonexistent path at the target origin and
 * fingerprints the response. If the origin is a SPA/catch-all, this will be
 * HTTP 200 with the app's standard shell HTML — the same shell every other
 * unmatched path returns.
 */
export async function detectCatchAll(origin: string): Promise<CatchAllFingerprint | null> {
  const nonce = `vibescan-spacheck-${Math.random().toString(36).slice(2, 10)}-notfound`;
  const url = `${origin}/${nonce}`;
  const r = await safeGetForFingerprint(url);
  if (!r || r.status !== 200) return null;
  const titleMatch = /<title[^>]*>([^<]{1,200})<\/title>/i.exec(r.body);
  return {
    bodyLength: withoutEcho(r.body, pathOf(url)).length,
    title: titleMatch?.[1]?.trim() ?? "",
  };
}

/**
 * Returns true when a probe response looks like the catch-all shell rather
 * than genuine content at that path. Two independent signals — body size
 * within 3% of the baseline, or an exact <title> match — either is
 * sufficient, since catch-all shells are byte-for-byte consistent. Pass the
 * probed URL so a shell that echoes the requested path is still recognised.
 */
export function matchesCatchAll(body: string, catchAll: CatchAllFingerprint | null, probedUrl?: string): boolean {
  if (!catchAll || catchAll.bodyLength === 0) return false;

  const length = withoutEcho(body, pathOf(probedUrl)).length;
  const diff = Math.abs(length - catchAll.bodyLength) / catchAll.bodyLength;
  if (diff < 0.03) return true;

  if (catchAll.title.length > 3) {
    const titleMatch = /<title[^>]*>([^<]{1,200})<\/title>/i.exec(body);
    const title = titleMatch?.[1]?.trim() ?? "";
    if (title.length > 0 && title === catchAll.title) return true;
  }

  return false;
}
