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

const NONCE_TIMEOUT_MS = 8_000;

export interface CatchAllFingerprint {
  bodyLength: number;
  title: string;
}

async function safeGetForFingerprint(
  url: string,
): Promise<{ status: number; body: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NONCE_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "Mozilla/5.0 Seclayer Security Scanner" },
    });
    const body = await res.text().catch(() => "");
    return { status: res.status, body };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetches a random, guaranteed-nonexistent path at the target origin and
 * fingerprints the response. If the origin is a SPA/catch-all, this will be
 * HTTP 200 with the app's standard shell HTML — the same shell every other
 * unmatched path returns.
 */
export async function detectCatchAll(origin: string): Promise<CatchAllFingerprint | null> {
  const nonce = `vibescan-spacheck-${Math.random().toString(36).slice(2, 10)}-notfound`;
  const r = await safeGetForFingerprint(`${origin}/${nonce}`);
  if (!r || r.status !== 200) return null;
  const titleMatch = /<title[^>]*>([^<]{1,200})<\/title>/i.exec(r.body);
  return {
    bodyLength: r.body.length,
    title: titleMatch?.[1]?.trim() ?? "",
  };
}

/**
 * Returns true when a probe response looks like the catch-all shell rather
 * than genuine content at that path. Two independent signals — body size
 * within 3% of the baseline, or an exact <title> match — either is
 * sufficient, since catch-all shells are byte-for-byte consistent.
 */
export function matchesCatchAll(body: string, catchAll: CatchAllFingerprint | null): boolean {
  if (!catchAll || catchAll.bodyLength === 0) return false;

  const diff = Math.abs(body.length - catchAll.bodyLength) / catchAll.bodyLength;
  if (diff < 0.03) return true;

  if (catchAll.title.length > 3) {
    const titleMatch = /<title[^>]*>([^<]{1,200})<\/title>/i.exec(body);
    const title = titleMatch?.[1]?.trim() ?? "";
    if (title.length > 0 && title === catchAll.title) return true;
  }

  return false;
}
