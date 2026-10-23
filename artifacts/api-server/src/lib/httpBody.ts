/** Request headers and bounded response-body reading. */
import { SCANNER_USER_AGENT } from "./appOrigin";
import { type ScanHttpContext, type IdentityOverride, type HttpResult } from "./httpTypes";

export function buildHeaders(
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

/** Most decoded bytes of a target's response the scanner will hold in memory. */
export const MAX_BODY_BYTES = 5 * 1024 * 1024;

/**
 * The body as text, keeping whatever arrived if the request is aborted (the timeout) or the
 * connection drops part-way. res.text() throws away everything on failure, which for a stream that
 * was cut at the deadline is precisely the part worth having.
 */
export async function readBodyBounded(res: Response): Promise<string> {
  return (await readBodyMarked(res)).body;
}

/** As readBodyBounded, and says whether the read was cut short (deadline or reset) so the body is partial. */
export async function readBodyMarked(
  res: Response,
  maxBytes: number = MAX_BODY_BYTES,
): Promise<{ body: string; truncated: boolean }> {
  const reader = res.body?.getReader?.();
  if (!reader) {
    let failed = false;
    const body = await res.text().catch(() => { failed = true; return ""; });
    return { body: body.slice(0, maxBytes), truncated: failed || body.length > maxBytes };
  }
  const decoder = new TextDecoder();
  let out = "";
  let received = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.length;
      if (received > maxBytes) {
        // A decompressed body can be a thousand times its wire size. Stop reading and
        // drop the connection rather than hold it all in memory.
        out += decoder.decode(value.subarray(0, value.length - (received - maxBytes)), { stream: true });
        out += decoder.decode();
        await reader.cancel().catch(() => {});
        return { body: out, truncated: true };
      }
      out += decoder.decode(value, { stream: true });
    }
    out += decoder.decode();
  } catch {
    // Aborted or reset: what was read so far stands.
    out += decoder.decode();
    return { body: out, truncated: true };
  }
  return { body: out, truncated: false };
}

export async function readResponse(res: Response, redirected: boolean, maxBytes?: number): Promise<HttpResult> {
  const { body, truncated } = await readBodyMarked(res, maxBytes);
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

  return { status: res.status, body, headers, setCookies, finalUrl: res.url, redirected, ...(truncated ? { truncated } : {}) };
}
