/**
 * Reads a Strict-Transport-Security header the way RFC 6797 section 6.1 says a browser does: directive names are
 * case-insensitive, a value may be quoted (max-age="31536000" is valid), each directive counts once (the first), and a
 * header with no usable max-age is ignored altogether. Reading it with a pattern such as /max-age=(\d+)/ calls a quoted
 * value zero and reports a healthy policy as "too short".
 */
export interface HstsPolicy {
  /** Seconds, or null when the header has no usable max-age (browsers ignore it). 0 means "forget this host". */
  maxAge: number | null;
  includeSubDomains: boolean;
  preload: boolean;
}

export function parseHsts(header: string): HstsPolicy {
  const seen = new Map<string, string>();
  for (const part of header.split(";")) {
    const m = /^\s*([^\s=]+)\s*(?:=\s*(.*?))?\s*$/.exec(part);
    if (!m) continue;
    const name = m[1]!.toLowerCase();
    if (!seen.has(name)) seen.set(name, (m[2] ?? "").replace(/^"(.*)"$/, "$1"));
  }
  const raw = seen.get("max-age");
  return {
    maxAge: raw !== undefined && /^\d+$/.test(raw) ? parseInt(raw, 10) : null,
    includeSubDomains: seen.has("includesubdomains"),
    preload: seen.has("preload"),
  };
}
