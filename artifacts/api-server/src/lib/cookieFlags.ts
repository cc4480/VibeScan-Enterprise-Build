/**
 * Reads the name and attributes of one Set-Cookie header.
 *
 * Attributes are parsed from the segments after the first ";" instead of testing
 * the whole header with /secure/i, which also matched a cookie NAME or value
 * containing "secure" and so counted the flag as present when it was not. A
 * cookie the server is deleting (Max-Age=0, or an Expires in the past) is marked
 * so callers can skip it: it holds no session, whatever flags it lacks.
 */
export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: boolean;
  deleted: boolean;
}

export function parseSetCookie(cookie: string, now = Date.now()): ParsedCookie | null {
  const [first = "", ...attrs] = cookie.split(";");
  if (!first.includes("=")) return null;
  const out: ParsedCookie = {
    name: first.split("=")[0]?.trim() || "cookie",
    secure: false,
    httpOnly: false,
    sameSite: false,
    deleted: false,
  };
  for (const raw of attrs) {
    const eq = raw.indexOf("=");
    const key = (eq === -1 ? raw : raw.slice(0, eq)).trim().toLowerCase();
    const val = eq === -1 ? "" : raw.slice(eq + 1).trim();
    if (key === "secure") out.secure = true;
    else if (key === "httponly") out.httpOnly = true;
    else if (key === "samesite") out.sameSite = true;
    else if (key === "max-age" && /^-?\d+$/.test(val) && Number(val) <= 0) out.deleted = true;
    else if (key === "expires") {
      const t = Date.parse(val);
      if (!Number.isNaN(t) && t < now) out.deleted = true;
    }
  }
  return out;
}
