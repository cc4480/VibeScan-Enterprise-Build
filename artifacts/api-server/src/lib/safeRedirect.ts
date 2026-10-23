/**
 * Where a post-sign-in redirect is allowed to land.
 *
 * A `returnTo` parameter is attacker-controllable and is followed AFTER a
 * successful sign-in, which is precisely when the victim trusts the page they
 * arrive on. That makes an open redirect here a credential-phishing primitive,
 * not a cosmetic issue.
 *
 * String checks cannot do this job, and both previous attempts here were
 * bypassable:
 *
 *   routes/auth.ts       returnTo.startsWith("/") ? returnTo : "/"
 *   routes/googleAuth.ts also rejected a leading "//"
 *
 * The first let "//evil.com" straight through. The second stopped that literal
 * form but not the ones the URL parser NORMALISES into it — per the WHATWG URL
 * spec a backslash is rewritten to a forward slash for special schemes, and
 * tab, newline and carriage return are stripped entirely, so all of these left
 * the site:
 *
 *   "/\evil.com"     -> https://evil.com/
 *   "/\t/evil.com"   -> https://evil.com/
 *   "/\n/evil.com"   -> https://evil.com/
 *
 * So resolve the value with the same parser the browser will use and confirm it
 * stayed on our origin, rather than trying to out-guess it with prefixes.
 */

/**
 * A base that cannot collide with a real target. `.invalid` is reserved by
 * RFC 2606 and never resolves, so a value that somehow produced this origin
 * still could not be navigated to.
 */
const RESOLUTION_BASE = "https://return-to.invalid";

/**
 * Returns a same-origin path safe to hand to res.redirect(), or "/" when the
 * input is missing, malformed, or points anywhere else.
 *
 * The return value is always a path — never an absolute URL — so a caller
 * cannot accidentally reintroduce the problem by concatenating.
 */
export function safeReturnTo(raw: unknown): string {
  if (typeof raw !== "string" || raw.trim() === "") return "/";
  let url: URL;
  try {
    url = new URL(raw, RESOLUTION_BASE);
  } catch {
    return "/";
  }
  // Anything that resolved to another origin — absolute, protocol-relative, or
  // normalised into one — is refused.
  if (url.origin !== RESOLUTION_BASE) return "/";
  const path = `${url.pathname}${url.search}${url.hash}`;
  // Defensive: a same-origin resolution always yields a rooted path, but never
  // hand back something that is not one.
  return path.startsWith("/") && !path.startsWith("//") ? path : "/";
}
