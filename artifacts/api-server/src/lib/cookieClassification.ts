/**
 * How a cookie's name is read, shared by the root scan (scanner.ts) and the
 * inner-page crawl (crawler.ts).
 *
 * This module exists because those two carried identical copies of the
 * classifier, with a comment on each saying it must match the other. The
 * duplication was deliberate — crawler.ts is pure logic and importing
 * scanner.ts would pull in the db layer, which reads DATABASE_URL at import
 * time — but "keep two regexes in sync by hand" is a bug waiting to happen,
 * and it duly happened: a fix to the HttpOnly rule landed in one and not the
 * other. Nothing here imports anything, so both can use it freely.
 */

/**
 * Names suggesting a cookie carries session or auth state. A missing flag on
 * one of these means something very different from a missing flag on a
 * UI-preference or analytics cookie, so they are scored separately.
 */
export const SESSION_COOKIE_PATTERN =
  /session|token|jwt|csrf|xsrf|login|credential|phpsessid|jsessionid|connect\.sid|remember_?me|auth_?token|access_?token|refresh_?token|\bsid\b/i;

export function isLikelySessionCookie(name: string): boolean {
  return SESSION_COOKIE_PATTERN.test(name);
}

/**
 * True for a double-submit CSRF token, which must be readable by JavaScript.
 *
 * The pattern is: the server sets a random value as a cookie, the page reads
 * it and echoes it in a request header, and the server compares the two. An
 * attacker's cross-origin page can cause the cookie to be sent but cannot read
 * it to set the header. Marking that cookie HttpOnly does not harden it — it
 * breaks the defence outright, because the page can no longer read it.
 *
 * So a CSRF cookie is still a session cookie for Secure and SameSite, which it
 * genuinely needs, and is exempt from HttpOnly alone.
 *
 * Dropbox is the case that surfaced this. `__Host-js_csrf` is Secure,
 * SameSite=None and deliberately not HttpOnly — the name says so — while every
 * other cookie Dropbox sets carries HttpOnly. We reported their correct
 * implementation as a Medium finding.
 *
 * A name carrying both a CSRF marker and a session marker is NOT exempt:
 * "session_csrf_token" is ambiguous, and the safer reading of an ambiguous
 * name is the one that keeps the cookie locked down.
 */
export function isCsrfTokenCookie(name: string): boolean {
  if (!/csrf|xsrf/i.test(name)) return false;
  return !/session|jwt|login|credential|phpsessid|jsessionid|connect\.sid|remember_?me|auth_?token|access_?token|refresh_?token|\bsid\b/i.test(
    name,
  );
}

/**
 * Whether a cookie must carry HttpOnly to be considered correctly configured.
 * Kept as its own function so both call sites ask the same question rather
 * than each re-deriving it from the two predicates above.
 */
export function requiresHttpOnly(name: string): boolean {
  return !isCsrfTokenCookie(name);
}
