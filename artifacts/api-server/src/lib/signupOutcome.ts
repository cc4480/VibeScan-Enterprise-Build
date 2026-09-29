/**
 * Reading what a signup submission actually produced. Pure: no requests are made here.
 *
 * The first version of autoSecondAccount.ts called any Set-Cookie on the response a session. Two
 * reviewers simulated it and got a "second account" back from a 419 CSRF failure, from a 400
 * that CLEARS a cookie, and from a 500 that sets an anonymous connect.sid — an identity
 * equivalent to nobody, which the access-control probe then compared against, found nothing,
 * and reported as a clean run. What counts as a session, and what counts as "this needs email
 * verification", lives here so both can be tested without a server.
 */
import { LOGIN_SHAPED_RE, visibleText } from "./signupForm";

/**
 * Wording that says an email step stands between the visitor and a working account.
 *
 * Deliberately wide: a miss creates an unverified account and triggers a mail to example.com,
 * while a false hit only skips one test with an honest reason. Each alternative is a phrase, not
 * a bare word, and "sent" needs a boundary on both sides ("email ... consent" is not a mail).
 */
const VERIFICATION_RE = new RegExp(
  "\\b(?:" +
    [
      String.raw`check (?:your )?(?:e-?mail|inbox)`,
      String.raw`(?:confirm|verify|activate)(?:ing)? (?:your |the )?(?:e-?mail|account|address|identity)`,
      String.raw`(?:confirmation|verification|activation) (?:link|e-?mail|code|message)`,
      String.raw`almost there`,
      String.raw`(?:we|i)(?:'ve| have)? sent (?:you )?(?:an? |the )?(?:e-?mail|message|link|code|confirmation|verification)`,
      String.raw`(?:e-?mail|message|link|code|confirmation) (?:has |have |was |is being )?(?:been )?sent`,
      String.raw`e-?mail[^.\n<]{0,40}\bsent`,
      String.raw`enter the \d[- ]?digit (?:verification |confirmation )?code`,
      String.raw`\d[- ]digit (?:verification |confirmation )?code`,
      String.raw`pending[_\s-]?(?:verification|confirmation|activation)`,
      String.raw`(?:e-?mail[_\s-]?)?(?:verified|confirmed)["']?\s*:\s*false`,
      String.raw`unverified`,
      String.raw`must (?:verify|confirm|activate)`,
    ].join("|") +
    ")\\b",
  "i",
);

/** True when a response body says an email step is needed. Script and style text is ignored. */
export function requiresEmailVerification(body: string): boolean {
  return VERIFICATION_RE.test(visibleText(body));
}

/** True when a redirect target's path or query is a verification step: /check-your-email, /verify?token=... */
export function locationHintsVerification(url: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  return /verif|confirm|check[-_]?(?:your[-_]?)?(?:e-?mail|inbox)|activat|otp|two[-_]?factor|mfa|2fa|e-?mail[-_]?sent|pending/i.test(
    `${u.pathname}${u.search}`,
  );
}

/** True when a URL is where a site sends someone to sign in, which is not where a new account lands. */
export function isLoginShapedUrl(url: string): boolean {
  try {
    return LOGIN_SHAPED_RE.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

/**
 * The cookies a sequence of responses left behind, as a browser would keep them: a later value
 * replaces an earlier one, and an empty, expired or Max-Age<=0 cookie deletes it. A response that
 * "sets" session= with an epoch Expires is logging the visitor OUT, not in.
 */
export class CookieJar {
  private readonly cookies = new Map<string, string>();

  absorb(setCookies: string[]): void {
    for (const line of setCookies) {
      const [pair, ...attrs] = line.split(";").map((s) => s.trim());
      const eq = (pair ?? "").indexOf("=");
      if (!pair || eq <= 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const gone =
        value === "" ||
        attrs.some((a) => {
          const maxAge = /^max-age\s*=\s*(-?\d+)/i.exec(a);
          if (maxAge) return Number(maxAge[1]) <= 0;
          const expires = /^expires\s*=\s*(.+)$/i.exec(a);
          if (expires) {
            const t = Date.parse(expires[1]!);
            return !Number.isNaN(t) && t <= Date.now();
          }
          return false;
        });
      if (gone) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }

  /** The Cookie header value, or null when nothing is held. */
  header(): string | null {
    return this.cookies.size === 0 ? null : [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}
