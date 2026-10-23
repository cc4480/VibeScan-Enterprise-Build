/**
 * Automatic second account for cross-account access-control testing (BOLA/IDOR).
 *
 * accessControlProbe.ts needs two genuinely different identities to prove an
 * authorisation boundary exists between them, and until now the only way to
 * get a second one was the user pasting in credentials for an account they
 * created themselves. That makes the single most valuable active check in
 * this scanner opt-in-by-manual-effort, which most users never do.
 *
 * This module tries, once, to create a disposable throwaway account through
 * the target's own public self-serve signup form — the same thing a real
 * visitor could do — and hands back working credentials ONLY when that
 * succeeds cleanly and immediately. It is built to fail safe in every other
 * case, never to guess harder or retry:
 *
 *   - Only a small, fixed list of common signup PATHS is tried, never a
 *     crawl or a brute-force of arbitrary routes.
 *   - A form only counts as a signup form on evidence that belongs to the
 *     form itself (signupForm.ts). A login form is never one, however much
 *     "Sign up" wording sits elsewhere on its page.
 *   - Everything stays on the target. A form that posts to another host (a
 *     hosted auth provider) and a signup page the request was redirected to on
 *     another host are both left alone: creating an account at a third party
 *     is not testing the customer, and it is not what they authorised.
 *   - Email verification aborts the attempt. The response, every redirect
 *     hop after it and the URLs it redirected through are all read for it
 *     (signupOutcome.ts); the module never waits for, guesses at, or tries to
 *     complete an email flow.
 *   - Success requires a session, not a status. The cookies must survive the
 *     way a browser would keep them (an empty or expired one deletes), the
 *     response must not be a rejection, the landing page must not be a login
 *     page, and a request carrying the cookie must see something an anonymous
 *     visitor does not. Any cookie at all used to count, so a 419 that set
 *     laravel_session was returned as a "second account" that was nobody.
 *   - One attempt, one account. Once a signup POST has been sent, this returns
 *     after that one response, whatever it was: a POST that timed out on our
 *     side may still have created the account, and a second POST on the next
 *     path would create another one (six paths, six accounts).
 *   - The throwaway email is at example.com, the domain IANA reserves
 *     specifically so it never routes to a real mailbox.
 *
 * The result says when a POST was sent (`submitted`) and to whom (`email`),
 * because an account may exist on the target even when no session came back,
 * and the customer is owed the address to find it by.
 */
import { scanFetch, getScanHttpContext, ScanScope, type HttpResult, type ScanCredentials } from "./http";
import { contentSimilarity, isDenied } from "./accessControlProbe";
import { extractSignupForm, buildFormBody, disposableEmail, disposablePassword, type DetectedSignupForm } from "./signupForm";
import { CookieJar, isLoginShapedUrl, locationHintsVerification, requiresEmailVerification } from "./signupOutcome";

const SIGNUP_PATH_CANDIDATES = ["/signup", "/sign-up", "/register", "/join", "/auth/signup", "/auth/register"];

const TIMEOUT_MS = 8_000;
/** Whole-attempt allowance. Every request checks it first, so a slow target cannot stretch the scan. */
const TOTAL_BUDGET_MS = 45_000;
const MAX_HOPS = 3;
/** Above this, a page that carries the new cookie is "the same page" an anonymous visitor gets. */
const SAME_PAGE_THRESHOLD = 0.9;

const NO_FORM = "no self-serve signup form granting an immediate session was found";
const NEEDS_VERIFICATION = "the target's signup requires email verification, which cannot be completed automatically";

export interface AutoSecondAccountResult {
  secondary: ScanCredentials | null;
  /** Present only when `secondary` is null — why no account could be created. */
  skippedReason?: string;
  /**
   * True once a signup POST was sent. An account may then exist on the target even though no
   * session came back, so a caller must not describe the attempt as "nothing was created".
   */
  submitted?: boolean;
  /** The throwaway address used, when one was submitted: how the owner finds and deletes the account. */
  email?: string;
}

export interface AutoSecondAccountOptions {
  timeoutMs?: number;
  budgetMs?: number;
}

const sameHost = (a: string, b: string): boolean => {
  try { return new URL(a).hostname.toLowerCase() === new URL(b).hostname.toLowerCase(); } catch { return false; }
};

/**
 * Try, once, to obtain a working second account on the scan target. Never throws: every failure
 * path returns `{ secondary: null, skippedReason }`, and one that happens after a POST was sent
 * still says so.
 */
export async function attemptAutoSecondAccount(
  baseUrl: string,
  opts: AutoSecondAccountOptions = {},
): Promise<AutoSecondAccountResult> {
  const sent: { email?: string } = {};
  try {
    return await attempt(baseUrl, opts, sent);
  } catch (err) {
    console.error("[scan] auto second-account creation failed", err);
    return {
      secondary: null,
      skippedReason: sent.email
        ? "the signup was submitted once, then reading the result failed, so an account may exist on the target"
        : "attempting an automatic second account failed",
      ...(sent.email ? { submitted: true, email: sent.email } : {}),
    };
  }
}

async function attempt(baseUrl: string, opts: AutoSecondAccountOptions, sent: { email?: string }): Promise<AutoSecondAccountResult> {
  const timeoutMs = opts.timeoutMs ?? TIMEOUT_MS;
  const deadline = Date.now() + (opts.budgetMs ?? TOTAL_BUDGET_MS);
  const scope = getScanHttpContext()?.scope ?? (() => { try { return new ScanScope(baseUrl); } catch { return null; } })();
  const inScope = (url: string): boolean => sameHost(url, baseUrl) || (scope?.includes(url) ?? false);
  const budgetLeft = (): boolean => Date.now() < deadline;

  for (const path of SIGNUP_PATH_CANDIDATES) {
    if (!budgetLeft()) break;
    let pageUrl: string;
    try {
      pageUrl = new URL(path, baseUrl).toString();
    } catch {
      continue;
    }
    if (!inScope(pageUrl)) continue;

    // Anonymous on purpose (`as: null`): the scan's own signed-in session must never reach a signup page.
    // Redirects are walked by hand and never followed off the target: a hosted auth provider's
    // signup would be somebody else's form, and its action somebody else's endpoint.
    const page = await getWithinScope(pageUrl, { timeoutMs, inScope, budgetLeft });
    if (!page || page.status < 200 || page.status >= 300) continue;

    const form = extractSignupForm(page.body, page.finalUrl);
    if (!form || !inScope(form.action)) continue;

    // Exactly one submission, whatever comes back.
    return submitOnce(form, baseUrl, pageUrl, { timeoutMs, inScope, budgetLeft }, sent);
  }

  return { secondary: null, skippedReason: NO_FORM };
}

interface Ctx {
  timeoutMs: number;
  inScope: (url: string) => boolean;
  budgetLeft: () => boolean;
}

/** GET a page anonymously, following redirects only while they stay on the target. Null when one leaves it. */
async function getWithinScope(url: string, ctx: Ctx): Promise<HttpResult | null> {
  let current = url;
  for (let hop = 0; hop <= MAX_HOPS + 2; hop++) {
    if (!ctx.inScope(current) || !ctx.budgetLeft()) return null;
    const res = await scanFetch(current, { as: null, timeoutMs: ctx.timeoutMs, redirect: "manual" });
    if (!res) return null;
    const location = res.status >= 300 && res.status < 400 ? res.headers["location"] : undefined;
    if (!location) return { ...res, finalUrl: current };
    try {
      current = new URL(location, current).toString();
    } catch {
      return null;
    }
  }
  return null;
}

async function submitOnce(
  form: DetectedSignupForm,
  baseUrl: string,
  signupPageUrl: string,
  ctx: Ctx,
  sent: { email?: string },
): Promise<AutoSecondAccountResult> {
  const email = disposableEmail();
  const body = buildFormBody(form, email, disposablePassword());
  // Recorded BEFORE the request: a POST that times out here may still have been applied over there.
  sent.email = email;
  const made = { submitted: true as const, email };
  const failed = (why: string): AutoSecondAccountResult => ({ secondary: null, skippedReason: why, ...made });

  // `redirect: "manual"` deliberately: a signup handler commonly sets the session cookie on the
  // redirect response itself (302 to /dashboard), and scanFetch's normal auto-follow only surfaces
  // the FINAL hop's headers — it would silently lose exactly the cookie this needs. The hops are
  // walked below instead, by hand, so every one is scope-checked and every Set-Cookie is kept.
  const first = await scanFetch(form.action, {
    method: form.method,
    as: null,
    timeoutMs: ctx.timeoutMs,
    redirect: "manual",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!first) return failed("the signup form was submitted once but the request did not complete, so an account may or may not exist");

  const jar = new CookieJar();
  const trail = await follow(first, form.action, jar, ctx);

  // Verification first: the message can sit on a page the redirect led to, and a rejection that
  // names it is more useful said that way.
  if (trail.locations.some(locationHintsVerification) || trail.bodies.some(requiresEmailVerification)) {
    return failed(NEEDS_VERIFICATION);
  }
  if (first.status >= 400) {
    return failed(`the signup form was submitted once and the target rejected it (HTTP ${first.status})`);
  }
  const cookie = jar.header();
  if (!cookie) return failed("the signup form was submitted once but no session cookie came back");
  if (isLoginShapedUrl(trail.landing)) {
    return failed("the signup form was submitted once but the target sent the new account to its sign-in page rather than signing it in");
  }

  const landing = ctx.inScope(trail.landing) ? [trail.landing] : [];
  const candidates = [...new Set([...landing, new URL("/", baseUrl).toString(), signupPageUrl])].slice(0, 3);
  if (!(await sessionWorks(candidates, cookie, ctx))) {
    return failed(
      "the signup form was submitted once and a session cookie came back, but with it the target still looked the same as it does to an anonymous visitor, so it is not a signed-in session",
    );
  }
  return { secondary: { cookie }, ...made };
}

interface Trail {
  bodies: string[];
  /** Every redirect target seen, absolute. */
  locations: string[];
  /** Where the submission ended up: the last redirect target, or the form action when it did not redirect. */
  landing: string;
}

/** Walks the response's redirects by hand (in scope only), keeping every cookie and every body. */
async function follow(first: HttpResult, from: string, jar: CookieJar, ctx: Ctx): Promise<Trail> {
  const trail: Trail = { bodies: [first.body], locations: [], landing: from };
  let cur = first;
  let curUrl = from;
  jar.absorb(first.setCookies);
  for (let hop = 0; hop < MAX_HOPS && cur.status >= 300 && cur.status < 400; hop++) {
    const location = cur.headers["location"];
    if (!location) break;
    let next: string;
    try {
      next = new URL(location, curUrl).toString();
    } catch {
      break;
    }
    trail.locations.push(next);
    trail.landing = next;
    if (!ctx.inScope(next) || !ctx.budgetLeft()) break;
    const cookie = jar.header();
    const res = await scanFetch(next, {
      as: cookie ? { cookie } : null,
      timeoutMs: ctx.timeoutMs,
      redirect: "manual",
    });
    if (!res) break;
    jar.absorb(res.setCookies);
    trail.bodies.push(res.body);
    cur = res;
    curUrl = next;
  }
  return trail;
}

/**
 * Does carrying this cookie make the target treat us as somebody? Asks for a few pages both ways
 * and needs one where the cookie's answer is a real page, is not a sign-in wall, and differs from
 * the anonymous answer. A tracking cookie on a page that is identical for everyone fails this.
 */
async function sessionWorks(urls: string[], cookie: string, ctx: Ctx): Promise<boolean> {
  const signedOut = getScanHttpContext()?.detectSignedOut;
  for (const url of urls) {
    if (!ctx.inScope(url) || !ctx.budgetLeft()) continue;
    const [mine, anon] = await Promise.all([
      scanFetch(url, { as: { cookie }, timeoutMs: ctx.timeoutMs }),
      scanFetch(url, { as: null, timeoutMs: ctx.timeoutMs }),
    ]);
    if (!mine || !anon) continue;
    if (mine.status < 200 || mine.status >= 300 || isDenied(mine.status, mine.body)) continue;
    if (isLoginShapedUrl(mine.finalUrl) || signedOut?.(mine.body, mine.finalUrl, url)) continue;
    const differs =
      anon.status !== mine.status ||
      anon.finalUrl !== mine.finalUrl ||
      contentSimilarity(mine.body, anon.body) < SAME_PAGE_THRESHOLD;
    if (differs) return true;
  }
  return false;
}
