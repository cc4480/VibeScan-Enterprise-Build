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
 *   - Only a small, fixed list of common signup PATHS is tried (the same
 *     discipline the live-path signature probes elsewhere use), never a
 *     crawl or a brute-force of arbitrary routes.
 *   - A page only counts as a signup form if it names itself one (the URL is
 *     signup-shaped AND the page's own copy says "sign up" / "create account"
 *     / "register" / "join" somewhere) — a login form that happens to have an
 *     email and a password field is not mistaken for one.
 *   - If the response after submitting so much as HINTS at email
 *     verification ("check your email", "confirm your email", "verify",
 *     an activation link), this aborts immediately and reports no secondary
 *     account. It never waits for, guesses at, or tries to complete an email
 *     flow — there is no inbox to check.
 *   - Success requires an actual session to come back (a cookie), not just a
 *     2xx status. A form that "succeeds" with no session proves nothing.
 *   - The throwaway email is at example.com, the domain IANA reserves
 *     specifically so it never routes to a real mailbox — this cannot
 *     generate email to anyone, ever, even if a target's mail step is
 *     misconfigured to fire before verification.
 *   - One attempt, one account. If it doesn't work cleanly, the scan falls
 *     back to exactly what already happens today: BOLA is skipped with a
 *     clear reason, and the user can supply a second account manually.
 */
import { randomBytes } from "node:crypto";
import { scanFetch, type ScanCredentials } from "./http";

const SIGNUP_PATH_CANDIDATES = [
  "/signup",
  "/sign-up",
  "/register",
  "/join",
  "/auth/signup",
  "/auth/register",
];

const TIMEOUT_MS = 8_000;

const SIGNUP_COPY_RE = /\b(sign up|create (a |an |your )?account|register|join (free|now|us)?)\b/i;
const VERIFICATION_REQUIRED_RE =
  /\b(check your email|confirm your email|verify your email|verification link|activation link|almost there.*email|email.*sent)\b/i;

interface ParsedInput {
  name: string;
  type: string;
  value: string;
}

interface DetectedSignupForm {
  action: string;
  method: string;
  fields: ParsedInput[];
  emailField: string;
  passwordFields: string[];
}

function getAttr(attrs: string, name: string): string | null {
  const m = new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, "i").exec(attrs);
  return m ? m[1]! : null;
}

function parseInputs(formInner: string): ParsedInput[] {
  const inputs: ParsedInput[] = [];
  const inputRe = /<input\b([^>]*)>/gi;
  let m: RegExpExecArray | null;
  while ((m = inputRe.exec(formInner)) !== null) {
    const attrs = m[1]!;
    const name = getAttr(attrs, "name");
    if (!name) continue;
    inputs.push({
      name,
      type: (getAttr(attrs, "type") ?? "text").toLowerCase(),
      value: getAttr(attrs, "value") ?? "",
    });
  }
  return inputs;
}

/**
 * A signup form only counts when the URL was reached by trying a
 * signup-shaped path AND the page's own copy uses signup language — a page
 * with an email+password field alone (a login form) is not enough.
 */
export function extractSignupForm(html: string, pageUrl: string): DetectedSignupForm | null {
  if (!SIGNUP_COPY_RE.test(html)) return null;

  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let m: RegExpExecArray | null;
  while ((m = formRe.exec(html)) !== null) {
    const attrs = m[1]!;
    const inner = m[2]!;
    const inputs = parseInputs(inner);
    const emailInput = inputs.find((i) => i.type === "email" || /email/i.test(i.name));
    const passwordInputs = inputs.filter((i) => i.type === "password");
    if (!emailInput || passwordInputs.length === 0) continue;

    const actionAttr = getAttr(attrs, "action");
    const action = actionAttr ? new URL(actionAttr, pageUrl).toString() : pageUrl;
    const method = (getAttr(attrs, "method") ?? "POST").toUpperCase();

    return {
      action,
      method: method === "GET" ? "POST" : method,
      fields: inputs,
      emailField: emailInput.name,
      passwordFields: passwordInputs.map((p) => p.name),
    };
  }
  return null;
}

function disposableEmail(): string {
  // example.com is reserved by IANA specifically so it never resolves to a
  // real mailbox (RFC 2606) — this can never deliver mail to a real person.
  return `secscan-test-${randomBytes(6).toString("hex")}@example.com`;
}

function disposablePassword(): string {
  // Meets typical length/complexity rules (upper, lower, digit, symbol) without
  // needing per-target tuning.
  return `Xk9${randomBytes(9).toString("hex")}!Q`;
}

function buildFormBody(form: DetectedSignupForm, email: string, password: string): URLSearchParams {
  const body = new URLSearchParams();
  for (const field of form.fields) {
    if (field.name === form.emailField) {
      body.set(field.name, email);
    } else if (form.passwordFields.includes(field.name)) {
      body.set(field.name, password);
    } else if (field.type !== "checkbox" && field.type !== "radio") {
      // Preserves hidden fields verbatim — CSRF tokens, plan selectors, etc.
      body.set(field.name, field.value);
    } else if (field.type === "checkbox") {
      // Ticks every checkbox present (terms-of-service, marketing opt-in) so a
      // required "I agree" box doesn't silently block the submission.
      body.set(field.name, field.value || "on");
    }
  }
  return body;
}

export interface AutoSecondAccountResult {
  secondary: ScanCredentials | null;
  /** Present only when `secondary` is null — why no account could be created. */
  skippedReason?: string;
}

/**
 * Try, once, to obtain a working second account on the scan target. Never
 * throws: every failure path returns `{ secondary: null, skippedReason }`.
 */
export async function attemptAutoSecondAccount(baseUrl: string): Promise<AutoSecondAccountResult> {
  for (const path of SIGNUP_PATH_CANDIDATES) {
    let pageUrl: string;
    try {
      pageUrl = new URL(path, baseUrl).toString();
    } catch {
      continue;
    }

    const page = await scanFetch(pageUrl, { as: null, timeoutMs: TIMEOUT_MS });
    if (!page || page.status < 200 || page.status >= 300) continue;

    const form = extractSignupForm(page.body, page.finalUrl);
    if (!form) continue;

    const email = disposableEmail();
    const password = disposablePassword();
    const body = buildFormBody(form, email, password);

    // `redirect: "manual"` deliberately: a signup handler commonly sets the
    // session cookie on the redirect response itself (302 to /dashboard),
    // and scanFetch's normal auto-follow only surfaces the FINAL hop's
    // headers — it would silently lose exactly the cookie this needs. Reading
    // the immediate response directly, whatever its status, avoids that.
    const submitRes = await scanFetch(form.action, {
      method: form.method,
      as: null,
      timeoutMs: TIMEOUT_MS,
      redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!submitRes) continue;

    if (VERIFICATION_REQUIRED_RE.test(submitRes.body)) {
      return {
        secondary: null,
        skippedReason: "the target's signup requires email verification, which cannot be completed automatically",
      };
    }

    if (submitRes.setCookies.length > 0) {
      const cookie = submitRes.setCookies.map((c) => c.split(";")[0]).join("; ");
      return { secondary: { cookie } };
    }
    // This path didn't yield a usable form/session — try the next candidate.
  }

  return {
    secondary: null,
    skippedReason: "no self-serve signup form granting an immediate session was found",
  };
}
