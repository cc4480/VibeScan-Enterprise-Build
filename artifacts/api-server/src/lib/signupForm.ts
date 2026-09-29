/**
 * Finding, and filling in, a self-serve signup form. Pure: no requests are made here.
 *
 * Split out of autoSecondAccount.ts, which decides whether to submit anything at all. The one
 * question this file answers is the dangerous one: is this <form> really a signup form?
 * Answering "yes" for a login form sends throwaway credentials to the target's login endpoint,
 * which is a failed sign-in attempt against a real customer's system. So the test is about the
 * FORM, not the page around it:
 *
 *   - "Don't have an account? Sign up", a "Login / Register" nav, a footer's "Join our
 *     newsletter" and even navigator.serviceWorker.register() all appear on ordinary login
 *     pages. Matching signup wording anywhere on the page (the first version) accepted every
 *     one of them, and the first email+password form on the page won.
 *   - A form is a signup form only on positive evidence that belongs to it: it posts to a
 *     signup-shaped URL, it asks for the password twice, or its own text (button, legend,
 *     labels) names it a signup without also naming it a login.
 *   - A form that posts to a login-shaped URL is never a signup form, and neither is one on a
 *     page the request was redirected to a login URL for, unless the form itself posts to a
 *     signup URL.
 */
import { randomBytes } from "node:crypto";

export interface ParsedInput {
  name: string;
  type: string;
  value: string;
  required: boolean;
}

export interface DetectedSignupForm {
  action: string;
  method: string;
  fields: ParsedInput[];
  emailField: string;
  passwordFields: string[];
}

/** Wording that names a form as one that creates an account. Tested on the form's own text. */
const SIGNUP_COPY_RE =
  /\b(?:sign[\s-]?up|create (?:a |an |your |my )?(?:free )?account|register|registration|join (?:free|now|us|today)|get started|start (?:your )?(?:free )?(?:trial|account))\b/i;
const LOGIN_COPY_RE = /\b(?:log[\s-]?in|sign[\s-]?in)\b/i;

/** Paths that read as creating an account, and paths that read as signing in to one. */
const SIGNUP_SHAPED_RE = /sign[-_]?up|regist|(?:^|\/)join(?:\/|\.|$)|create[-_]?(?:an?[-_])?(?:account|user)|new[-_]?(?:account|user)/i;
export const LOGIN_SHAPED_RE = /(?:^|\/)(?:log[-_]?in|sign[-_]?in|sessions?|authenticate)(?:\/|\.|$)/i;

/** A page's visible text: markup, scripts, styles and comments removed, common entities decoded. */
export function visibleText(html: string): string {
  return html
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<(script|style|noscript|template)\b[\s\S]*?<\/\1\s*>/gi, " ")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;|&#160;|&#xa0;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * The value of an attribute, quoted or not. `data-name="x"` is not `name`: the character before
 * the name must not be a word character or a hyphen, or a data-* look-alike wins.
 */
function getAttr(attrs: string, name: string): string | null {
  const m = new RegExp(`(?<![\\w-])${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'>]+))`, "i").exec(attrs);
  return m ? (m[1] ?? m[2] ?? m[3] ?? "") : null;
}

const hasFlag = (attrs: string, name: string): boolean => new RegExp(`(?<![\\w-])${name}(?![\\w-])`, "i").test(attrs);

function parseInputs(formInner: string): ParsedInput[] {
  const inputs: ParsedInput[] = [];
  const inputRe = /<input\b([^>]*)>/gi;
  let m: RegExpExecArray | null;
  while ((m = inputRe.exec(formInner)) !== null) {
    const attrs = m[1]!.replace(/\/\s*$/, "");
    const name = getAttr(attrs, "name");
    if (!name) continue;
    inputs.push({
      name,
      type: (getAttr(attrs, "type") ?? "text").toLowerCase(),
      value: getAttr(attrs, "value") ?? "",
      required: hasFlag(attrs, "required"),
    });
  }
  return inputs;
}

/** What the form says about itself: its text plus the labels on submit/button inputs. */
function formText(inner: string): string {
  const labels: string[] = [];
  const re = /<input\b([^>]*)>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(inner)) !== null) {
    const type = (getAttr(m[1]!, "type") ?? "").toLowerCase();
    if (type === "submit" || type === "button") labels.push(getAttr(m[1]!, "value") ?? "");
  }
  return `${visibleText(inner)} ${labels.join(" ")}`;
}

/** Resolves a form action; null when it is malformed or not http(s), instead of throwing. */
function resolveAction(actionAttr: string | null, pageUrl: string): string | null {
  try {
    const u = new URL(actionAttr ?? "", pageUrl);
    return u.protocol === "http:" || u.protocol === "https:" ? u.toString() : null;
  } catch {
    return null;
  }
}

const pathOf = (url: string): string => {
  try { return new URL(url).pathname; } catch { return ""; }
};

/**
 * The signup form on a page, or null. Never throws.
 *
 * Every form is scored on evidence that belongs to it and the strongest wins, so a login form
 * that comes first no longer beats the register form below it. `pageUrl` is the FINAL url after
 * redirects: a /signup that bounces to /login is a login page.
 */
export function extractSignupForm(html: string, pageUrl: string): DetectedSignupForm | null {
  const pageLoginShaped = LOGIN_SHAPED_RE.test(pathOf(pageUrl));
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let best: { form: DetectedSignupForm; score: number } | null = null;
  let m: RegExpExecArray | null;

  while ((m = formRe.exec(html)) !== null) {
    const attrs = m[1]!;
    const inner = m[2]!;
    const inputs = parseInputs(inner);
    const emailInput = inputs.find((i) => i.type === "email" || /e-?mail/i.test(i.name));
    const passwordInputs = inputs.filter((i) => i.type === "password");
    if (!emailInput || passwordInputs.length === 0) continue;

    const action = resolveAction(getAttr(attrs, "action"), pageUrl);
    if (!action) continue;
    const actionPath = pathOf(action);

    const signupAction = SIGNUP_SHAPED_RE.test(actionPath);
    const loginAction = LOGIN_SHAPED_RE.test(actionPath);
    const text = formText(inner);
    const signupCopy = SIGNUP_COPY_RE.test(text);
    const loginCopy = LOGIN_COPY_RE.test(text);
    const confirmsPassword = passwordInputs.length >= 2;

    // A form that names itself a login, or posts where logins go, is not one to create accounts with.
    if (loginAction && !signupAction) continue;
    if (pageLoginShaped && !signupAction) continue;
    // Positive evidence that belongs to the form: a signup URL, a repeated password, or its own
    // wording — and wording only counts when it does not also say "log in".
    if (!(signupAction || confirmsPassword || (signupCopy && !loginCopy))) continue;

    const score = (signupAction ? 3 : 0) + (confirmsPassword ? 3 : 0) + (signupCopy ? 2 : 0) + (loginCopy ? -1 : 0);
    if (best && best.score >= score) continue;

    const method = (getAttr(attrs, "method") ?? "POST").toUpperCase();
    best = {
      score,
      form: {
        action,
        // A signup over GET would put the password in the URL, and in every log between here and there.
        method: method === "GET" ? "POST" : method,
        fields: inputs,
        emailField: emailInput.name,
        passwordFields: passwordInputs.map((p) => p.name),
      },
    };
  }
  return best?.form ?? null;
}

export function disposableEmail(): string {
  // example.com is reserved by IANA specifically so it never resolves to a
  // real mailbox (RFC 2606) — this can never deliver mail to a real person.
  return `secscan-test-${randomBytes(6).toString("hex")}@example.com`;
}

export function disposablePassword(): string {
  // Meets typical length/complexity rules (upper, lower, digit, symbol) without
  // needing per-target tuning.
  return `Xk9${randomBytes(9).toString("hex")}!Q`;
}

/** A plausible value for an obviously-named text field, so a required "username" does not sink the signup. */
function textValueFor(name: string, tag: string): string | null {
  const n = name.toLowerCase();
  if (/(^|[^a-z])(user(name)?|login|handle|nick(name)?)$/.test(n)) return `secscan-${tag}`;
  if (/first|given|fname/.test(n)) return "SecScan";
  if (/last|sur(name)?|family|lname/.test(n)) return "Test";
  if (/(^|[^a-z])name$|full[-_]?name|display/.test(n)) return "SecScan Test";
  return null;
}

/** Boxes worth ticking: terms and consent gates. Marketing opt-ins and unknown boxes (a honeypot) are left alone. */
const CONSENT_BOX_RE = /term|tos|agree|accept|consent|privacy|policy|age|adult|18/i;

export function buildFormBody(form: DetectedSignupForm, email: string, password: string): URLSearchParams {
  const body = new URLSearchParams();
  const tag = randomBytes(4).toString("hex");
  for (const field of form.fields) {
    if (field.name === form.emailField) {
      body.set(field.name, email);
    } else if (form.passwordFields.includes(field.name)) {
      body.set(field.name, password);
    } else if (field.type === "checkbox") {
      if (field.required || CONSENT_BOX_RE.test(field.name)) body.set(field.name, field.value || "on");
    } else if (field.type === "radio") {
      // Never guessed: which option is right is the form's business.
    } else if (field.type === "hidden" || field.type === "submit" || field.type === "button") {
      // Preserves hidden fields verbatim — CSRF tokens, plan selectors, etc.
      body.set(field.name, field.value);
    } else {
      body.set(field.name, field.value || textValueFor(field.name, tag) || "");
    }
  }
  return body;
}
