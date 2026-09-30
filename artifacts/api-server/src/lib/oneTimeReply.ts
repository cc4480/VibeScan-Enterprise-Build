/**
 * Reading the reply of a "use this once" endpoint (raceConditionProbe.ts).
 *
 * The first version called a reply a success when it was any 2xx whose first 2,000 characters did
 * not match a short phrase list, and raised a HIGH finding at confidence 90 when two of five were.
 * The list missed most ways an application says no with a 200:
 *
 *   {"success":false,"error":"Coupon code is required"}   {"error":"Invalid promo code"}
 *   {"message":"Coupon has already been redeemed"}         {"valid":false}
 *   Code not found                                         {"alreadyClaimed":true}
 *
 * ("already been redeemed" is not "already redeemed".) Each was counted a success, so an endpoint
 * that reports errors in a 200 body produced a race-condition finding whose text said "a discount
 * applied repeatedly".
 *
 * A reply is one of three things, and the difference matters to the caller:
 *   accepted     the request was taken: nothing in it says otherwise
 *   rejected     the application said no, cleanly: a 4xx, or a 2xx whose body is a refusal
 *   inconclusive says nothing about one-time enforcement: no reply, a redirect, a rate limit (429),
 *                an outage (5xx), or an HTML page (a sign-in wall, an SPA shell)
 */
import type { HttpResult } from "./http";

export type ReplyKind = "accepted" | "rejected" | "inconclusive";

/** Phrases that mean "no" in a message or a plain-text body. Phrases, never bare common words. */
const REFUSAL_RE =
  /\b(?:already (?:been )?(?:used|redeemed|claimed|applied|taken)|has been (?:used|redeemed|claimed)|invalid|expired|no longer (?:valid|available)|not (?:found|eligible|valid|allowed|available|applicable)|one[- ]time use|limit (?:reached|exceeded)|too many|denied|forbidden|unauthori[sz]ed|sign[ -]?in|log[ -]?in|required|missing|cannot|can't|unable to|failed|failure|error)\b/i;

const ERROR_KEYS = new Set(["error", "errors", "err", "exception"]);
/** A value of false under any of these means the action did not happen. */
const MUST_BE_TRUE = new Set(["success", "ok", "valid", "applied", "redeemed", "claimed", "granted", "accepted", "eligible", "succeeded"]);
/** A value of true under any of these means it was refused. */
const MUST_BE_FALSE = new Set(["alreadyclaimed", "alreadyredeemed", "alreadyused", "alreadyapplied", "used", "expired", "invalid", "duplicate", "denied"]);
const STATE_KEYS = new Set(["status", "result", "state", "outcome"]);
const MESSAGE_KEYS = new Set(["message", "msg", "reason", "detail", "description", "title"]);
const REFUSAL_STATES = /^(?:error|fail|failed|failure|invalid|rejected|denied|declined|expired|used|duplicate|forbidden|conflict)$/i;

const nonEmpty = (v: unknown): boolean =>
  v === true || (typeof v === "string" && v.trim() !== "") || (Array.isArray(v) && v.length > 0) || (!!v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length > 0);

/** Does a parsed JSON reply say the action was refused? */
function jsonRefusal(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  for (const [rawKey, v] of Object.entries(value as Record<string, unknown>)) {
    const key = rawKey.toLowerCase().replace(/[-_]/g, "");
    if (ERROR_KEYS.has(key) && nonEmpty(v)) return true;
    if (MUST_BE_TRUE.has(key) && v === false) return true;
    if (MUST_BE_FALSE.has(key) && v === true) return true;
    if (STATE_KEYS.has(key) && typeof v === "string" && REFUSAL_STATES.test(v.trim())) return true;
    if (key === "status" && typeof v === "number" && v >= 400 && v < 600) return true;
    if (MESSAGE_KEYS.has(key) && typeof v === "string" && REFUSAL_RE.test(v)) return true;
  }
  return false;
}

const isHtml = (res: HttpResult): boolean =>
  (res.headers["content-type"] ?? "").toLowerCase().includes("text/html") || /^\s*<(?:!doctype html|html)\b/i.test(res.body);

export function classifyReply(res: HttpResult | null): ReplyKind {
  if (!res) return "inconclusive";
  const { status } = res;
  // A body cut off by the deadline or a reset is a fragment: it cannot be read as "the action was taken".
  if (res.truncated) return "inconclusive";
  if (status === 408 || status === 429 || status >= 500) return "inconclusive";
  if (status >= 400) return "rejected";
  if (status >= 300 || status < 200) return "inconclusive";
  if (isHtml(res)) return "inconclusive";

  const body = res.body.trim();
  if (body === "") return "accepted"; // a 204 carries no failure signal; the control request decides
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    if (REFUSAL_RE.test(body.slice(0, 2_000))) return "rejected";
    // Something that opens like JSON but does not parse is a cut-off document, not a success.
    return /^[{[]/.test(body) ? "inconclusive" : "accepted";
  }
  return jsonRefusal(parsed) ? "rejected" : "accepted";
}

/** Wording that says THIS action was already taken, as opposed to any refusal at all. */
const SPENT_RE =
  /\b(?:already (?:been )?(?:used|redeemed|claimed|applied|taken|consumed|activated)|(?:has|have) been (?:used|redeemed|claimed|consumed)|previously (?:used|redeemed|claimed)|(?:coupon|code|promo(?:tion)?|voucher|reward|offer|bonus|gift)\b[^.]{0,30}\bno longer (?:valid|available)|fully (?:redeemed|used)|only (?:be )?(?:used|redeemed|claimed) once|one[- ]time use|maximum (?:number of )?(?:uses|redemptions)|redemption limit)\b/i;
const SPENT_KEYS = new Set(["alreadyclaimed", "alreadyredeemed", "alreadyused", "alreadyapplied"]);

function spentJson(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.entries(value as Record<string, unknown>).some(([k, v]) => {
    if (SPENT_KEYS.has(k.toLowerCase().replace(/[-_]/g, "")) && v === true) return true;
    return typeof v === "string" && SPENT_RE.test(v);
  });
}

/**
 * Does this reply say the action was ALREADY USED? The only refusal that proves a one-time rule
 * exists. A generic 403, a 429, a rate limiter's or WAF's JSON error, "invalid code" or "login
 * required" is a refusal for some other reason and says nothing about whether the action was spent,
 * so a race finding may not lean on it.
 */
export function isSpentReply(res: HttpResult | null): boolean {
  if (!res || res.truncated || isHtml(res)) return false;
  if (res.status === 408 || res.status === 429 || res.status >= 500 || (res.status >= 300 && res.status < 400)) return false;
  if (classifyReply(res) !== "rejected") return false;
  const body = res.body.trim();
  try {
    return spentJson(JSON.parse(body));
  } catch {
    return SPENT_RE.test(body.slice(0, 2_000));
  }
}
