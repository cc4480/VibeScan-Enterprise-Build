/** Constants, patterns and predicates shared by the API probes. */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { type ScanCredentials } from "./http";
import { type ApiEndpoint } from "./apiSurface";

export const TIMEOUT_MS = 8_000;

export const MAX_ENDPOINTS_TESTED = 25;

export const MAX_PARAMS_PER_ENDPOINT = 4;

// Small enough not to be load against a customer, large enough that any real
// limiter would have engaged.
export const RATE_LIMIT_BURST = 12;

/**
 * Paths that are meant to answer an unlimited burst and must not be flagged
 * for it. A liveness probe is polled continuously by the platform itself —
 * Railway, Kubernetes, a load balancer — and rate-limiting it would make the
 * platform mark a healthy service as down. A provider-discovery or
 * well-known endpoint returns data that is public by definition (an OAuth
 * client ID is not a secret), so throttling it stops nothing an attacker
 * couldn't already get by loading the page once.
 *
 * Found the hard way: this probe flagged seclayer.app's own
 * /api/system/health and /api/auth/providers, while its actual
 * credential-issuing endpoint enforced a limit correctly (verified live:
 * 429 from the sixth request). The finding's own "credential stuffing"
 * language never applied to either endpoint it named.
 */
export const RATE_LIMIT_EXEMPT_PATTERN =
  /\/(healthz?|health[-_]?check|status|ready(iness)?|live(ness)?|ping|version|manifest\.json|\.well-known\/[^/]+|providers?|config(uration)?|robots\.txt|sitemap\.xml|favicon\.ico)(\/|$)/i;

/**
 * The only endpoints where "no throttling seen in a short burst" says anything worth a report:
 * ones an attacker would hammer (guessing passwords, codes or reset tokens). Almost any read API
 * tolerates twelve requests, so a burst against /api/orders proves nothing.
 */
export const RATE_LIMIT_SENSITIVE_PATTERN =
  /\/(log-?in|sign-?in|auth(enticate)?|password|passwd|forgot|reset|otp|2fa|mfa|verify|verification|token|pin|code|magic)(\/|[-_.]|$)/i;

/**
 * Collections that are public by design. The same data for a signed-in caller and an anonymous
 * one is what a product catalogue IS, so it is only worth reporting when the data itself is
 * personal (see PERSONAL_DATA_RE).
 */
export const PUBLIC_COLLECTION_PATTERN =
  /\/(products?|catalog(ue)?|categories|category|posts?|articles?|blogs?|news|pages?|plans?|pricing|faqs?|countries|currencies|languages|locations|stores|shops?|events|courses|recipes|listings|menu|features|tags|testimonials|reviews|changelog|releases|docs|jobs|careers)(\/|$)/i;

/** Values that mark a payload as somebody's data rather than catalogue content. */
export const PERSONAL_DATA_RE = /[\w.+-]+@[\w-]+\.[\w.-]+|\b\d{3}-\d{2}-\d{4}\b/;

/** Paths whose POST is a query rather than a write. */
export const READ_SHAPED = /\b(search|query|filter|lookup|find|list|report|graphql|validate|preview|check)\b/i;

/** A stand-in for a path parameter. Reading record 1 is a read. */
export const PATH_PARAM_VALUE = "1";

export function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

/** Substitute {placeholders} so the URL can actually be requested. */
export function concreteUrl(endpoint: ApiEndpoint): string {
  return endpoint.url.replace(/\{[^}]+\}/g, PATH_PARAM_VALUE);
}

/** Is a POST to this endpoint a question rather than a change? */
export function isReadShaped(endpoint: ApiEndpoint): boolean {
  if (endpoint.method === "GET" || endpoint.method === "HEAD") return true;
  if (endpoint.method !== "POST") return false;
  try {
    return READ_SHAPED.test(new URL(endpoint.url).pathname);
  } catch {
    return false;
  }
}

const NOT_FOUND_TEXT =
  /\b(not found|no such (route|endpoint|resource|page)|unknown (route|endpoint)|route .{0,80} not found|cannot (get|post|patch|put|delete))\b/i;

/** A full HTML document, as opposed to an API answer. */
export function isHtmlDocument(body: string): boolean {
  return /^\s*<(!doctype\s+html|html[\s>])/i.test(body.slice(0, 1_000));
}

/**
 * A "not found" answer sent with a success status: the signature of a host that answers 200 for
 * paths it never routed. `{"error":"not found","path":"/x","status":404}`, a "Page not found"
 * document, or a bare "404". Such a body is a router's refusal, not data and not a handler.
 */
export function isNotFoundBody(body: string): boolean {
  const head = body.slice(0, 2_000);
  try {
    const j: unknown = JSON.parse(body);
    if (j && typeof j === "object" && !Array.isArray(j)) {
      const o = j as Record<string, unknown>;
      const code = o["status"] ?? o["statusCode"] ?? o["code"];
      if (code === 404 || code === "404" || code === 410) return true;
      const msg = o["error"] ?? o["message"];
      if (typeof msg === "string" && NOT_FOUND_TEXT.test(msg) && Object.keys(o).length <= 6) return true;
      return false;
    }
    if (Array.isArray(j)) return false;
  } catch { /* not JSON */ }
  if (isHtmlDocument(head)) {
    return /<title[^>]*>[^<]*(not found|404)[^<]*<\/title>/i.test(head) || /<h1[^>]*>\s*(page )?not found/i.test(head);
  }
  return /^\s*(404\b|not found\b|cannot (get|post|patch|put|delete) )/i.test(head);
}

/** Does this response carry data, as opposed to a refusal or an empty shell? */
export function looksLikeData(status: number, body: string): boolean {
  if (status < 200 || status >= 300) return false;
  const trimmed = body.trim();
  if (trimmed.length < 20) return false;
  if (isNotFoundBody(trimmed)) return false;
  // An empty collection is a successful answer, not an exposure.
  if (/^\[\s*\]$/.test(trimmed)) return false;
  if (/^\{\s*("?(data|items|results|rows)"?\s*:\s*\[\s*\]\s*)\}$/.test(trimmed)) return false;
  return true;
}

/**
 * A refusal, whatever status code it arrives with. A redirect to a sign-in page (which the client
 * followed, so the status is the login page's 200) and an HTML sign-in page are refusals too.
 */
export function isRefusal(status: number, body: string, res?: { redirected: boolean; finalUrl: string }): boolean {
  if (status === 401 || status === 403) return true;
  if (res?.redirected) {
    try {
      if (/\/(log-?in|sign-?in|sign_in|auth|sso|session|account\/login)(\/|$|\?)/i.test(new URL(res.finalUrl).pathname)) return true;
    } catch { /* an unparseable final URL says nothing */ }
  }
  const head = body.slice(0, 2_000);
  if (/^\s*<(!doctype|html)/i.test(head) && (/<input[^>]+type=["']password["']/i.test(head) || /\b(sign in|log in|login)\b/i.test(head))) {
    return true;
  }
  return /\b(unauthori[sz]ed|forbidden|access denied|not authenticated|not logged in|authentication required|login required|please (log|sign) ?in|(log|sign) ?in to continue|permission denied|invalid token|missing token)\b/i.test(
    head,
  );
}

/** Same JSON shape (field names), or byte-identical: "the anonymous caller got what the signed-in one did". */
export function sameShape(a: string, b: string): boolean {
  if (a === b) return true;
  const fa = jsonFieldNames(a).sort().join(",");
  return fa !== "" && fa === jsonFieldNames(b).sort().join(",");
}

/**
 * An identifier chosen so that nothing can possibly exist at it.
 *
 * This is what makes write-verb authorisation testable without risk. DELETE on
 * a record that does not exist destroys nothing, but the status code still says
 * whether authorisation ran: a refusal means the check happens before the
 * lookup, while a 404 means an unauthenticated caller reached the database.
 *
 * PUT is deliberately never sent — many APIs treat it as an upsert, so a PUT to
 * a nonexistent id creates the record instead of missing it.
 */
export const IMPLAUSIBLE_ID = "999999997";

/** Response fields that should not be leaving the server at all. */
// Two entries deliberately excluded: bare "hash" and bare "token" are common
// as public, non-sensitive field names — a content hash for cache-busting or
// dedup, a share/invite token already exposed in a URL. The prefixed forms
// (password_hash, access_token, session_token, …) still catch the case that
// actually matters, without a bare word firing on every API that returns a
// pagination cursor called "token".
export const SENSITIVE_FIELD_RE =
  /^(password|passwd|pwd|password_?hash|salt|secret|api_?key|apikey|private_?key|access_?token|refresh_?token|session_?token|ssn|social_?security|card_?number|cardnumber|cvv|cvc|iban|routing_?number|tax_?id)$/i;

/** Fields that let a caller grant themselves something by including them. */
export const PRIVILEGE_FIELD_RE =
  /^(role|roles|is_?admin|admin|is_?staff|permissions?|scopes?|plan|tier|credits?|balance|verified|is_?verified|email_?verified|owner_?id|user_?id|account_?id)$/i;

/**
 * Did an unauthenticated write to a nonexistent id reach a handler that processed it? A refusal
 * (401/403), "not found" (404, 410), "method not allowed" (405/501) and a router's default
 * "Cannot DELETE /path" are all inconclusive or fine.
 */
export function isHandlerReached(status: number, body: string): boolean {
  if (/\bCannot (DELETE|PATCH|PUT|POST|GET)\b/i.test(body.slice(0, 500))) return false;
  if (status >= 200 && status < 300) {
    // A catch-all host answers an unrouted verb with 200 and its shell or a "not found" body.
    // Neither is a handler accepting the write.
    return !isNotFoundBody(body) && !isHtmlDocument(body);
  }
  if (status === 400 || status === 422) {
    // A malformed-JSON 400 comes from the body parser, before any handler.
    return /\b(validation|required|must be|is invalid|invalid (field|value|input|body|payload)|missing (field|param))/i.test(body.slice(0, 1_000)) &&
      !/\b(unexpected token|malformed|JSON)\b/i.test(body.slice(0, 300));
  }
  return false;
}

export interface ApiProbeInput {
  endpoints: ApiEndpoint[];
  /** The scan's session. Without one, missing-auth cannot be distinguished. */
  credentials?: ScanCredentials;
  /** A second account, enabling API-level IDOR comparison. */
  secondary?: ScanCredentials;
}

/** Collect every field name in a JSON document, however deeply nested. */
export function jsonFieldNames(body: string, limit = 400): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return [];
  }

  const names = new Set<string>();
  const walk = (node: unknown, depth: number) => {
    if (names.size >= limit || depth > 6 || !node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      // One element is enough: collection members share a shape.
      if (node.length > 0) walk(node[0], depth + 1);
      return;
    }
    for (const [key, value] of Object.entries(node)) {
      names.add(key);
      walk(value, depth + 1);
    }
  };
  walk(parsed, 0);
  return [...names];
}

/**
 * Sensitive fields present in a response body.
 *
 * A read, so entirely safe to perform, and it catches the case where an API
 * returns the whole database row and lets the front end pick fields — the
 * password hash is still on the wire, and still in the browser's memory.
 */
export function exposedSensitiveFields(body: string): string[] {
  return jsonFieldNames(body).filter((n) => SENSITIVE_FIELD_RE.test(n));
}

/** Privilege-bearing fields a write endpoint declares it will accept. */
export function privilegeFieldsAccepted(endpoint: ApiEndpoint): string[] {
  return endpoint.params
    .filter((p) => p.location === "body" && PRIVILEGE_FIELD_RE.test(p.name))
    .map((p) => p.name);
}
