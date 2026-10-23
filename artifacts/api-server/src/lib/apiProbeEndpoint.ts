import { concreteUrl, TIMEOUT_MS, looksLikeData, isRefusal, sameShape, PUBLIC_COLLECTION_PATTERN, PERSONAL_DATA_RE, exposedSensitiveFields, RATE_LIMIT_SENSITIVE_PATTERN, RATE_LIMIT_EXEMPT_PATTERN, RATE_LIMIT_BURST, IMPLAUSIBLE_ID, isHandlerReached, isNotFoundBody, isHtmlDocument, MAX_PARAMS_PER_ENDPOINT } from "./apiProbeHelpers";
import { requestWith } from "./apiProbeSurface";
import type { ApiEndpoint } from "./apiSurface";
import type { ApiProbeInput } from "./apiProbeHelpers";
import type { ScanCredentials } from "./http";
import { randomBytes } from "node:crypto";
import { scanFetch } from "./http";
import { isDestructiveUrl } from "./destructive";
import { SQL_ERROR_SIGNATURES } from "./injectionProbe";

/** What the per-endpoint tests collect; apiProbeFindings.ts turns it into findings. */
export interface ApiProbeHits {
  unauthenticated: string[];
  injectable: Array<{ endpoint: string; param: string; where: string }>;
  overExposed: Array<{ endpoint: string; fields: string[] }>;
  unratelimited: string[];
  crossAccount: string[];
  massAssignable: Array<{ endpoint: string; fields: string[] }>;
  unauthorizedWrites: string[];
}

/** Runs every per-endpoint test (auth, data exposure, IDOR, rate limit, BFLA, mass assignment, injection) against one endpoint. */
export async function testEndpoint(
  endpoint: ApiEndpoint,
  input: ApiProbeInput,
  secondary: ScanCredentials | undefined,
  hits: ApiProbeHits,
): Promise<void> {
  const { unauthenticated, injectable, overExposed, unratelimited, crossAccount, unauthorizedWrites } = hits;
  const url = concreteUrl(endpoint);
  let anonymousBody: string | null = null;

  // ── 1. Missing authentication ───────────────────────────────────────────
  // Only meaningful with a session to contrast against: without one there is
  // no way to tell a public endpoint from an unprotected one.
  if (input.credentials && (endpoint.method === "GET" || endpoint.method === "HEAD")) {
    const [authed, anon] = await Promise.all([
      scanFetch(url, { as: input.credentials, timeoutMs: TIMEOUT_MS }),
      scanFetch(url, { as: null, timeoutMs: TIMEOUT_MS }),
    ]);

    if (
      authed &&
      anon &&
      looksLikeData(authed.status, authed.body) &&
      looksLikeData(anon.status, anon.body) &&
      // An HTML document answering an API path is the host's app shell, not the API.
      !isHtmlDocument(anon.body) &&
      !isRefusal(anon.status, anon.body, anon) &&
      sameShape(authed.body, anon.body)
    ) {
      anonymousBody = anon.body;
      // A catalogue answers everyone the same; that is not an exposure unless the payload is
      // personal. Anything else, matching the signed-in answer, is what this finding reports.
      const publicByDesign =
        PUBLIC_COLLECTION_PATTERN.test(new URL(url).pathname) &&
        !PERSONAL_DATA_RE.test(anon.body) &&
        exposedSensitiveFields(anon.body).length === 0;
      if (!publicByDesign) unauthenticated.push(`${endpoint.method} ${new URL(url).pathname}`);
    }
  }

  // ── 1b. Excessive data exposure ─────────────────────────────────────────
  // Pure read. Catches an API that returns the whole database row and lets
  // the front end choose what to display — the password hash still crossed
  // the wire and still sits in the browser's memory.
  if (endpoint.method === "GET" || endpoint.method === "HEAD") {
    const res = await scanFetch(url, {
      ...(input.credentials ? { as: input.credentials } : {}),
      timeoutMs: TIMEOUT_MS,
    });
    if (res && looksLikeData(res.status, res.body) && !isRefusal(res.status, res.body)) {
      const fields = exposedSensitiveFields(res.body);
      if (fields.length > 0) {
        overExposed.push({ endpoint: `${endpoint.method} ${new URL(url).pathname}`, fields });
      }

      // ── 1c. API-level IDOR ────────────────────────────────────────────
      // The phase-04 comparison applied per endpoint: if a second account is
      // served byte-comparable data from a URL naming a record, one of them
      // is reading data that is not theirs.
      // Skipped when an anonymous caller got the same data and it is not personal: then it is
      // public, and "the second account can read it" says nothing about ownership.
      const publicToAnyone =
        anonymousBody !== null && !PERSONAL_DATA_RE.test(res.body) && exposedSensitiveFields(res.body).length === 0;
      if (secondary && !publicToAnyone && /\/\d+(?:\/|$)/.test(new URL(url).pathname)) {
        const asOther = await scanFetch(url, { as: secondary, timeoutMs: TIMEOUT_MS });
        if (
          asOther &&
          !isRefusal(asOther.status, asOther.body) &&
          looksLikeData(asOther.status, asOther.body) &&
          asOther.body === res.body
        ) {
          crossAccount.push(`${endpoint.method} ${new URL(url).pathname}`);
        }
      }
    }
  }

  // ── 1d. Rate limiting ───────────────────────────────────────────────────
  // Reads only, and a small burst — enough to show no limiter exists without
  // becoming load against a customer's server.
  if (
    endpoint.method === "GET" &&
    unratelimited.length < 3 &&
    RATE_LIMIT_SENSITIVE_PATTERN.test(new URL(url).pathname) &&
    // Reads of the current session sit under /auth/ but are not where anyone guesses a password:
    // NextAuth's /api/auth/session answers {} to everyone, and twelve of those prove nothing.
    !SESSION_STATE_SEGMENT.test(lastSegment(new URL(url).pathname)) &&
    !RATE_LIMIT_EXEMPT_PATTERN.test(new URL(url).pathname)
  ) {
    const burst = await Promise.all(
      Array.from({ length: RATE_LIMIT_BURST }, () =>
        scanFetch(url, {
          ...(input.credentials ? { as: input.credentials } : {}),
          timeoutMs: TIMEOUT_MS,
        }),
      ),
    );
    const answered = burst.filter((r) => r !== null);
    const throttled = answered.some((r) => r!.status === 429);
    // A limiter that announces itself (RateLimit-* / Retry-After) is a limiter, and a burst answered
    // only by a catch-all's shell or "not found" body never reached a sign-in route at all.
    const announced = answered.some((r) => Object.keys(r!.headers).some((h) => /^(x-)?ratelimit|^retry-after$/i.test(h)));
    const reachedNothing = answered.every((r) => isNotFoundBody(r!.body) || isHtmlDocument(r!.body));
    if (!throttled && !announced && !reachedNothing && answered.length === RATE_LIMIT_BURST && answered.every((r) => r!.status < 400)) {
      unratelimited.push(`${endpoint.method} ${new URL(url).pathname}`);
    }
  }

  // ── 1e. Write-verb authorisation (BFLA) ─────────────────────────────────
  // Aimed at an identifier nothing can exist at, so a successful DELETE
  // destroys nothing — but the status still reveals whether authorisation
  // runs before the lookup. PUT is never sent: many APIs upsert.
  if (
    input.credentials &&
    /\{[^}]+\}/.test(endpoint.url) &&
    (endpoint.method === "GET" || endpoint.method === "DELETE" || endpoint.method === "PATCH")
  ) {
    const target = endpoint.url.replace(/\{[^}]+\}/g, IMPLAUSIBLE_ID);
    if (!isDestructiveUrl(target)) {
      for (const verb of ["DELETE", "PATCH"] as const) {
        const res = await scanFetch(target, { method: verb, as: null, timeoutMs: TIMEOUT_MS });
        // Only evidence that a handler RAN counts: a 2xx (it accepted the request without
        // asking who sent it), or a validation-level 400/422 (it got as far as reading the
        // input). A 404 or 405 proves nothing: Express answers 404 "Cannot DELETE /x" for any
        // verb nobody routed, so an API with no such handler at all looks identical.
        if (res && isHandlerReached(res.status, res.body)) {
          unauthorizedWrites.push(`${verb} ${new URL(target).pathname} -> ${res.status}`);
          break;
        }
      }
    }
  }

  // ── 1f. Mass assignment ─────────────────────────────────────────────────
  // Read from the declared contract in runApiProbes, for every endpoint rather than only these.

  // ── 2. SQL injection ────────────────────────────────────────────────────
  const params = endpoint.params.slice(0, MAX_PARAMS_PER_ENDPOINT);
  for (const param of params) {
    if (param.location === "header") continue;
    // A body field can only be tested by sending a body, so it is limited to
    // endpoints where doing so is a question rather than a change.
    if (param.location === "body" && endpoint.method !== "POST") continue;

    const marker = "sq" + randomBytes(4).toString("hex");
    const [baseline, injected] = await Promise.all([
      requestWith(endpoint, url, param, marker, input.credentials),
      requestWith(endpoint, url, param, `${marker}'`, input.credentials),
    ]);
    if (!baseline || !injected) continue;

    for (const signature of SQL_ERROR_SIGNATURES) {
      // Same discipline as injectionProbe: the signature must be absent from
      // the benign baseline, so a page that always mentions SQL is not a hit.
      if (signature.test(injected.body) && !signature.test(baseline.body)) {
        injectable.push({
          endpoint: `${endpoint.method} ${new URL(url).pathname}`,
          param: param.name,
          where: param.location,
        });
        break;
      }
    }
  }
}

const SESSION_STATE_SEGMENT = /^(sessions?|csrf(-token)?|me|user|whoami|providers|logout|log-out|signout|sign-out|callback)$/i;

function lastSegment(pathname: string): string {
  const parts = pathname.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? "";
}
