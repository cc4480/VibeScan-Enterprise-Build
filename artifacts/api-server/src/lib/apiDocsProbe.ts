/**
 * Exposed API documentation probe.
 *
 * Checks for publicly accessible OpenAPI/Swagger/ReDoc documentation.
 * AI-generated backends frequently ship with Swagger UI enabled in production,
 * leaking the full API contract (endpoints, params, auth schemes, schemas).
 *
 * False-positive prevention:
 * - Generic paths like /docs and /docs/ are excluded — they commonly serve
 *   Docusaurus, GitBook, and product wikis that match keyword checks but are
 *   NOT API security issues.
 * - Spec file paths (*.json, *.yaml) require valid OpenAPI/Swagger structure,
 *   not just the presence of a "paths" key.
 * - UI paths require the Swagger UI JavaScript bundle to be referenced in the
 *   page, or specific ReDoc markers — not just the word "swagger" in text.
 * - A minimum body length is enforced to skip empty/redirect responses.
 *
 * Read-only GET requests only.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { detectCatchAll, matchesCatchAll } from "./spaCatchAll";
import { scanFetch } from "./http";
import { API_DOC_PATHS } from "./apiDocsProbePaths";
export { isOpenApiSpec } from "./apiDocsProbePaths";

const TIMEOUT_MS = 7_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safeGet(url: string): Promise<{ status: number; body: string; ct: string } | null> {
  const res = await scanFetch(url, { timeoutMs: TIMEOUT_MS });
  if (!res) return null;
  return { status: res.status, body: res.body, ct: res.headers["content-type"] ?? "" };
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────────────────────────────────────

// SPA/multi-tenant catch-all detection (detectCatchAll, matchesCatchAll) lives
// in ./spaCatchAll — shared with probes.ts's checkSensitiveFiles, which probes
// a much larger set of paths and needs the same false-positive suppression.

export async function runApiDocsProbe(targetUrl: string): Promise<ScanVulnerability[]> {
  let origin: string;
  try { origin = new URL(targetUrl).origin; } catch { return []; }

  // Baseline probe: detect SPA catch-all routing BEFORE probing real paths.
  // If the app returns 200 + its HTML shell for a random nonexistent path, every
  // subsequent 200 response must be checked against this baseline.
  const catchAll = await detectCatchAll(origin).catch(() => null);

  const results = await Promise.allSettled(
    API_DOC_PATHS.map(async ({ path, label, validate }) => {
      const url = origin + path;
      const r = await safeGet(url);
      if (!r || r.status !== 200) return null;

      // Suppress if response is the SPA catch-all shell — not a real doc endpoint
      if (matchesCatchAll(r.body, catchAll, url)) return null;

      if (!validate(r.body, r.ct)) return null;

      const isSpec =
        path.endsWith(".json") || path.endsWith(".yaml") ||
        r.ct.includes("application/json") || r.ct.includes("application/yaml");

      return vuln({
        name: `Exposed API Documentation — ${label} at ${path}`,
        // Severity is deliberately low, and this is why: publishing an OpenAPI
        // spec is mainstream, intentional practice — Stripe, Vercel, Cloudflare,
        // GitHub and Twilio all serve one at their apex domain on purpose. A
        // reachable spec is not itself a weakness: the endpoints it documents
        // still enforce their own auth, so the spec describes the surface rather
        // than opening it. Reporting it as a MEDIUM "exploit your backend"
        // vulnerability fired confidently against Vercel, Cloudflare and Netlify,
        // whose specs are a documented developer resource — a false positive
        // whose own evidence ("spec structure validated") only confirmed the spec
        // was real, never that exposing it was a mistake.
        //
        // A spec file is therefore INFO — a surface-disclosure note to confirm is
        // intended. An interactive UI with "Try It Out" is LOW: marginally more,
        // because it invites unauthenticated probing from the browser, though it
        // too only exercises endpoints that enforce their own auth.
        severity: isSpec ? "info" : "low",
        category: "Information Disclosure",
        description: isSpec
          ? `An ${label} is publicly reachable at ${path}, exposing your API contract — ` +
            `endpoints, schemas, parameters and auth schemes — in machine-readable form. ` +
            `This is frequently intentional; many public APIs publish their spec on purpose. ` +
            `Confirm the exposure is meant to be public. If the spec describes an internal or ` +
            `admin API, it lowers the effort to enumerate that surface and should be removed.`
          : `An interactive API documentation UI (${label}) is publicly accessible at ${path}. ` +
            `Anyone can explore your API endpoints, and a bundled "Try It Out" feature can issue ` +
            `calls from the browser. Confirm this is intentional; the endpoints behind it still ` +
            `enforce their own authentication, but the UI invites probing.`,
        evidence: `GET ${url}\nHTTP 200 — ${label} confirmed (${isSpec ? "spec structure validated" : "UI bundle script detected"})`,
        solution:
          "If this exposure is not intentional, disable API documentation in production or restrict it to authenticated users or internal IPs. " +
          (isSpec
            ? "Remove the spec file from your production deployment or serve it behind an auth middleware. "
            : "FastAPI: set `docs_url=None, redoc_url=None` when `os.getenv('ENV') != 'development'`. ") +
          "Express/Swagger: gate the route with an IP allowlist or require an `Authorization` header. " +
          "If public docs are intentional, consider disabling the 'Try It Out' feature and trimming auth-scheme detail.",
        cweId: "CWE-200",
        cvssScore: isSpec ? 0 : 3.1,
        wstgId: "WSTG-CONF-02",
        confidence: 92,
      });
    }),
  );

  const found: ScanVulnerability[] = [];
  const seenPaths = new Set<string>();

  for (const r of results) {
    if (r.status !== "fulfilled" || !r.value) continue;
    if (!seenPaths.has(r.value.name)) {
      seenPaths.add(r.value.name);
      found.push(r.value);
    }
  }

  return found.slice(0, 5);
}