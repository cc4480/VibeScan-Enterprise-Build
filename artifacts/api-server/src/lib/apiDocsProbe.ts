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

const TIMEOUT_MS = 7_000;
const MIN_BODY_BYTES = 200; // Skip thin redirect/error pages

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safeGet(url: string): Promise<{ status: number; body: string; ct: string } | null> {
  const res = await scanFetch(url, { timeoutMs: TIMEOUT_MS });
  if (!res) return null;
  return { status: res.status, body: res.body, ct: res.headers["content-type"] ?? "" };
}

// ─────────────────────────────────────────────────────────────────────────────
// VALIDATION HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/** Confirms an OpenAPI/Swagger JSON spec — requires multiple structural markers */
function isOpenApiJson(body: string, ct: string): boolean {
  if (!ct.includes("application/json") && !ct.includes("text/plain") && !ct.includes("text/html")) return false;
  if (body.length < MIN_BODY_BYTES) return false;
  // Must have the openapi/swagger version field AND a paths object
  const hasVersion = /"openapi"\s*:\s*"[23]/.test(body) || /"swagger"\s*:\s*"2/.test(body);
  const hasPaths = /"paths"\s*:\s*\{/.test(body);
  const hasInfo = /"info"\s*:\s*\{/.test(body);
  return hasVersion && hasPaths && hasInfo;
}

/** Confirms an OpenAPI/Swagger YAML spec */
function isOpenApiYaml(body: string): boolean {
  if (body.length < MIN_BODY_BYTES) return false;
  const hasVersion = /^openapi:\s*['"']?[23]/m.test(body) || /^swagger:\s*['"']?2/m.test(body);
  const hasPaths = /^paths:/m.test(body);
  const hasInfo = /^info:/m.test(body);
  return hasVersion && hasPaths && hasInfo;
}

/**
 * Confirms a Swagger UI page — requires the swagger-ui-bundle.js or swagger-ui-dist
 * script to be loaded. Avoids matching pages that merely mention "swagger" in text.
 */
function isSwaggerUiPage(body: string): boolean {
  if (body.length < MIN_BODY_BYTES) return false;
  return (
    /swagger-ui-bundle\.js|swagger-ui-standalone|SwaggerUIBundle\s*\(/i.test(body) ||
    /swagger-ui-dist|swagger\.min\.js/i.test(body) ||
    // FastAPI/Spring Boot inject a specific swagger-ui initialiser inline
    /SwaggerUIBundle\s*\(\s*\{[^}]{20,}url/i.test(body)
  );
}

/**
 * Confirms a ReDoc page — requires the ReDoc script bundle, not just the word "redoc".
 */
function isRedocPage(body: string): boolean {
  if (body.length < MIN_BODY_BYTES) return false;
  return (
    /redoc\.standalone\.js|redoc-vendor\.chunk\.js|<redoc\s+spec-url/i.test(body) ||
    /Redoc\.init\s*\(/i.test(body)
  );
}

/** Confirms a GraphQL SDL schema */
function isGraphqlSdl(body: string, ct: string): boolean {
  if (body.length < 50) return false;
  const isTextLike = ct.includes("graphql") || ct.includes("text/plain") || ct.includes("text/html");
  if (!isTextLike) return false;
  return /type\s+Query\s*\{|type\s+Mutation\s*\{|schema\s*\{/.test(body);
}

// ─────────────────────────────────────────────────────────────────────────────
// CANDIDATE PATHS
// ─────────────────────────────────────────────────────────────────────────────

interface ApiDocPath {
  path: string;
  label: string;
  validate: (body: string, ct: string) => boolean;
}

const API_DOC_PATHS: ApiDocPath[] = [
  // ── OpenAPI JSON / YAML spec files ────────────────────────────────────────
  {
    path: "/openapi.json",
    label: "OpenAPI JSON spec",
    validate: (b, ct) => isOpenApiJson(b, ct),
  },
  {
    path: "/openapi.yaml",
    label: "OpenAPI YAML spec",
    validate: (b) => isOpenApiYaml(b),
  },
  {
    path: "/swagger.json",
    label: "Swagger 2.0 JSON spec",
    validate: (b, ct) => isOpenApiJson(b, ct),
  },
  {
    path: "/swagger.yaml",
    label: "Swagger YAML spec",
    validate: (b) => isOpenApiYaml(b),
  },
  {
    path: "/v1/openapi.json",
    label: "Versioned OpenAPI JSON spec",
    validate: (b, ct) => isOpenApiJson(b, ct),
  },
  {
    path: "/api-docs/swagger.json",
    label: "OpenAPI JSON spec",
    validate: (b, ct) => isOpenApiJson(b, ct),
  },

  // ── Swagger UI pages ───────────────────────────────────────────────────────
  // NOTE: /docs and /docs/ intentionally excluded — they commonly serve Docusaurus,
  // GitBook, and product documentation that would cause false positives.
  {
    path: "/swagger-ui.html",
    label: "Swagger UI",
    validate: (b) => isSwaggerUiPage(b),
  },
  {
    path: "/swagger-ui/",
    label: "Swagger UI",
    validate: (b) => isSwaggerUiPage(b),
  },
  {
    path: "/swagger/",
    label: "Swagger UI",
    validate: (b) => isSwaggerUiPage(b),
  },
  {
    path: "/api-docs",
    label: "Swagger/OpenAPI UI",
    validate: (b) => isSwaggerUiPage(b),
  },
  {
    path: "/api-docs/",
    label: "Swagger/OpenAPI UI",
    validate: (b) => isSwaggerUiPage(b),
  },
  {
    path: "/api/docs",
    label: "API documentation UI",
    validate: (b, ct) => isSwaggerUiPage(b) || isRedocPage(b) || isOpenApiJson(b, ct),
  },
  {
    path: "/api/swagger",
    label: "Swagger UI",
    validate: (b, ct) => isSwaggerUiPage(b) || isOpenApiJson(b, ct),
  },

  // ── Versioned docs paths ───────────────────────────────────────────────────
  {
    path: "/api/v1/docs",
    label: "Versioned API docs",
    validate: (b, ct) => isSwaggerUiPage(b) || isRedocPage(b) || isOpenApiJson(b, ct),
  },
  {
    path: "/api/v2/docs",
    label: "Versioned API docs",
    validate: (b, ct) => isSwaggerUiPage(b) || isRedocPage(b) || isOpenApiJson(b, ct),
  },

  // ── ReDoc ──────────────────────────────────────────────────────────────────
  {
    path: "/redoc",
    label: "ReDoc API documentation",
    validate: (b) => isRedocPage(b),
  },
  {
    path: "/redoc/",
    label: "ReDoc API documentation",
    validate: (b) => isRedocPage(b),
  },

  // ── GraphQL schema SDL ─────────────────────────────────────────────────────
  {
    path: "/graphql/schema",
    label: "GraphQL SDL schema",
    validate: (b, ct) => isGraphqlSdl(b, ct),
  },
];

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
      if (matchesCatchAll(r.body, catchAll)) return null;

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
