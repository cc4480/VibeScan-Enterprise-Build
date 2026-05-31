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

const TIMEOUT_MS = 7_000;
const MIN_BODY_BYTES = 200; // Skip thin redirect/error pages

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safeGet(url: string): Promise<{ status: number; body: string; ct: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "Mozilla/5.0 VibeScan Security Scanner" },
    });
    const body = await res.text().catch(() => "");
    const ct = res.headers.get("content-type") ?? "";
    return { status: res.status, body, ct };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
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
// SPA CATCH-ALL ROUTING DETECTION
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Detects SPA catch-all routing (React/Vite/Next.js apps that return HTTP 200
 * for every path). Fingerprints the response to a guaranteed-nonexistent path
 * so we can suppress false positives from path-based probing.
 *
 * If the app is a SPA catch-all, every probed path like /swagger or /openapi.json
 * gets the same HTML shell with HTTP 200 — body length and <title> will match.
 */
interface CatchAllFingerprint {
  bodyLength: number;
  title: string;
}

async function detectCatchAll(origin: string): Promise<CatchAllFingerprint | null> {
  const nonce = `vibescan-spacheck-${Math.random().toString(36).slice(2, 10)}-notfound`;
  const r = await safeGet(`${origin}/${nonce}`);
  if (!r || r.status !== 200) return null;
  const titleMatch = /<title[^>]*>([^<]{1,200})<\/title>/i.exec(r.body);
  return {
    bodyLength: r.body.length,
    title: titleMatch?.[1]?.trim() ?? "",
  };
}

/**
 * Returns true when a probe response looks like the SPA catch-all shell.
 * Two signals — body size within 3% of baseline, or exact title match.
 * Either signal alone is sufficient since SPAs are very consistent.
 */
function matchesCatchAll(body: string, catchAll: CatchAllFingerprint | null): boolean {
  if (!catchAll || catchAll.bodyLength === 0) return false;

  // Signal 1: body length within 3% — the HTML shell is always the same size
  const diff = Math.abs(body.length - catchAll.bodyLength) / catchAll.bodyLength;
  if (diff < 0.03) return true;

  // Signal 2: same <title> element — SPAs have one static title for all routes
  if (catchAll.title.length > 3) {
    const titleMatch = /<title[^>]*>([^<]{1,200})<\/title>/i.exec(body);
    const title = titleMatch?.[1]?.trim() ?? "";
    if (title.length > 0 && title === catchAll.title) return true;
  }

  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────────────────────────────────────

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
        severity: "medium",
        category: "Information Disclosure",
        description: isSpec
          ? `An ${label} is publicly accessible at ${path}. This exposes your complete ` +
            `API contract — every endpoint, request/response schema, parameter, and ` +
            `authentication scheme — dramatically lowering the effort needed to enumerate ` +
            `and exploit your backend.`
          : `An interactive API documentation UI (${label}) is publicly accessible at ${path}. ` +
            `This lets anyone explore and test your API endpoints without authentication, ` +
            `exposing your full backend surface. The bundled "Try It Out" feature may also ` +
            `allow unauthenticated API calls directly from the browser.`,
        evidence: `GET ${url}\nHTTP 200 — ${label} confirmed (${isSpec ? "spec structure validated" : "UI bundle script detected"})`,
        solution:
          "Disable API documentation in production or restrict access to authenticated users or internal IPs. " +
          (isSpec
            ? "Remove the spec file from your production deployment or serve it behind an auth middleware. "
            : "FastAPI: set `docs_url=None, redoc_url=None` when `os.getenv('ENV') != 'development'`. ") +
          "Express/Swagger: gate the route with an IP allowlist or require an `Authorization` header. " +
          "If public docs are intentional, disable the 'Try It Out' feature and remove auth scheme details.",
        cweId: "CWE-200",
        cvssScore: 5.3,
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
