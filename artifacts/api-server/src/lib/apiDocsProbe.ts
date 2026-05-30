/**
 * Exposed API documentation probe.
 *
 * Checks for publicly accessible OpenAPI/Swagger/ReDoc documentation endpoints.
 * AI-generated backends frequently ship with Swagger UI enabled in production,
 * leaking the full API contract (endpoints, params, auth schemes, schemas).
 *
 * Read-only HEAD/GET requests only.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const TIMEOUT_MS = 7_000;

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
// CANDIDATE PATHS
// ─────────────────────────────────────────────────────────────────────────────

interface ApiDocPath {
  path: string;
  label: string;
  validate: (body: string, ct: string) => boolean;
}

const API_DOC_PATHS: ApiDocPath[] = [
  // ── OpenAPI JSON / YAML ────────────────────────────────────────────────────
  {
    path: "/openapi.json",
    label: "OpenAPI JSON spec",
    validate: (b) => /"openapi"\s*:\s*"[23]/.test(b) || /"swagger"\s*:\s*"2/.test(b) || /"paths"\s*:/.test(b),
  },
  {
    path: "/openapi.yaml",
    label: "OpenAPI YAML spec",
    validate: (b) => /^openapi:\s*[23]/m.test(b) || /^swagger:\s*['"']?2/m.test(b) || /^paths:/m.test(b),
  },
  {
    path: "/swagger.json",
    label: "Swagger 2.0 JSON spec",
    validate: (b) => /"swagger"\s*:\s*"2/.test(b) || /"paths"\s*:/.test(b) || /"info"\s*:/.test(b),
  },
  {
    path: "/swagger.yaml",
    label: "Swagger YAML spec",
    validate: (b) => /^swagger:\s*/m.test(b) || /^paths:/m.test(b),
  },
  // ── Swagger UI paths ───────────────────────────────────────────────────────
  {
    path: "/swagger-ui.html",
    label: "Swagger UI",
    validate: (b) => /swagger-ui|SwaggerUI|swagger\.json/i.test(b),
  },
  {
    path: "/swagger-ui/",
    label: "Swagger UI",
    validate: (b) => /swagger-ui|SwaggerUI/i.test(b),
  },
  {
    path: "/swagger/",
    label: "Swagger UI",
    validate: (b) => /swagger-ui|SwaggerUI|swagger\.json/i.test(b),
  },
  // ── API docs paths ─────────────────────────────────────────────────────────
  {
    path: "/api-docs",
    label: "Swagger/OpenAPI UI",
    validate: (b) => /swagger-ui|SwaggerUI|"openapi"|"swagger"/i.test(b),
  },
  {
    path: "/api-docs/",
    label: "Swagger/OpenAPI UI",
    validate: (b) => /swagger-ui|SwaggerUI|"openapi"|"swagger"/i.test(b),
  },
  {
    path: "/api-docs/swagger.json",
    label: "OpenAPI JSON spec",
    validate: (b) => /"paths"\s*:/.test(b) || /"openapi"\s*:/.test(b),
  },
  {
    path: "/api/docs",
    label: "API documentation UI",
    validate: (b) => /swagger-ui|redoc|ReDoc|"openapi"|"paths"\s*:/i.test(b),
  },
  // ── ReDoc ──────────────────────────────────────────────────────────────────
  {
    path: "/redoc",
    label: "ReDoc API documentation",
    validate: (b) => /redoc|ReDoc|openapi/i.test(b),
  },
  {
    path: "/redoc/",
    label: "ReDoc API documentation",
    validate: (b) => /redoc|ReDoc|openapi/i.test(b),
  },
  // ── Versioned paths ────────────────────────────────────────────────────────
  {
    path: "/api/v1/docs",
    label: "Versioned API docs",
    validate: (b) => /swagger-ui|redoc|"openapi"|"paths"\s*:/i.test(b),
  },
  {
    path: "/api/v2/docs",
    label: "Versioned API docs",
    validate: (b) => /swagger-ui|redoc|"openapi"|"paths"\s*:/i.test(b),
  },
  {
    path: "/v1/openapi.json",
    label: "Versioned OpenAPI spec",
    validate: (b) => /"paths"\s*:/.test(b) || /"openapi"\s*:/.test(b),
  },
  {
    path: "/api/swagger",
    label: "Swagger UI",
    validate: (b) => /swagger-ui|SwaggerUI|"paths"\s*:/i.test(b),
  },
  // ── GraphQL schema SDL ─────────────────────────────────────────────────────
  {
    path: "/graphql/schema",
    label: "GraphQL SDL schema",
    validate: (b, ct) =>
      (ct.includes("graphql") || ct.includes("text/plain")) &&
      /type\s+Query|type\s+Mutation|schema\s*\{/.test(b),
  },
  // ── FastAPI / Django / Rails auto-generated ────────────────────────────────
  {
    path: "/docs",
    label: "FastAPI/auto-generated API docs",
    validate: (b) => /swagger-ui|SwaggerUI|fastapi|"openapi"/i.test(b),
  },
  {
    path: "/docs/",
    label: "FastAPI/auto-generated API docs",
    validate: (b) => /swagger-ui|SwaggerUI|fastapi|"openapi"/i.test(b),
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────────────────────────────────────

export async function runApiDocsProbe(targetUrl: string): Promise<ScanVulnerability[]> {
  let origin: string;
  try { origin = new URL(targetUrl).origin; } catch { return []; }

  const results = await Promise.allSettled(
    API_DOC_PATHS.map(async ({ path, label, validate }) => {
      const url = origin + path;
      const r = await safeGet(url);
      if (!r || r.status !== 200) return null;
      if (!validate(r.body, r.ct)) return null;

      // Determine if it's a spec file (JSON/YAML) or a UI page
      const isSpec =
        path.endsWith(".json") || path.endsWith(".yaml") ||
        r.ct.includes("application/json") || r.ct.includes("application/yaml");

      const pathSegment = path;

      return vuln({
        name: `Exposed API Documentation — ${label} at ${pathSegment}`,
        severity: "medium",
        category: "Information Disclosure",
        description: isSpec
          ? `An ${label} is publicly accessible at ${pathSegment}. This exposes your complete ` +
            `API contract — every endpoint, request/response schema, parameter, and authentication ` +
            `scheme — dramatically reducing the effort required to find and exploit vulnerabilities.`
          : `An interactive API documentation UI (${label}) is publicly accessible at ${pathSegment}. ` +
            `This lets anyone explore and test your API endpoints without any authentication, ` +
            `revealing your full backend surface area.`,
        evidence: `GET ${url}\nHTTP 200 — ${label} confirmed`,
        solution:
          "Disable API documentation in production, or restrict access to internal networks / " +
          "authenticated users. " +
          (isSpec
            ? "Move the spec behind auth middleware or remove it from your production build. "
            : "FastAPI: set `docs_url=None` and `redoc_url=None` when `ENV != 'development'`. ") +
          "Express/Swagger: gate the `/api-docs` route with an IP allowlist or API key. " +
          "If public docs are required, remove auth scheme details and use a read-only spec.",
        cweId: "CWE-200",
        cvssScore: 5.3,
        wstgId: "WSTG-CONF-02",
        confidence: 90,
      });
    }),
  );

  const found: ScanVulnerability[] = [];
  const seenPaths = new Set<string>();

  for (const r of results) {
    if (r.status !== "fulfilled" || !r.value) continue;
    // Deduplicate by path segment embedded in name
    const key = r.value.name;
    if (!seenPaths.has(key)) {
      seenPaths.add(key);
      found.push(r.value);
    }
  }

  return found.slice(0, 5); // Cap: max 5 findings
}
