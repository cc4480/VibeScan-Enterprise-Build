/** The API documentation paths to try, and the validators that decide a response really is that document. */
export const MIN_BODY_BYTES = 200; // Skip thin redirect/error pages

// ─────────────────────────────────────────────────────────────────────────────
// VALIDATION HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/** Confirms an OpenAPI/Swagger JSON spec — requires multiple structural markers */
export function isOpenApiJson(body: string, ct: string): boolean {
  if (!ct.includes("application/json") && !ct.includes("text/plain") && !ct.includes("text/html")) return false;
  if (body.length < MIN_BODY_BYTES) return false;
  // Must have the openapi/swagger version field AND a paths object
  const hasVersion = /"openapi"\s*:\s*"[23]/.test(body) || /"swagger"\s*:\s*"2/.test(body);
  const hasPaths = /"paths"\s*:\s*\{/.test(body);
  const hasInfo = /"info"\s*:\s*\{/.test(body);
  return hasVersion && hasPaths && hasInfo;
}

/**
 * Structural check for a JSON OpenAPI/Swagger document: it must parse, carry a
 * `swagger`/`openapi` version string and a `paths` object. Unlike the substring
 * checks above it is content-type independent and cannot be satisfied by an HTML
 * shell or an error body that merely mentions the word. Shared with the path
 * probes in probes-data.ts and the crawler's inner-route probes.
 */
export function isOpenApiSpec(body: string): boolean {
  if (body.length < 50 || body.trimStart()[0] !== "{") return false;
  try {
    const doc = JSON.parse(body) as Record<string, unknown>;
    const version = doc["openapi"] ?? doc["swagger"];
    const paths = doc["paths"];
    return typeof version === "string" && /^[23]/.test(version) &&
      typeof paths === "object" && paths !== null && !Array.isArray(paths);
  } catch {
    return false;
  }
}

/** Confirms an OpenAPI/Swagger YAML spec */
export function isOpenApiYaml(body: string): boolean {
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
export function isSwaggerUiPage(body: string): boolean {
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
export function isRedocPage(body: string): boolean {
  if (body.length < MIN_BODY_BYTES) return false;
  return (
    /redoc\.standalone\.js|redoc-vendor\.chunk\.js|<redoc\s+spec-url/i.test(body) ||
    /Redoc\.init\s*\(/i.test(body)
  );
}

/** Confirms a GraphQL SDL schema */
export function isGraphqlSdl(body: string, ct: string): boolean {
  if (body.length < 50) return false;
  const isTextLike = ct.includes("graphql") || ct.includes("text/plain") || ct.includes("text/html");
  if (!isTextLike) return false;
  return /type\s+Query\s*\{|type\s+Mutation\s*\{|schema\s*\{/.test(body);
}

// ─────────────────────────────────────────────────────────────────────────────
// CANDIDATE PATHS
// ─────────────────────────────────────────────────────────────────────────────

export interface ApiDocPath {
  path: string;
  label: string;
  validate: (body: string, ct: string) => boolean;
}

export const API_DOC_PATHS: ApiDocPath[] = [
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
