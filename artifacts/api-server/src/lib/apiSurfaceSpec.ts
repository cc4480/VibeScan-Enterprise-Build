/** Endpoint discovery from OpenAPI / Swagger documents. */
import { type ApiEndpoint, type ApiParam, type ParamLocation } from "./apiSurface";

export const HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options"];

// A bundle can be megabytes; discovery should not become the slow part of a scan.
export const MAX_ENDPOINTS = 120;

// ─────────────────────────────────────────────────────────────────────────────
// OpenAPI / Swagger
// ─────────────────────────────────────────────────────────────────────────────

export interface OpenApiSchema {
  type?: string;
  properties?: Record<string, unknown>;
  items?: OpenApiSchema;
  $ref?: string;
}

export interface OpenApiOperation {
  parameters?: Array<{ name?: string; in?: string; $ref?: string }>;
  requestBody?: {
    content?: Record<string, { schema?: OpenApiSchema }>;
  };
}

export interface OpenApiDocument {
  openapi?: string;
  swagger?: string;
  servers?: Array<{ url?: string }>;
  basePath?: string;
  paths?: Record<string, Record<string, OpenApiOperation>>;
  components?: { schemas?: Record<string, OpenApiSchema> };
  definitions?: Record<string, OpenApiSchema>;
}

/** Resolve a local $ref like "#/components/schemas/User". Remote refs are ignored. */
export function resolveRef(doc: OpenApiDocument, ref: string): OpenApiSchema | undefined {
  if (!ref.startsWith("#/")) return undefined;
  let node: unknown = doc;
  for (const segment of ref.slice(2).split("/")) {
    if (!node || typeof node !== "object") return undefined;
    node = (node as Record<string, unknown>)[decodeURIComponent(segment.replace(/~1/g, "/").replace(/~0/g, "~"))];
  }
  return node as OpenApiSchema | undefined;
}

/** Top-level field names of a request body, following one level of $ref. */
export function bodyFields(doc: OpenApiDocument, schema: OpenApiSchema | undefined, depth = 0): string[] {
  if (!schema || depth > 2) return [];
  if (schema.$ref) return bodyFields(doc, resolveRef(doc, schema.$ref), depth + 1);
  if (schema.items) return bodyFields(doc, schema.items, depth + 1);
  return schema.properties ? Object.keys(schema.properties) : [];
}

/**
 * Read every declared operation out of an OpenAPI or Swagger 2 document.
 *
 * The spec is the best source available: it names parameters the front end may
 * never send, which is precisely where forgotten, untested handlers live.
 */
export function endpointsFromSpec(specText: string, origin: string): ApiEndpoint[] {
  let doc: OpenApiDocument;
  try {
    doc = JSON.parse(specText) as OpenApiDocument;
  } catch {
    // YAML specs are common and parsing one properly would mean adding a
    // dependency. Recover the paths by pattern instead — fewer parameters, but
    // the endpoint list is the part that matters most.
    return endpointsFromYamlish(specText, origin);
  }

  if (!doc.paths || typeof doc.paths !== "object") return [];

  // Swagger 2 uses basePath; OpenAPI 3 uses servers[].url, which may be relative.
  let base = "";
  const serverUrl = doc.servers?.[0]?.url;
  if (typeof serverUrl === "string" && serverUrl.trim()) {
    base = serverUrl.startsWith("http")
      ? serverUrl.replace(/\/+$/, "")
      : `${origin}${serverUrl.replace(/\/+$/, "")}`;
  } else if (typeof doc.basePath === "string") {
    base = `${origin}${doc.basePath.replace(/\/+$/, "")}`;
  } else {
    base = origin;
  }

  const out: ApiEndpoint[] = [];

  for (const [path, operations] of Object.entries(doc.paths)) {
    if (!operations || typeof operations !== "object") continue;

    for (const [method, operation] of Object.entries(operations)) {
      if (!HTTP_METHODS.includes(method.toLowerCase())) continue;
      if (out.length >= MAX_ENDPOINTS) return out;

      const params: ApiParam[] = [];

      for (const p of operation?.parameters ?? []) {
        const resolved = p.$ref
          ? (resolveRef(doc, p.$ref) as unknown as { name?: string; in?: string } | undefined)
          : p;
        if (!resolved?.name) continue;
        const where = (resolved.in ?? "query").toLowerCase();
        if (where === "query" || where === "path" || where === "header") {
          params.push({ name: resolved.name, location: where as ParamLocation });
        }
      }

      // Any JSON-ish content type; a spec may declare application/vnd.x+json.
      const content = operation?.requestBody?.content ?? {};
      for (const [mediaType, media] of Object.entries(content)) {
        if (!/json/i.test(mediaType)) continue;
        for (const field of bodyFields(doc, media?.schema)) {
          params.push({ name: field, location: "body" });
        }
      }

      // Path templates that were never declared as parameters still matter.
      for (const match of path.matchAll(/\{([^}]+)\}/g)) {
        const name = match[1]!;
        if (!params.some((p) => p.name === name && p.location === "path")) {
          params.push({ name, location: "path" });
        }
      }

      out.push({
        url: `${base}${path}`,
        method: method.toUpperCase(),
        params,
        source: "spec",
      });
    }
  }

  return out;
}

/** Last-resort path extraction from a YAML spec, without a YAML parser. */
export function endpointsFromYamlish(text: string, origin: string): ApiEndpoint[] {
  const out: ApiEndpoint[] = [];
  const lines = text.split(/\r?\n/);
  let inPaths = false;
  let currentPath: string | null = null;

  for (const line of lines) {
    if (/^paths:/.test(line)) {
      inPaths = true;
      continue;
    }
    if (!inPaths) continue;
    // A new top-level key ends the paths block.
    if (/^\S/.test(line) && !/^paths:/.test(line)) break;

    const pathMatch = /^\s{2}(\/[^\s:]*):/.exec(line);
    if (pathMatch) {
      currentPath = pathMatch[1]!;
      continue;
    }

    const methodMatch = /^\s{4}([a-z]+):/.exec(line);
    if (methodMatch && currentPath && HTTP_METHODS.includes(methodMatch[1]!)) {
      if (out.length >= MAX_ENDPOINTS) break;
      const params: ApiParam[] = [];
      for (const m of currentPath.matchAll(/\{([^}]+)\}/g)) {
        params.push({ name: m[1]!, location: "path" });
      }
      out.push({
        url: `${origin}${currentPath}`,
        method: methodMatch[1]!.toUpperCase(),
        params,
        source: "spec",
      });
    }
  }

  return out;
}
