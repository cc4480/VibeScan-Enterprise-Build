import type { ScanVulnerability } from "./scanner";
import { isOpenApiSpec } from "./apiDocsProbe";
import { isSecretBearingConfigJson } from "./probes-data";

export interface PathProbe {
  suffix: string;
  name: string;
  severity: ScanVulnerability["severity"];
  category: string;
  cweId: string;
  cvssScore?: number;
  wstgId?: string;
  description: (path: string) => string;
  solution: string;
  validate: (body: string, ct: string, status: number) => boolean;
  /**
   * The file's genuine content is itself an HTML document (a GraphQL playground).
   * Every other probe result that is a full HTML document is an app shell, not
   * the file, and the crawler drops it before `validate` runs.
   */
  servesHtml?: boolean;
}

/** Full HTML document, as opposed to a file that merely contains angle brackets. */
export const looksLikeHtmlDocument = (body: string): boolean =>
  /<!doctype\s+html|<html[\s>]/i.test(body.slice(0, 4000));

/** dotenv shape: every non-blank, non-comment line is KEY=VALUE. */
function looksLikeEnvFile(body: string): boolean {
  if (looksLikeHtmlDocument(body)) return false;
  const lines = body.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  return lines.length > 0 && lines.every((l) => /^(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=/.test(l));
}

/** A log file has timestamped or level-prefixed lines, several of them. */
const LOG_LINE = /^\s*(?:[[(]?\d{4}[-/]\d{2}[-/]\d{2}|[[(]?\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|[[(]?(?:ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE|FATAL|CRITICAL)\b)/;
function looksLikeLogFile(body: string): boolean {
  if (looksLikeHtmlDocument(body)) return false;
  return body.split(/\r?\n/).filter((l) => LOG_LINE.test(l)).length >= 2;
}

export const PATH_PROBES: PathProbe[] = [
  {
    suffix: "/swagger.json",
    name: "API Documentation Exposed on Inner Route (Swagger)",
    severity: "info",
    category: "Information Disclosure",
    cweId: "CWE-200",
    cvssScore: 0,
    wstgId: "WSTG-CONF-04",
    description: (path) =>
      `Swagger/OpenAPI documentation is publicly accessible at "${path}swagger.json". This gives attackers a complete blueprint of every API endpoint, parameters, authentication schemes, and data models — without needing to reverse-engineer the application.`,
    solution: "Require authentication to access API docs in production, or restrict them to internal networks.",
    validate: (body) => isOpenApiSpec(body),
  },
  {
    suffix: "/openapi.json",
    name: "API Documentation Exposed on Inner Route (OpenAPI)",
    severity: "info",
    category: "Information Disclosure",
    cweId: "CWE-200",
    cvssScore: 0,
    wstgId: "WSTG-CONF-04",
    description: (path) =>
      `OpenAPI documentation is publicly accessible at "${path}openapi.json". This exposes a complete map of your API surface to unauthenticated users.`,
    solution: "Restrict API documentation to authenticated users or internal network access.",
    validate: (body) => isOpenApiSpec(body),
  },
  {
    suffix: "/api-docs",
    name: "API Documentation Exposed on Inner Route",
    severity: "info",
    category: "Information Disclosure",
    cweId: "CWE-200",
    cvssScore: 0,
    wstgId: "WSTG-CONF-04",
    description: (path) =>
      `API documentation is publicly accessible at "${path}api-docs". This may expose internal endpoint details and data structures.`,
    solution: "Restrict API documentation to authenticated users.",
    validate: (body) => isOpenApiSpec(body),
  },
  {
    suffix: "/.env",
    name: "Environment File Exposed on Inner Route",
    severity: "critical",
    category: "Credential Exposure",
    cweId: "CWE-312",
    cvssScore: 9.1,
    wstgId: "WSTG-CONF-04",
    description: (path) =>
      `A .env file is publicly accessible at "${path}.env". This file typically contains database passwords, API keys, JWT secrets, and third-party tokens that can immediately compromise all connected services.`,
    solution: "Block .env* files at the web server level. Rotate all exposed credentials immediately.",
    validate: (body) => looksLikeEnvFile(body),
  },
  {
    suffix: "/.git/HEAD",
    name: "Git Repository Exposed on Inner Route",
    severity: "high",
    category: "Source Code Exposure",
    cweId: "CWE-538",
    cvssScore: 8.1,
    wstgId: "WSTG-CONF-04",
    description: (path) =>
      `A Git repository is accessible at "${path}.git/HEAD". Attackers can reconstruct source code, deleted files, and any credentials ever committed using git-dumper.`,
    solution: "Block /.git directory access at the web server. Never deploy VCS directories to a public web root.",
    validate: (body) => /^ref: refs\/heads\/\S+/.test(body.trim()) || /^[0-9a-f]{40}$/m.test(body.trim()),
  },
  {
    suffix: "/config.json",
    name: "Configuration File Exposed on Inner Route",
    severity: "high",
    category: "Information Disclosure",
    cweId: "CWE-200",
    cvssScore: 6.5,
    wstgId: "WSTG-CONF-04",
    description: (path) =>
      `A configuration file containing credential-shaped values is publicly accessible at "${path}config.json". Anything served from the web root is readable by anyone, so any secret in it is public.`,
    solution: "Remove config.json from web-accessible paths. Use environment variables for runtime configuration.",
    // Public bootstrap config (API URLs, flags, publishable SDK keys) is not a
    // finding; same rule as the root config.json probe in probes-data.ts.
    validate: (body, ct) => isSecretBearingConfigJson(body, ct),
  },
  {
    suffix: "/graphql",
    name: "GraphQL Endpoint Exposed on Inner Route",
    severity: "medium",
    category: "Information Disclosure",
    cweId: "CWE-200",
    cvssScore: 5.3,
    wstgId: "WSTG-CONF-04",
    description: (path) =>
      `A GraphQL endpoint appears accessible at "${path}graphql". If introspection is enabled, attackers can enumerate your entire schema including all queries, mutations, types, and fields.`,
    solution: "Disable GraphQL introspection in production. Add depth limiting and query complexity analysis.",
    servesHtml: true,
    // Structural, not the word. The old test matched /graphql|GraphQL/i
    // anywhere in the body, so nytimes.com's ordinary HTML page — which names
    // the word in a script URL — was reported as an exposed GraphQL endpoint.
    //
    // Two things are genuinely worth reporting at this path, and neither is
    // "the page said graphql": a JSON response shaped the way the GraphQL spec
    // says one is, and an interactive playground console served as HTML. A
    // playground IS an exposure, so HTML is not rejected outright — it has to
    // carry a playground fingerprint rather than the bare word.
    validate: (body, ct) => {
      const isHtml = ct.includes("text/html") || /^\s*<(?:!doctype|html)/i.test(body);
      if (isHtml) {
        return /GraphQL\s*Playground|GraphiQL|graphiql(?:\.min)?\.(?:js|css)|id=["']graphiql["']|Apollo\s+(?:Sandbox|Studio)|embeddable-sandbox/i.test(
          body,
        );
      }
      if (!(ct.includes("json") || body.trim().startsWith("{"))) return false;
      try {
        const doc = JSON.parse(body) as {
          data?: { __typename?: unknown; __schema?: unknown };
          errors?: unknown;
        };
        if (typeof doc?.data?.__typename === "string") return true;
        if (doc?.data?.__schema) return true;
        // A GET to a real GraphQL endpoint answers with a spec-shaped top-level
        // `errors` array ("GET query missing" and similar).
        return Array.isArray(doc?.errors) && doc.errors.length > 0;
      } catch {
        return false;
      }
    },
  },
  {
    suffix: "/debug.log",
    name: "Debug Log Exposed on Inner Route",
    severity: "medium",
    category: "Information Disclosure",
    cweId: "CWE-532",
    cvssScore: 5.3,
    wstgId: "WSTG-CONF-04",
    description: (path) =>
      `A debug log file is publicly accessible at "${path}debug.log". Logs can contain sensitive request data, stack traces, and application internals.`,
    solution: "Store logs outside the web root. Block .log files at the web server.",
    validate: (body) => looksLikeLogFile(body),
  },
];
