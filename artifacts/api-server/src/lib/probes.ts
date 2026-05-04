/**
 * Active security probes — HTTP-based checks run in parallel alongside the main header scan.
 * Each probe is independent and best-effort (failures are non-fatal).
 *
 * Covers: sensitive file exposure, HTTP methods, active CORS, open redirects,
 * robots.txt analysis, Subresource Integrity, error disclosure, HTTPS redirect,
 * rate limiting, directory listing, and clickjacking verification.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";

const PROBE_TIMEOUT_MS = 8_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

async function safeGet(
  url: string,
  options: RequestInit = {},
  timeoutMs = PROBE_TIMEOUT_MS,
): Promise<{ status: number; body: string; headers: Record<string, string>; finalUrl: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    const body = await res.text().catch(() => "");
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, body, headers, finalUrl: res.url };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. SENSITIVE FILE EXPOSURE
// ─────────────────────────────────────────────────────────────────────────────

interface SensitivePath {
  path: string;
  name: string;
  severity: ScanVulnerability["severity"];
  cweId: string;
  cvssScore?: number;
  category: string;
  description: string;
  solution: string;
  validate: (body: string, contentType: string) => boolean;
}

const SENSITIVE_PATHS: SensitivePath[] = [
  // ── Version control ──────────────────────────────────────────────────────
  {
    path: "/.git/HEAD",
    name: "Git Repository Exposed",
    severity: "critical", cweId: "CWE-538", cvssScore: 9.8,
    category: "Source Code Exposure",
    description: "The .git directory is publicly accessible. Attackers can reconstruct your entire source code history—including deleted files, credentials ever committed, and all branches—using tools like git-dumper.",
    solution: "Block /.git at the web server: Nginx: `location ~ /\\.git { deny all; return 404; }` Apache: `<Directory .git> Deny from all </Directory>`. Never deploy VCS directories to a public web root.",
    validate: (body) => /^ref: refs\/heads\/\S+/.test(body.trim()) || /^[0-9a-f]{40}$/m.test(body.trim()),
  },
  {
    path: "/.git/config",
    name: "Git Config Exposed",
    severity: "high", cweId: "CWE-538", cvssScore: 7.5,
    category: "Source Code Exposure",
    description: "The Git configuration file is publicly accessible, revealing remote repository URLs, branch names, and any credentials stored via git-credential helpers.",
    solution: "Block all access to .git at the web server level.",
    validate: (body) => /\[core\]|\[remote\s|repositoryformatversion/.test(body),
  },
  {
    path: "/.svn/entries",
    name: "SVN Repository Exposed",
    severity: "high", cweId: "CWE-538", cvssScore: 7.5,
    category: "Source Code Exposure",
    description: "A Subversion (.svn) metadata directory is publicly accessible, potentially exposing the full source code tree.",
    solution: "Block .svn directories: `location ~ /\\.svn { deny all; }`",
    validate: (body) => /^\d+\n/.test(body) || /dir\n/.test(body.slice(0, 100)),
  },
  {
    path: "/.hg/requires",
    name: "Mercurial Repository Exposed",
    severity: "high", cweId: "CWE-538", cvssScore: 7.5,
    category: "Source Code Exposure",
    description: "A Mercurial (.hg) repository directory is publicly accessible.",
    solution: "Block .hg directories at the web server level.",
    validate: (body) => /dotencode|fncache|revlogv/.test(body),
  },

  // ── Environment / credentials ────────────────────────────────────────────
  {
    path: "/.env",
    name: "Environment File Exposed (.env)",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "A .env file is publicly accessible. This file typically contains database passwords, API keys, JWT secrets, and third-party tokens in plaintext. Attackers can immediately compromise every connected service.",
    solution: "Rotate ALL credentials in the file immediately. Block .env* files: `location ~ /\\.env { deny all; }`. Never place .env files in the web root.",
    validate: (body, ct) => !ct.includes("text/html") || /^[A-Z_][A-Z0-9_]*\s*=.+/m.test(body),
  },
  {
    path: "/.env.local",
    name: "Environment File Exposed (.env.local)",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: ".env.local is publicly accessible. This override file often contains developer or staging credentials.",
    solution: "Block all .env* files at the web server and rotate any exposed credentials.",
    validate: (body, ct) => !ct.includes("text/html") || /^[A-Z_][A-Z0-9_]*\s*=.+/m.test(body),
  },
  {
    path: "/.env.production",
    name: "Production Environment File Exposed (.env.production)",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "The production .env file is publicly accessible, exposing live database credentials, payment keys, and all production secrets.",
    solution: "Block all .env* files immediately and rotate all exposed production credentials.",
    validate: (body, ct) => !ct.includes("text/html") || /^[A-Z_][A-Z0-9_]*\s*=.+/m.test(body),
  },
  {
    path: "/.env.backup",
    name: "Backup Environment File Exposed",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.1,
    category: "Credential Exposure",
    description: "A backup of the environment config is publicly accessible.",
    solution: "Delete .env backups from the server. Block all .env* files.",
    validate: (body, ct) => !ct.includes("text/html") || /^[A-Z_][A-Z0-9_]*\s*=.+/m.test(body),
  },
  {
    path: "/.env.staging",
    name: "Staging Environment File Exposed",
    severity: "high", cweId: "CWE-312", cvssScore: 8.2,
    category: "Credential Exposure",
    description: "Staging environment configuration is publicly accessible, which often shares similar credentials to production.",
    solution: "Block all .env* files at the web server.",
    validate: (body, ct) => !ct.includes("text/html") || /^[A-Z_][A-Z0-9_]*\s*=.+/m.test(body),
  },

  // ── PHP / CMS configs ────────────────────────────────────────────────────
  {
    path: "/wp-config.php",
    name: "WordPress Config File Exposed (wp-config.php)",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "WordPress configuration is accessible as source code (PHP not executing). This exposes the database host, name, username, password, table prefix, and all WordPress secret keys.",
    solution: "Ensure PHP is correctly configured to execute .php files. Move wp-config.php one level above the web root as an additional safeguard.",
    validate: (body) => /DB_NAME|DB_PASSWORD|DB_USER|table_prefix|AUTH_KEY/.test(body),
  },
  {
    path: "/phpinfo.php",
    name: "PHP Info Page Exposed",
    severity: "high", cweId: "CWE-200", cvssScore: 7.5,
    category: "Information Disclosure",
    description: "A phpinfo() page is accessible. This reveals PHP version, all loaded modules, server paths, environment variables (including $_ENV secrets), and configuration values—a complete reconnaissance package for attackers.",
    solution: "Delete phpinfo.php from production. Never deploy debug scripts to production servers.",
    validate: (body) => /phpinfo\(\)|PHP Version|<title>phpinfo\(\)/i.test(body),
  },
  {
    path: "/info.php",
    name: "PHP Info Page Exposed (info.php)",
    severity: "high", cweId: "CWE-200", cvssScore: 7.5,
    category: "Information Disclosure",
    description: "A PHP info page is accessible, disclosing detailed server and environment configuration.",
    solution: "Delete info.php from production immediately.",
    validate: (body) => /phpinfo\(\)|PHP Version|PHP Variables/i.test(body),
  },
  {
    path: "/config.php",
    name: "PHP Config File Exposed",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.1,
    category: "Credential Exposure",
    description: "A PHP configuration file is accessible as source code, potentially exposing database credentials and application secrets.",
    solution: "Ensure PHP processes .php files. Block direct web access to config files.",
    validate: (body) => /\$(?:db_|database|password|pass|secret|key|host)/i.test(body),
  },
  {
    path: "/configuration.php",
    name: "Joomla Configuration Exposed",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "The Joomla configuration file is accessible as source, exposing database credentials and secret keys.",
    solution: "Ensure PHP is executing .php files. Verify web server configuration for the Joomla directory.",
    validate: (body) => /JConfig|db_name|db_password|db_prefix|\$password/i.test(body),
  },
  {
    path: "/settings.php",
    name: "Drupal Settings File Exposed",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "The Drupal settings.php file is accessible as source code, exposing database credentials and hash salt.",
    solution: "Ensure PHP is configured to execute .php files, not serve them raw.",
    validate: (body) => /\$databases|\$db_url|hash_salt|drupal_hash_salt/i.test(body),
  },

  // ── Database backups ─────────────────────────────────────────────────────
  {
    path: "/backup.sql",
    name: "Database Backup Exposed",
    severity: "critical", cweId: "CWE-552", cvssScore: 9.8,
    category: "Data Exposure",
    description: "A SQL database backup is publicly downloadable. An attacker can download your entire database including user credentials, personal data, and all application records.",
    solution: "Remove all database dumps from the web root immediately. Store backups encrypted in a private, non-web-accessible location.",
    validate: (body) => /CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL dump|-- PostgreSQL database dump/i.test(body.slice(0, 3000)),
  },
  {
    path: "/dump.sql",
    name: "Database Dump Exposed",
    severity: "critical", cweId: "CWE-552", cvssScore: 9.8,
    category: "Data Exposure",
    description: "A database dump is publicly accessible.",
    solution: "Remove dump.sql from the web root.",
    validate: (body) => /CREATE TABLE|INSERT INTO|DROP TABLE|-- (MySQL|Dump|PostgreSQL)/i.test(body.slice(0, 3000)),
  },
  {
    path: "/db.sql",
    name: "Database File Exposed",
    severity: "critical", cweId: "CWE-552", cvssScore: 9.8,
    category: "Data Exposure",
    description: "A database file is publicly accessible.",
    solution: "Remove db.sql from the web root.",
    validate: (body) => /CREATE TABLE|INSERT INTO|DROP TABLE|PRAGMA/i.test(body.slice(0, 3000)),
  },
  {
    path: "/database.sql",
    name: "Database Export Exposed",
    severity: "critical", cweId: "CWE-552", cvssScore: 9.8,
    category: "Data Exposure",
    description: "A database export file is publicly accessible.",
    solution: "Remove database.sql from the web root.",
    validate: (body) => /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(body.slice(0, 3000)),
  },
  {
    path: "/backup.zip",
    name: "Backup Archive Exposed",
    severity: "critical", cweId: "CWE-552", cvssScore: 9.1,
    category: "Source Code Exposure",
    description: "A backup archive is publicly downloadable. This likely contains source code, configuration files with credentials, and database exports.",
    solution: "Remove all backup files from the web root. Store backups in a private, access-controlled location.",
    validate: (body, ct) => ct.includes("zip") || ct.includes("octet-stream") || body.slice(0, 2) === "PK",
  },
  {
    path: "/backup.tar.gz",
    name: "Backup Archive Exposed (.tar.gz)",
    severity: "critical", cweId: "CWE-552", cvssScore: 9.1,
    category: "Source Code Exposure",
    description: "A tar.gz backup archive is publicly downloadable.",
    solution: "Remove backup archives from the web root.",
    validate: (_, ct) => ct.includes("gzip") || ct.includes("octet-stream") || ct.includes("tar"),
  },

  // ── API documentation ─────────────────────────────────────────────────────
  {
    path: "/swagger.json",
    name: "API Documentation Exposed (Swagger)",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "Swagger/OpenAPI documentation is publicly accessible without authentication. This gives attackers a complete blueprint of every API endpoint, required parameters, authentication schemes, and data models.",
    solution: "Require authentication to access API docs in production. Add middleware to protect /swagger.json and /swagger-ui.html, or serve docs only on internal network.",
    validate: (body) => /"swagger"|"openapi"/.test(body.slice(0, 500)),
  },
  {
    path: "/openapi.json",
    name: "API Documentation Exposed (OpenAPI)",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "OpenAPI documentation is publicly accessible, providing a complete map of your API surface.",
    solution: "Restrict API docs to authenticated users or internal network access.",
    validate: (body) => /"openapi"|"swagger"/.test(body.slice(0, 500)),
  },
  {
    path: "/swagger-ui.html",
    name: "Swagger UI Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "Swagger UI is publicly accessible, allowing anyone to browse, test, and interact with your API directly from their browser.",
    solution: "Require authentication to access Swagger UI in production environments.",
    validate: (body) => /swagger-ui|SwaggerUI/i.test(body),
  },
  {
    path: "/api-docs",
    name: "API Documentation Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "API documentation is publicly accessible.",
    solution: "Restrict API documentation to authenticated users.",
    validate: (body) => /"swagger"|"openapi"|"paths"/.test(body.slice(0, 1000)),
  },
  {
    path: "/graphql",
    name: "GraphQL Introspection Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "A GraphQL endpoint appears accessible. If introspection is enabled, attackers can enumerate your entire schema including all queries, mutations, types, and fields.",
    solution: "Disable GraphQL introspection in production environments. Add depth limiting and query complexity analysis to prevent abuse.",
    validate: (body) => /\"__schema\"|\"__type\"|graphql|GraphQL/i.test(body),
  },

  // ── Spring Boot Actuator ─────────────────────────────────────────────────
  {
    path: "/actuator/env",
    name: "Spring Boot Actuator /env Exposed",
    severity: "critical", cweId: "CWE-200", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "Spring Boot Actuator's /env endpoint is publicly accessible. This dumps ALL environment variables, configuration properties, and system properties—including database passwords, API keys, and every secret your application uses.",
    solution: "Secure all Actuator endpoints: `management.endpoints.web.exposure.include=health` only. Restrict remaining endpoints behind authentication or to localhost only.",
    validate: (body) => /"activeProfiles"|"propertySources"|"systemEnvironment"/.test(body.slice(0, 1000)),
  },
  {
    path: "/actuator/configprops",
    name: "Spring Boot Config Properties Exposed",
    severity: "critical", cweId: "CWE-200", cvssScore: 9.1,
    category: "Credential Exposure",
    description: "Spring Boot Actuator's configprops endpoint exposes all configuration properties including sensitive values.",
    solution: "Never expose configprops in production. Restrict all Actuator endpoints.",
    validate: (body) => /"contexts"|"beans"|"properties"/.test(body.slice(0, 500)),
  },
  {
    path: "/actuator/beans",
    name: "Spring Boot Beans Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "Spring Boot Actuator's beans endpoint reveals the full application component structure and wiring.",
    solution: "Restrict all Actuator endpoints to internal network access only.",
    validate: (body) => /"beans"|"applicationContextId"/.test(body.slice(0, 500)),
  },

  // ── Config files ─────────────────────────────────────────────────────────
  {
    path: "/config.json",
    name: "Configuration File Exposed (config.json)",
    severity: "high", cweId: "CWE-200", cvssScore: 7.5,
    category: "Information Disclosure",
    description: "A configuration JSON file is publicly accessible, potentially containing connection strings, API keys, or internal endpoint URLs.",
    solution: "Remove config.json from the web root. Use environment variables for configuration, never static files.",
    validate: (body, ct) => (ct.includes("json") || body.trim().startsWith("{")) && !ct.includes("text/html"),
  },
  {
    path: "/Dockerfile",
    name: "Dockerfile Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "The application's Dockerfile is publicly accessible, revealing the exact base image, build steps, exposed ports, and potentially build-time secrets passed as ARGs.",
    solution: "Remove Dockerfile from the web root. Only deploy built application artifacts.",
    validate: (body) => /^FROM\s+\S+/m.test(body),
  },
  {
    path: "/docker-compose.yml",
    name: "Docker Compose Config Exposed",
    severity: "high", cweId: "CWE-200", cvssScore: 7.5,
    category: "Information Disclosure",
    description: "docker-compose.yml is publicly accessible, revealing service configurations, port mappings, volume mounts, and potentially hardcoded environment variables with credentials.",
    solution: "Remove docker-compose.yml from the web root.",
    validate: (body) => /^services:|^version:/.test(body),
  },
  {
    path: "/package.json",
    name: "Package Manifest Exposed (package.json)",
    severity: "info", cweId: "CWE-200",
    category: "Information Disclosure",
    description: "package.json is publicly accessible, revealing the full dependency tree and exact package versions. Attackers can identify dependencies with known CVEs and target your specific stack.",
    solution: "Block access to package.json from the web server. Ensure build artifacts are not deployed to the web root.",
    validate: (body, ct) => (ct.includes("json") || body.trim().startsWith("{")) && /"dependencies"|"scripts"|"name"/.test(body),
  },
  {
    path: "/web.config",
    name: "IIS Web Configuration Exposed",
    severity: "high", cweId: "CWE-200", cvssScore: 7.5,
    category: "Information Disclosure",
    description: "IIS web.config is publicly accessible. This may contain connection strings, authentication settings, and application configuration including potential credentials.",
    solution: "IIS normally blocks web.config access. Audit your IIS configuration to ensure this default protection is active.",
    validate: (body) => /<configuration>|<connectionStrings>|<appSettings>/i.test(body),
  },

  // ── Framework-specific ───────────────────────────────────────────────────
  {
    path: "/config/database.yml",
    name: "Rails Database Config Exposed",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "The Rails database.yml file is accessible, exposing database adapter, host, name, username, and password for all environments (development, test, production).",
    solution: "Block web access to the config directory. Use `DATABASE_URL` environment variable instead of hardcoding credentials in database.yml.",
    validate: (body) => /adapter:|database:|username:|password:|host:/i.test(body),
  },
  {
    path: "/config/secrets.yml",
    name: "Rails Secrets File Exposed",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "Rails secrets.yml is accessible, exposing secret_key_base and any other application secrets for all environments.",
    solution: "Block access to the config directory. Migrate to Rails encrypted credentials (`bin/rails credentials:edit`).",
    validate: (body) => /secret_key_base|development:|production:/i.test(body),
  },
  {
    path: "/local_settings.py",
    name: "Django Local Settings Exposed",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.1,
    category: "Credential Exposure",
    description: "A Django local settings file is accessible, likely containing SECRET_KEY, database credentials, and DEBUG=True.",
    solution: "Block .py files via web server rules. Never store settings files in a publicly accessible directory.",
    validate: (body) => /SECRET_KEY|DATABASES|DEBUG\s*=/.test(body),
  },

  // ── Logs ─────────────────────────────────────────────────────────────────
  {
    path: "/storage/logs/laravel.log",
    name: "Laravel Log File Exposed",
    severity: "high", cweId: "CWE-532", cvssScore: 7.5,
    category: "Information Disclosure",
    description: "The Laravel application log is publicly accessible. Log files contain exception stack traces with full file paths, SQL queries (including parameters), request data, and sometimes inadvertently logged credentials.",
    solution: "Ensure Laravel's /storage directory is not inside or accessible from the web root. The standard Laravel setup places it correctly — verify your deployment hasn't accidentally moved it.",
    validate: (body) => /\[\d{4}-\d{2}-\d{2}.*\].*(?:INFO|ERROR|DEBUG|WARNING)/i.test(body.slice(0, 3000)),
  },
  {
    path: "/debug.log",
    name: "Debug Log File Exposed",
    severity: "medium", cweId: "CWE-532", cvssScore: 6.5,
    category: "Information Disclosure",
    description: "A debug log is publicly accessible. Logs can contain sensitive request data, stack traces, and application internals.",
    solution: "Store logs outside the web root. Block .log files: `location ~ \\.log$ { deny all; }`",
    validate: (body) => body.length > 200 && /error|warn|debug|exception|trace/i.test(body.slice(0, 3000)),
  },

  // ── Other ────────────────────────────────────────────────────────────────
  {
    path: "/.gitignore",
    name: ".gitignore Exposes Sensitive Path Names",
    severity: "info", cweId: "CWE-200",
    category: "Information Disclosure",
    description: ".gitignore is publicly accessible. While not directly exploitable, it reveals the names of sensitive files on the server (e.g., '*.key', 'secrets/', 'credentials.json') that exist but aren't tracked in Git, giving attackers a targeted list of files to probe.",
    solution: "Consider blocking .gitignore at the web server to avoid disclosing the sensitive file structure.",
    validate: (body) => body.includes(".env") || body.includes("secret") || body.includes("*.key") || body.length > 100,
  },
  {
    path: "/server-status",
    name: "Apache Server Status Page Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "Apache's server-status page is publicly accessible, revealing real-time request data including request URIs being processed (which may contain tokens in URLs), active connections, server version, and performance metrics.",
    solution: "Restrict server-status to localhost only: `<Location /server-status> Require local </Location>`",
    validate: (body) => /Apache Server Status|requests currently being processed/i.test(body),
  },
  {
    path: "/.DS_Store",
    name: "macOS .DS_Store File Exposed",
    severity: "low", cweId: "CWE-200",
    category: "Information Disclosure",
    description: ".DS_Store files contain macOS Finder directory metadata including file names and layouts. Tools like ds_store_exp can enumerate the complete directory structure without needing directory listing enabled.",
    solution: "Add .DS_Store to .gitignore to prevent deployment. Block access: `location = /.DS_Store { deny all; }`. Clean any existing .DS_Store files from your server.",
    validate: (_, ct) => ct.includes("octet-stream") || ct.includes("x-ds"),
  },
  {
    path: "/crossdomain.xml",
    name: "Permissive crossdomain.xml Policy",
    severity: "medium", cweId: "CWE-942", cvssScore: 6.5,
    category: "CORS Misconfiguration",
    description: "A Flash/Silverlight cross-domain policy file exists. If it allows access from all domains (*), legacy Flash or PDF plugins can make credentialed cross-origin requests to your application.",
    solution: "Remove crossdomain.xml if Flash is not used. If needed, restrict to specific domains instead of using wildcards.",
    validate: (body) => /<cross-domain-policy|allow-access-from domain/i.test(body),
  },
];

export async function checkSensitiveFiles(baseUrl: string): Promise<ScanVulnerability[]> {
  let origin: string;
  let expectedHost: string;
  try {
    const parsed = new URL(baseUrl);
    origin = parsed.origin;
    expectedHost = parsed.hostname;
  } catch {
    return [];
  }

  const results = await Promise.allSettled(
    SENSITIVE_PATHS.map(async (p): Promise<ScanVulnerability | null> => {
      const url = `${origin}${p.path}`;
      const result = await safeGet(url, { redirect: "follow" });
      if (!result || result.status !== 200) return null;

      // Redirected to a different host = catch-all (login page etc.)
      try {
        const finalHost = new URL(result.finalUrl).hostname;
        if (finalHost !== expectedHost) return null;
      } catch {
        return null;
      }

      const ct = result.headers["content-type"] ?? "";
      if (!p.validate(result.body, ct)) return null;

      return vuln({
        name: p.name,
        severity: p.severity,
        category: p.category,
        description: p.description,
        evidence: `GET ${p.path} → HTTP 200 (${result.body.length.toLocaleString()} bytes)\nContent-Type: ${ct || "not set"}`,
        solution: p.solution,
        cweId: p.cweId,
        cvssScore: p.cvssScore,
      });
    }),
  );

  return results
    .filter((r): r is PromiseFulfilledResult<ScanVulnerability | null> => r.status === "fulfilled")
    .map((r) => r.value)
    .filter((v): v is ScanVulnerability => v !== null);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. HTTP METHODS PROBE
// ─────────────────────────────────────────────────────────────────────────────

export async function checkHttpMethods(targetUrl: string): Promise<ScanVulnerability[]> {
  const result = await safeGet(targetUrl, { method: "OPTIONS", redirect: "follow" });
  if (!result) return [];

  const allow = result.headers["allow"] ?? result.headers["access-control-allow-methods"] ?? "";
  if (!allow) return [];

  const vulns: ScanVulnerability[] = [];

  if (/\bTRACE\b/i.test(allow)) {
    vulns.push(vuln({
      name: "HTTP TRACE Method Enabled (Cross-Site Tracing)",
      severity: "medium",
      category: "HTTP Security",
      description: "The HTTP TRACE method is enabled. It reflects the full request back to the client—including headers like Authorization and Cookie. Combined with XSS (Cross-Site Tracing / XST), an attacker can steal session tokens that are marked HttpOnly, bypassing that protection.",
      evidence: `OPTIONS → Allow: ${allow}`,
      solution: "Disable TRACE server-wide. Apache: `TraceEnable Off`. Nginx: already off by default. IIS: Use URLScan or Request Filtering. This should be disabled regardless of whether XSS is present.",
      cweId: "CWE-16",
      cvssScore: 5.8,
    }));
  }

  const dangerousMethods = ["PUT", "DELETE", "PATCH"].filter((m) =>
    new RegExp(`\\b${m}\\b`, "i").test(allow),
  );
  if (dangerousMethods.length > 0) {
    vulns.push(vuln({
      name: `Dangerous HTTP Methods Advertised (${dangerousMethods.join(", ")})`,
      severity: "high",
      category: "HTTP Security",
      description: `The server advertises ${dangerousMethods.join("/")} in the Allow header for the root path. If not properly guarded by application-level authorization, these methods can allow arbitrary file uploads or deletion of server resources.`,
      evidence: `OPTIONS → Allow: ${allow}`,
      solution: "Restrict HTTP methods to only those genuinely required. Use application-level authorization on any write methods. Block unused methods at the web server or load balancer before requests reach application code.",
      cweId: "CWE-650",
      cvssScore: 7.5,
    }));
  }

  if (/\bCONNECT\b/i.test(allow)) {
    vulns.push(vuln({
      name: "HTTP CONNECT Method Enabled",
      severity: "medium",
      category: "HTTP Security",
      description: "The CONNECT method is advertised. This method is used to establish tunnels and could allow the server to be used as a proxy to reach internal systems not otherwise accessible.",
      evidence: `OPTIONS → Allow: ${allow}`,
      solution: "Disable the CONNECT method unless you are intentionally running a proxy server.",
      cweId: "CWE-441",
      cvssScore: 6.1,
    }));
  }

  return vulns;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. ACTIVE CORS TESTING
// ─────────────────────────────────────────────────────────────────────────────

export async function checkActiveCors(targetUrl: string): Promise<ScanVulnerability[]> {
  const testOrigins = [
    "https://evil-attacker.com",
    "null",
  ];

  for (const origin of testOrigins) {
    const result = await safeGet(targetUrl, {
      headers: { Origin: origin },
      redirect: "follow",
    });
    if (!result) continue;

    const acao = result.headers["access-control-allow-origin"];
    const acac = result.headers["access-control-allow-credentials"];
    if (!acao) continue;

    const reflectsOrigin = acao === origin;
    const withCredentials = /^true$/i.test(acac ?? "");

    if (reflectsOrigin && withCredentials) {
      return [vuln({
        name: "CORS Misconfiguration — Credentials Allowed from Arbitrary Origin",
        severity: "critical",
        category: "CORS Misconfiguration",
        description: `The server reflects any request Origin in Access-Control-Allow-Origin AND sets Access-Control-Allow-Credentials: true. This allows any malicious website to make authenticated cross-origin requests on behalf of a logged-in victim — reading their private data, performing actions as them, and effectively bypassing SameSite cookie protections.`,
        evidence: `Request: Origin: ${origin}\nResponse: Access-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac}`,
        solution: "Maintain a strict server-side allowlist of trusted origins. Never dynamically reflect the incoming Origin header without validating it against the allowlist. Never combine a dynamic origin with credentials: true.",
        cweId: "CWE-942",
        cvssScore: 9.1,
      })];
    }

    if (reflectsOrigin && !withCredentials) {
      return [vuln({
        name: "CORS Misconfiguration — Origin Reflected Without Allowlist",
        severity: "medium",
        category: "CORS Misconfiguration",
        description: `The server reflects any Origin value in Access-Control-Allow-Origin without validating it. While credentials are not currently sent, this enables cross-origin data theft from any public API endpoint your application exposes.`,
        evidence: `Request: Origin: ${origin}\nResponse: Access-Control-Allow-Origin: ${acao}`,
        solution: "Validate the Origin header against an explicit allowlist. Only reflect origins that are on the approved list. Never use a catch-all reflection.",
        cweId: "CWE-942",
        cvssScore: 6.5,
      })];
    }
  }

  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. OPEN REDIRECT TESTING
// ─────────────────────────────────────────────────────────────────────────────

export async function checkOpenRedirect(targetUrl: string): Promise<ScanVulnerability[]> {
  const base = new URL(targetUrl);
  const probeTarget = "https://evil-redirect-probe.com";
  const params = ["redirect", "url", "next", "goto", "return", "returnUrl", "returnTo", "r", "redirect_uri", "callback", "continue", "dest", "destination", "forward"];

  for (const param of params) {
    const testUrl = new URL(targetUrl);
    testUrl.searchParams.set(param, probeTarget);

    const result = await safeGet(testUrl.toString(), { redirect: "manual" });
    if (!result) continue;

    if (result.status >= 300 && result.status < 400) {
      const location = result.headers["location"] ?? "";
      if (/evil-redirect-probe\.com/i.test(location)) {
        return [vuln({
          name: "Open Redirect Vulnerability",
          severity: "medium",
          category: "Unvalidated Redirects",
          description: `The '${param}' parameter controls where users are sent after an action without validation. Attackers send victims a URL on ${base.hostname} (which they trust) that silently redirects them to a phishing site. This is widely used in credential harvesting campaigns because the initial URL appears legitimate.`,
          evidence: `GET ${testUrl.pathname}?${param}=${encodeURIComponent(probeTarget)}\n→ HTTP ${result.status} Location: ${location}`,
          solution: "Validate all redirect targets against an allowlist of permitted paths or domains. Prefer relative paths. If external redirects are needed, use an intermediate confirmation page and never accept destination URLs from user input directly.",
          cweId: "CWE-601",
          cvssScore: 6.1,
        })];
      }
    }
  }

  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. ROBOTS.TXT ANALYSIS
// ─────────────────────────────────────────────────────────────────────────────

export async function checkRobotsTxt(baseUrl: string): Promise<ScanVulnerability[]> {
  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return [];
  }

  const result = await safeGet(`${origin}/robots.txt`);
  if (!result || result.status !== 200 || result.body.length < 10) return [];

  const lines = result.body.split("\n");
  const disallowedPaths = lines
    .filter((l) => /^Disallow:\s*/i.test(l))
    .map((l) => l.replace(/^Disallow:\s*/i, "").trim())
    .filter((p) => p && p !== "/" && p.length > 1);

  const sensitivePatterns = [
    /admin/i, /backup/i, /config/i, /private/i, /secret/i,
    /internal/i, /\/api\//i, /database/i, /\/db\//i, /\.sql/i,
    /staging/i, /\/dev\//i, /\/logs?\//i, /debug/i, /dashboard/i,
    /\/tmp\//i, /\/test\//i, /\.env/i, /credentials/i,
  ];

  const sensitivePaths = disallowedPaths.filter((p) =>
    sensitivePatterns.some((rx) => rx.test(p)),
  );

  if (sensitivePaths.length === 0) return [];

  return [vuln({
    name: "robots.txt Discloses Sensitive Application Paths",
    severity: "info",
    category: "Information Disclosure",
    description: `The robots.txt file contains ${sensitivePaths.length} path(s) that reveal sensitive areas of the application: ${sensitivePaths.slice(0, 5).join(", ")}${sensitivePaths.length > 5 ? "…" : ""}. Ironically, listing paths in robots.txt to hide them from search engines makes them more discoverable to attackers who always check this file first.`,
    evidence: sensitivePaths.slice(0, 8).map((p) => `Disallow: ${p}`).join("\n"),
    solution: "Do not use robots.txt to obscure sensitive paths — it achieves the opposite. Properly secure those endpoints with authentication. Consider using `Disallow: /` globally if you don't want any indexing, rather than listing individual sensitive paths.",
    cweId: "CWE-200",
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. SUBRESOURCE INTEGRITY (SRI) CHECK
// ─────────────────────────────────────────────────────────────────────────────

export async function checkSRI(html: string, baseUrl: string): Promise<ScanVulnerability[]> {
  let baseHost: string;
  try {
    baseHost = new URL(baseUrl).hostname;
  } catch {
    return [];
  }

  const scriptRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  const linkRegex = /<link[^>]+href=["']([^"']+)["'][^>]*rel=["']stylesheet["'][^>]*>/gi;
  const missingIntegrity: string[] = [];

  const checkTag = (tag: string, src: string) => {
    try {
      const u = new URL(src, baseUrl);
      if (u.hostname !== baseHost && !tag.includes("integrity=")) {
        missingIntegrity.push(src);
      }
    } catch { /* relative URL */ }
  };

  let m: RegExpExecArray | null;
  while ((m = scriptRegex.exec(html)) !== null) checkTag(m[0], m[1]);
  while ((m = linkRegex.exec(html)) !== null) checkTag(m[0], m[1]);

  if (missingIntegrity.length === 0) return [];

  return [vuln({
    name: "External Resources Missing Subresource Integrity (SRI)",
    severity: "medium",
    category: "Supply Chain Security",
    description: `${missingIntegrity.length} external script(s)/stylesheet(s) are loaded from third-party CDNs without Subresource Integrity hashes. If any of these CDNs are compromised (which has happened to major CDNs), attackers can inject arbitrary JavaScript that runs on your site for all visitors—stealing credentials, hijacking sessions, or installing skimmers.`,
    evidence: missingIntegrity.slice(0, 5).map((s) => `Missing integrity: ${s}`).join("\n"),
    solution: 'Add integrity and crossorigin to all external resources: `<script src="https://cdn.example.com/lib.js" integrity="sha384-..." crossorigin="anonymous">`. Generate hashes at https://www.srihash.org/ or using `openssl dgst -sha384 -binary FILE | openssl base64 -A`.',
    cweId: "CWE-353",
    cvssScore: 6.1,
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. ERROR PAGE DISCLOSURE
// ─────────────────────────────────────────────────────────────────────────────

export async function checkErrorDisclosure(baseUrl: string): Promise<ScanVulnerability[]> {
  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return [];
  }

  const testPath = `/_vibescan-${Date.now()}-not-a-real-path`;
  const result = await safeGet(`${origin}${testPath}`);
  if (!result) return [];

  const body = result.body;

  const leakPatterns: Array<{ rx: RegExp; name: string }> = [
    { rx: /at\s+\w[\w.]+\s+\((?:\/[\w./\\-]+|[A-Z]:\\[\w./\\-]+):\d+:\d+\)/m, name: "JavaScript/Node.js stack trace with file paths" },
    { rx: /Traceback \(most recent call last\)[\s\S]{0,200}File "\/[^"]+"/m, name: "Python traceback with system file paths" },
    { rx: /in \/[\w./\\-]+\.php on line \d+/m, name: "PHP error with file path" },
    { rx: /Parse error:|Fatal error:|Warning:|Notice:/m, name: "PHP error message" },
    { rx: /ActiveRecord::\w+|ActionController::\w+/m, name: "Ruby on Rails exception class" },
    { rx: /\bat [\w.$]+\([\w$.]+\.java:\d+\)/m, name: "Java stack trace" },
    { rx: /System\.(NullReference|InvalidOperation|Web\.Http)Exception/m, name: "ASP.NET exception" },
    { rx: /werkzeug\.debug|Debugger caught an exception/m, name: "Werkzeug/Flask debugger (CRITICAL — allows RCE via debug console)" },
    { rx: /Whoops\\|Symfony\\Component\\Debug\\Exception/m, name: "PHP Whoops/Symfony debug page" },
    { rx: /DebugException|Illuminate\\Foundation\\Exceptions/m, name: "Laravel debug page" },
    { rx: /Django.*DEBUG.*True|django\.core\.exceptions/m, name: "Django debug page (DEBUG=True in production)" },
  ];

  const matched = leakPatterns.find((p) => p.rx.test(body));
  if (!matched) return [];

  const isFlaskDebugger = /werkzeug\.debug|Debugger caught/.test(body);

  return [vuln({
    name: isFlaskDebugger
      ? "Flask/Werkzeug Interactive Debugger Exposed (Remote Code Execution)"
      : "Verbose Error Pages Expose Internal Application Details",
    severity: isFlaskDebugger ? "critical" : "medium",
    category: "Information Disclosure",
    description: isFlaskDebugger
      ? "The Flask/Werkzeug interactive debugger is enabled and publicly accessible. This allows ANYONE to execute arbitrary Python code on your server directly from their browser. This is a complete server compromise."
      : `Non-existent URLs trigger error pages containing ${matched.name}. These responses reveal internal file paths, framework/library versions, function call stacks, and application structure—dramatically reducing attacker effort to find exploitable weaknesses.`,
    evidence: `GET ${testPath} → HTTP ${result.status}\nLeak type: ${matched.name}`,
    solution: isFlaskDebugger
      ? "IMMEDIATELY disable the Werkzeug debugger: set DEBUG=False and FLASK_ENV=production. This is a critical emergency—your server can be fully compromised."
      : "Disable debug mode in production. Use a generic error page that reveals nothing. Log detailed errors server-side only. Framework guides: Express.js — use a production error handler middleware. Django — DEBUG = False. PHP — display_errors = Off in php.ini. Rails — config.consider_all_requests_local = false.",
    cweId: isFlaskDebugger ? "CWE-94" : "CWE-209",
    cvssScore: isFlaskDebugger ? 10.0 : 5.3,
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. HTTP → HTTPS REDIRECT CHECK
// ─────────────────────────────────────────────────────────────────────────────

export async function checkHttpsRedirect(targetUrl: string): Promise<ScanVulnerability[]> {
  let hostname: string;
  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== "https:") return [];
    hostname = parsed.hostname;
  } catch {
    return [];
  }

  const result = await safeGet(`http://${hostname}/`, { redirect: "manual" }, 6_000);
  if (!result) return [];

  if (result.status >= 300 && result.status < 400) {
    const location = result.headers["location"] ?? "";
    if (location.startsWith("https://")) return [];
  }

  if (result.status === 200 || (result.status >= 300 && !result.headers["location"]?.startsWith("https://"))) {
    return [vuln({
      name: "HTTP Traffic Not Redirected to HTTPS",
      severity: "high",
      category: "Transport Security",
      description: "The HTTP version of the site does not redirect to HTTPS. Users who visit via HTTP (from bookmarks, old links, or typed URLs) communicate in plaintext—exposing session cookies, passwords, and all data to network interception. This also undermines HSTS since the first request is unprotected.",
      evidence: `http://${hostname}/ → HTTP ${result.status} (not redirected to HTTPS)`,
      solution: "Configure a permanent 301 redirect from HTTP to HTTPS at the web server or load balancer. Nginx: `return 301 https://$host$request_uri;` Apache: `Redirect permanent / https://yourdomain.com/` After HTTPS is stable, add HSTS with preloading.",
      cweId: "CWE-319",
      cvssScore: 7.4,
    })];
  }

  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. RATE LIMITING DETECTION
// ─────────────────────────────────────────────────────────────────────────────

export async function checkRateLimiting(targetUrl: string): Promise<ScanVulnerability[]> {
  const result = await safeGet(targetUrl, {}, 6_000);
  if (!result) return [];

  const h = result.headers;
  const hasRateLimit =
    h["x-ratelimit-limit"] ||
    h["x-rate-limit-limit"] ||
    h["ratelimit-limit"] ||
    h["retry-after"] ||
    h["x-ratelimit-remaining"] ||
    h["ratelimit-remaining"] ||
    h["cf-ray"] || // Cloudflare manages rate limiting
    h["x-kong-limit"] ||
    h["x-envoy-ratelimited"];

  if (!hasRateLimit) {
    return [vuln({
      name: "No Rate Limiting Detected",
      severity: "low",
      category: "Brute Force Protection",
      description: "No rate limiting or throttling headers were detected. Without rate limiting, attackers can run automated brute-force attacks against login endpoints, enumerate valid user accounts through credential stuffing, abuse API endpoints at scale, or perform denial-of-service attacks by flooding your server.",
      solution: "Implement rate limiting on all sensitive endpoints (login, registration, password reset, API). Node.js: express-rate-limit. Django: DRF throttling. Also implement: account lockout after N failures, CAPTCHA on login, and IP-based throttling at the CDN/load balancer level. Return standard headers: X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After.",
      cweId: "CWE-307",
      cvssScore: 5.3,
    })];
  }

  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. CLICKJACKING VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────

export async function checkClickjacking(targetUrl: string): Promise<ScanVulnerability[]> {
  // Only run if main scanner didn't already flag this via headers
  // This does a direct page fetch and checks the actual response headers
  const result = await safeGet(targetUrl, {}, 6_000);
  if (!result) return [];

  const xfo = result.headers["x-frame-options"];
  const csp = result.headers["content-security-policy"] ?? "";
  const hasFrameAncestors = /frame-ancestors/i.test(csp);

  // If both protections are missing, this is handled by the main scanner
  // But if X-Frame-Options is present but misconfigured:
  if (xfo && !/^(DENY|SAMEORIGIN)$/i.test(xfo.trim())) {
    return [vuln({
      name: "X-Frame-Options Header Misconfigured",
      severity: "medium",
      category: "UI Security",
      description: `X-Frame-Options is set to an invalid or non-standard value: "${xfo}". Browsers may ignore unrecognized values, leaving the application vulnerable to clickjacking attacks where attackers embed your page in an invisible iframe.`,
      evidence: `X-Frame-Options: ${xfo}`,
      solution: 'Set X-Frame-Options to either "DENY" (blocks all framing) or "SAMEORIGIN" (allows framing by same origin). Alternatively, use CSP: Content-Security-Policy: frame-ancestors \'none\'',
      cweId: "CWE-1021",
      cvssScore: 4.3,
    })];
  }

  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export async function runAllProbes(
  targetUrl: string,
  html: string,
): Promise<ScanVulnerability[]> {
  const settled = await Promise.allSettled([
    checkSensitiveFiles(targetUrl),
    checkHttpMethods(targetUrl),
    checkActiveCors(targetUrl),
    checkOpenRedirect(targetUrl),
    checkRobotsTxt(targetUrl),
    checkSRI(html, targetUrl),
    checkErrorDisclosure(targetUrl),
    checkHttpsRedirect(targetUrl),
    checkRateLimiting(targetUrl),
    checkClickjacking(targetUrl),
  ]);

  return settled
    .filter((r): r is PromiseFulfilledResult<ScanVulnerability[]> => r.status === "fulfilled")
    .flatMap((r) => r.value);
}
