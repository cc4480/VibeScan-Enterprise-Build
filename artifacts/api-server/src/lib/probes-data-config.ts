import type { SensitivePath } from "./probes-data";

/**
 * A JSON config file counts as an exposure only when it carries a
 * credential-shaped key with a non-trivial value; public runtime config (API
 * URLs, flags, publishable SDK keys) does not. Shared with the crawler's
 * inner-route `config.json` probe so both apply the same rule.
 */
export function isSecretBearingConfigJson(body: string, ct: string): boolean {
  if (ct.includes("text/html")) return false;
  if (!(ct.includes("json") || body.trim().startsWith("{"))) return false;
  return /"[^"]*(?:password|passwd|secret|private_?key|connection_?string|db_pass|aws_secret|client_secret|api_secret)[^"]*"\s*:\s*"[^"]{8,}"/i.test(
    body,
  );
}

/** Config files, framework files, logs, .env variants and CI/CD pipeline configurations. */
export const SENSITIVE_PATHS_CONFIG: SensitivePath[] = [
  // ── Config files ─────────────────────────────────────────────────────────
  {
    path: "/config.json",
    name: "Configuration File Exposed (config.json)",
    severity: "high", cweId: "CWE-200", cvssScore: 7.5,
    category: "Information Disclosure",
    description: "A configuration JSON file containing credential-shaped values is publicly accessible. Configuration served from the web root is readable by anyone, so any secret in it is public.",
    solution: "Remove config.json from the web root, or strip the secret values from it. Server-side configuration belongs in environment variables. Only values that are safe to publish — API endpoint URLs, publishable SDK keys, feature flags — may ship to the browser.",
    // Serving /config.json is not itself a finding. It is the conventional name
    // for a single-page app's public bootstrap config: API endpoint URLs,
    // feature flags, and publishable client SDK keys (Firebase apiKey,
    // LaunchDarkly client ids, Braze) that are public by design. Flagging every
    // one of those was a High on kraken.com for a file containing exactly that
    // and nothing secret.
    //
    // Require a credential-shaped KEY carrying a non-trivial value — the thing
    // that would actually make the file an exposure.
    validate: (body, ct) => isSecretBearingConfigJson(body, ct),
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
    // SPA catch-all returns text/html — a real .gitignore is plain text
    validate: (body, ct) => !ct.includes("text/html") && (body.includes(".env") || body.includes("secret") || body.includes("*.key") || body.length > 100),
  },
  {
    path: "/server-status",
    servesHtml: true,
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
    description: "A Flash/Silverlight cross-domain policy file allows access from all domains (*). Legacy Flash or PDF plugins can use this to make credentialed cross-origin requests to your application.",
    solution: "Remove crossdomain.xml if Flash is not used. If needed, restrict to specific domains instead of using wildcards.",
    // The mere presence of crossdomain.xml is not a vulnerability — most sites
    // that ship one (including GitHub's, which uses permitted-cross-domain-policies
    // ="master-only") are intentionally restrictive.
    //
    // Fire ONLY on genuine wildcard DATA access: an <allow-access-from domain="*">
    // entry. This finding's description is "access from all domains (*)", and
    // that is the only condition that makes it true.
    //
    // permitted-cross-domain-policies="all" is deliberately NOT a trigger on its
    // own. It is a META-policy — it governs whether sub-path policy files may
    // exist, not who can read data — it is Flash's own default when the element
    // is absent, and a well-scoped master (e.g. nytimes: site-control "all" with
    // every allow-access-from bounded to *.nytimes.com) grants no universal
    // access. Firing on it reported "access from all domains" against a site that
    // allows nothing of the sort — a false positive whose evidence contradicted
    // the target. With Flash EOL since 2020, the sub-policy escalation it permits
    // (which also needs a file-upload primitive and a Flash runtime) does not
    // warrant a medium-severity CORS finding.
    validate: (body) => {
      if (!/<cross-domain-policy/i.test(body)) return false;
      return /<allow-access-from\s+domain\s*=\s*["']\*["']/i.test(body);
    },
  },

  // ── Additional .env variants ──────────────────────────────────────────────
  {
    path: "/.env.development",
    name: "Development Environment File Exposed (.env.development)",
    severity: "high", cweId: "CWE-312", cvssScore: 7.5,
    category: "Credential Exposure",
    description: "A development .env file is publicly accessible, potentially containing database credentials, API keys, and OAuth secrets used in development — which are often reused in staging or production.",
    solution: "Block all .env* files at the web server. Nginx: `location ~ /\\.env { deny all; }`. Never deploy .env files to the web root.",
    validate: (body) => !/<html|<!DOCTYPE/i.test(body.slice(0, 200)) && /^[A-Za-z_]\w*\s*=.+/m.test(body),
  },
  {
    path: "/.env.dev",
    name: "Dev Environment File Exposed (.env.dev)",
    severity: "high", cweId: "CWE-312", cvssScore: 7.5,
    category: "Credential Exposure",
    description: "A .env.dev file is publicly accessible, potentially containing developer credentials and service keys.",
    solution: "Block all .env* files at the web server and remove them from the web root.",
    validate: (body) => !/<html|<!DOCTYPE/i.test(body.slice(0, 200)) && /^[A-Za-z_]\w*\s*=.+/m.test(body),
  },
  {
    path: "/.env.development.local",
    name: "Local Development Overrides Exposed (.env.development.local)",
    severity: "high", cweId: "CWE-312", cvssScore: 7.5,
    category: "Credential Exposure",
    description: ".env.development.local is gitignored by default and contains developer-specific overrides, frequently with real third-party API credentials and database passwords.",
    solution: "Block all .env* files at the web server. This file should never be deployed.",
    validate: (body) => !/<html|<!DOCTYPE/i.test(body.slice(0, 200)) && /^[A-Za-z_]\w*\s*=.+/m.test(body),
  },
  {
    path: "/.env.test",
    name: "Test Environment File Exposed (.env.test)",
    severity: "medium", cweId: "CWE-312", cvssScore: 5.3,
    category: "Credential Exposure",
    description: "A test .env file is accessible. Test environments frequently share credentials with staging or contain real third-party API keys for integration tests.",
    solution: "Block all .env* files at the web server.",
    validate: (body) => !/<html|<!DOCTYPE/i.test(body.slice(0, 200)) && /^[A-Za-z_]\w*\s*=.+/m.test(body),
  },

  // ── CI/CD pipeline configurations ─────────────────────────────────────────
  {
    path: "/.travis.yml",
    name: "Travis CI Configuration Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: ".travis.yml is publicly accessible. CI configuration files reveal deployment scripts, environment variable names (and sometimes values), server addresses, and the complete build and deployment pipeline. Attackers use this to plan targeted attacks on your infrastructure.",
    solution: "Block CI config files at the web server or ensure they are not placed in the web root. Never hardcode secrets in CI configs — use the CI provider's encrypted secrets/variables feature.",
    // YAML CI files must not return text/html — that's an SPA catch-all serving index.html
    validate: (body, ct) => !ct.includes("text/html") && /language:|script:|deploy:|env:|install:/i.test(body),
  },
  {
    path: "/.circleci/config.yml",
    name: "CircleCI Configuration Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "A CircleCI configuration file is publicly accessible, revealing the full build, test, and deployment pipeline including any environment variable references.",
    solution: "Block the .circleci directory at the web server. Store all secrets in CircleCI's project environment variables, not in the config file.",
    validate: (body, ct) => !ct.includes("text/html") && /version:|jobs:|steps:|workflows:|orbs:/i.test(body),
  },
  {
    path: "/Jenkinsfile",
    name: "Jenkinsfile CI/CD Configuration Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "A Jenkinsfile is publicly accessible. Jenkins pipeline scripts often contain deployment targets, server addresses, credential references, and the complete build and release process.",
    solution: "Block Jenkinsfile at the web server. Use Jenkins credentials store for all secrets, never inline them in the Jenkinsfile.",
    validate: (body, ct) => !ct.includes("text/html") && /pipeline|stage|steps|agent|environment|credentials/i.test(body),
  },
  {
    path: "/.gitlab-ci.yml",
    name: "GitLab CI/CD Configuration Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: ".gitlab-ci.yml is publicly accessible, revealing build stages, deployment scripts, Docker image references, and environment variable names used in the pipeline.",
    solution: "Block .gitlab-ci.yml at the web server. All secrets should use GitLab CI/CD variables, not inline values.",
    // SPA apps return text/html for every route — only flag when genuine YAML content is returned
    validate: (body, ct) => !ct.includes("text/html") && /stages:|script:|deploy:|image:|variables:/i.test(body),
  },
  {
    path: "/.drone.yml",
    name: "Drone CI Configuration Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "A Drone CI configuration file is publicly accessible, revealing pipeline steps and deployment configuration.",
    solution: "Block CI config files at the web server.",
    validate: (body, ct) => !ct.includes("text/html") && /kind:|steps:|name:|image:|commands:/i.test(body),
  },

];
