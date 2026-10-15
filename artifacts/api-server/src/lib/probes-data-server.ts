import type { SensitivePath } from "./probes-data";
import { isOpenApiSpec } from "./apiDocsProbe";

/** WordPress, Actuator extras, Apache and Nginx diagnostics, Java/JEE, IDE files, generic config and API doc variants. */
export const SENSITIVE_PATHS_SERVER: SensitivePath[] = [
  // ── WordPress ─────────────────────────────────────────────────────────────
  {
    path: "/xmlrpc.php",
    name: "WordPress XML-RPC Enabled — Brute Force Amplification Vector",
    severity: "medium", cweId: "CWE-307", cvssScore: 7.5,
    category: "Brute Force Protection",
    description: "WordPress XML-RPC (xmlrpc.php) is accessible. The system.multicall method allows attackers to test thousands of username/password combinations in a single HTTP request, making brute-force attacks up to 1000× more efficient than targeting /wp-login.php directly. It's also used for DDoS amplification.",
    solution: "Disable XML-RPC if not needed (most sites don't need it): add `add_filter('xmlrpc_enabled', '__return_false');` to functions.php, or block it at the web server: `location = /xmlrpc.php { deny all; return 403; }`",
    validate: (body) => /xml version|xmlrpc|<methodResponse|<fault>/i.test(body),
  },

  // ── Spring Boot additional Actuator endpoints ─────────────────────────────
  {
    path: "/actuator/heapdump",
    name: "Spring Boot Heap Dump Endpoint Exposed — Full Memory Snapshot",
    severity: "critical", cweId: "CWE-200", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "The Spring Boot Actuator /heapdump endpoint is publicly accessible. This endpoint downloads a complete snapshot of the JVM heap memory, which contains ALL in-memory application data: database passwords, API keys, session tokens, decrypted secrets, user PII, and any other data the application has processed. An attacker can extract secrets directly from the heap dump using tools like Eclipse Memory Analyzer.",
    solution: "Restrict all Actuator endpoints immediately: `management.endpoints.web.exposure.include=health`. If heapdump is needed for debugging, restrict it to localhost or require authentication.",
    // A heap dump starts with its HPROF header, "JAVA PROFILE 1.0.x". A content type of octet-stream proves nothing: servers send it for any path.
    validate: (body) => /^JAVA PROFILE 1\.0/.test(body),
  },
  {
    path: "/actuator/loggers",
    name: "Spring Boot Loggers Endpoint Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "The Spring Boot Actuator /loggers endpoint is accessible. Attackers can use this to increase log verbosity (e.g. enabling DEBUG) to extract sensitive data from logs, or to identify internal package structures.",
    solution: "Restrict Actuator endpoints to authenticated users or internal network only.",
    validate: (body) => /"loggers"|"levels"|"configuredLevel"/.test(body.slice(0, 1000)),
  },
  {
    path: "/actuator/metrics",
    name: "Spring Boot Metrics Endpoint Exposed",
    severity: "low", cweId: "CWE-200",
    category: "Information Disclosure",
    description: "The Spring Boot Actuator /metrics endpoint reveals application performance counters, JVM statistics, and system resource usage. This aids attackers in understanding the application's technology stack and identifying attack windows.",
    solution: "Restrict all Actuator endpoints. Expose only /health publicly if needed.",
    validate: (body) => /"names"|"measurements"|"availableTags"/.test(body.slice(0, 1000)),
  },

  // ── Apache password / access control ─────────────────────────────────────
  {
    path: "/.htpasswd",
    name: "Apache .htpasswd Password File Exposed",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.1,
    category: "Credential Exposure",
    description: ".htpasswd is publicly accessible. This file contains usernames and hashed passwords used for HTTP Basic Authentication. The hashes (MD5-APR, bcrypt, SHA1) can be cracked offline with tools like hashcat or John the Ripper.",
    solution: "Remove .htpasswd from the web root. Configure Apache to block access to .ht* files (this is the default but can be accidentally overridden): `<Files ~ '^\\.ht'> Deny from all </Files>`",
    validate: (body) => /^[a-zA-Z0-9._-]+:\$apr1\$|^[a-zA-Z0-9._-]+:\{SHA\}|^[a-zA-Z0-9._-]+:[a-zA-Z0-9./]{13}/m.test(body),
  },

  // ── Apache / Nginx diagnostics ────────────────────────────────────────────
  {
    path: "/server-info",
    servesHtml: true,
    name: "Apache Server Info Page Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "Apache's /server-info page is accessible, revealing all loaded modules, configuration directives, virtual host settings, and compile-time options. This provides attackers a detailed map of the server configuration to find exploitable settings.",
    solution: "Disable mod_info or restrict to localhost: `<Location /server-info> Require local </Location>`",
    // mod_info's own heading, or its module listing ("Module Name:" entries)
    // together with its "Server Settings" section. "Server Settings" alone
    // matched game-server and bot dashboards that use the same route.
    validate: (body) => /Apache Server Information/i.test(body) || (/Server Settings/i.test(body) && /Module Name:/i.test(body)),
  },
  {
    path: "/nginx_status",
    name: "Nginx Status Page Exposed",
    severity: "low", cweId: "CWE-200",
    category: "Information Disclosure",
    description: "The Nginx stub_status page is accessible, showing active connections, total requests, and server state. While low severity on its own, it confirms the server is Nginx and reveals traffic patterns.",
    solution: "Restrict nginx_status to localhost: `allow 127.0.0.1; deny all;`",
    validate: (body) => /Active connections:|Reading:|Writing:|Waiting:|server accepts handled requests/i.test(body),
  },

  // ── Java / JEE ────────────────────────────────────────────────────────────
  {
    path: "/WEB-INF/web.xml",
    name: "Java Web Application Config (WEB-INF/web.xml) Exposed",
    severity: "high", cweId: "CWE-200", cvssScore: 7.5,
    category: "Information Disclosure",
    description: "The Java web application deployment descriptor (web.xml) is accessible. This file maps servlets, defines security constraints, lists initialization parameters, and may contain database JNDI references or other configuration that helps attackers understand the application structure.",
    solution: "Web servers should block direct access to WEB-INF by default. Verify your web server or servlet container is not misconfigured to serve this directory directly.",
    validate: (body) => /<web-app|<servlet|<filter|<context-param/i.test(body),
  },
  {
    path: "/WEB-INF/classes/application.properties",
    name: "Spring Application Properties Exposed (WEB-INF/classes/application.properties)",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "The Spring Boot application.properties file is publicly accessible. This file contains datasource URLs with credentials, JWT secrets, API keys, mail server passwords, and all other application configuration.",
    solution: "Block the WEB-INF directory at your web server. Spring properties files must not be directly accessible from the web.",
    validate: (body) => /spring\.|datasource\.|server\.port|jwt\.|mail\.|security\./i.test(body),
  },

  // ── IDE configuration files ───────────────────────────────────────────────
  {
    path: "/.vscode/settings.json",
    name: "VS Code Workspace Settings Exposed",
    severity: "low", cweId: "CWE-200",
    category: "Information Disclosure",
    description: ".vscode/settings.json is accessible. While usually benign, editor settings can reveal database connection strings, local server addresses, plugin configurations, and file paths that help attackers understand the development environment.",
    solution: "Block .vscode at the web server. IDE config files should be in .gitignore and never deployed.",
    validate: (body, ct) => (ct.includes("json") || body.trim().startsWith("{")) && body.length > 20,
  },
  {
    path: "/.idea/workspace.xml",
    name: "JetBrains IDE Workspace Config Exposed",
    severity: "low", cweId: "CWE-200",
    category: "Information Disclosure",
    description: ".idea/workspace.xml contains JetBrains IDE workspace configuration, run configurations, data source settings (which may include database credentials), and local file paths.",
    solution: "Block the .idea directory at the web server. Add it to .gitignore.",
    validate: (body) => /<project|<component name=|<configuration/i.test(body),
  },

  // ── Generic config files ──────────────────────────────────────────────────
  {
    path: "/config.yaml",
    name: "YAML Configuration File Exposed (config.yaml)",
    severity: "high", cweId: "CWE-200", cvssScore: 7.5,
    category: "Information Disclosure",
    description: "A YAML configuration file is publicly accessible. YAML configs commonly contain database connection strings, API keys, service passwords, and internal endpoint URLs.",
    solution: "Remove config.yaml from the web root. Use environment variables for sensitive configuration.",
    validate: (body, ct) => (ct.includes("yaml") || /^[a-z_]+:/m.test(body)) && !ct.includes("text/html"),
  },
  {
    path: "/config.yml",
    name: "YAML Configuration File Exposed (config.yml)",
    severity: "high", cweId: "CWE-200", cvssScore: 7.5,
    category: "Information Disclosure",
    description: "A YAML configuration file is publicly accessible, potentially containing service credentials and infrastructure details.",
    solution: "Remove config.yml from the web root and use environment variables for sensitive values.",
    validate: (body, ct) => (ct.includes("yaml") || /^[a-z_]+:/m.test(body)) && !ct.includes("text/html"),
  },
  {
    path: "/app.yaml",
    name: "Google App Engine Configuration Exposed (app.yaml)",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "app.yaml is accessible. Google App Engine config files define runtime settings, environment variables, and service routing. Environment variable sections may contain API keys and credentials.",
    solution: "Block app.yaml at the web server. Use GCP Secret Manager for credentials.",
    validate: (body) => /runtime:|handlers:|env_variables:|service:|instance_class:/i.test(body),
  },

  // Severity matches apiDocsProbe: a published spec is a map of the API, not a vulnerability.
  // ── Additional API doc variants ────────────────────────────────────────────
  {
    path: "/api/swagger.json",
    name: "API Documentation Exposed (/api/swagger.json)",
    severity: "info", cweId: "CWE-200", cvssScore: 0,
    category: "Information Disclosure",
    description: "Swagger API documentation is exposed at /api/swagger.json, providing a full blueprint of API endpoints, parameters, authentication schemes, and data models.",
    solution: "Require authentication to access API documentation in production.",
    validate: (body) => isOpenApiSpec(body),
  },
  {
    path: "/api/v1/swagger.json",
    name: "API v1 Documentation Exposed",
    severity: "info", cweId: "CWE-200", cvssScore: 0,
    category: "Information Disclosure",
    description: "API v1 Swagger documentation is publicly accessible, exposing the complete API surface for version 1.",
    solution: "Require authentication for API docs in production.",
    validate: (body) => isOpenApiSpec(body),
  },
  {
    path: "/api/v2/swagger.json",
    name: "API v2 Documentation Exposed",
    severity: "info", cweId: "CWE-200", cvssScore: 0,
    category: "Information Disclosure",
    description: "API v2 Swagger documentation is publicly accessible.",
    solution: "Require authentication for API docs in production.",
    validate: (body) => isOpenApiSpec(body),
  },
];
