import type { SensitivePath } from "./probes-data";

/** Version control, environment files, CMS configs, database backups, API docs and Spring Boot Actuator. */
export const SENSITIVE_PATHS_VCS_ENV_CMS: SensitivePath[] = [
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
    // Require at least one KEY=value line AND no HTML content regardless of
    // content-type — servers that return soft-404 HTML pages as text/plain were
    // previously passing this check due to the !ct.includes("text/html") short-circuit.
    validate: (body) => !/<html|<!DOCTYPE/i.test(body.slice(0, 200)) && /^[A-Za-z_]\w*\s*=.+/m.test(body),
  },
  {
    path: "/.env.local",
    name: "Environment File Exposed (.env.local)",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: ".env.local is publicly accessible. This override file often contains developer or staging credentials.",
    solution: "Block all .env* files at the web server and rotate any exposed credentials.",
    validate: (body) => !/<html|<!DOCTYPE/i.test(body.slice(0, 200)) && /^[A-Za-z_]\w*\s*=.+/m.test(body),
  },
  {
    path: "/.env.production",
    name: "Production Environment File Exposed (.env.production)",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.8,
    category: "Credential Exposure",
    description: "The production .env file is publicly accessible, exposing live database credentials, payment keys, and all production secrets.",
    solution: "Block all .env* files immediately and rotate all exposed production credentials.",
    validate: (body) => !/<html|<!DOCTYPE/i.test(body.slice(0, 200)) && /^[A-Za-z_]\w*\s*=.+/m.test(body),
  },
  {
    path: "/.env.backup",
    name: "Backup Environment File Exposed",
    severity: "critical", cweId: "CWE-312", cvssScore: 9.1,
    category: "Credential Exposure",
    description: "A backup of the environment config is publicly accessible.",
    solution: "Delete .env backups from the server. Block all .env* files.",
    validate: (body) => !/<html|<!DOCTYPE/i.test(body.slice(0, 200)) && /^[A-Za-z_]\w*\s*=.+/m.test(body),
  },
  {
    path: "/.env.staging",
    name: "Staging Environment File Exposed",
    severity: "high", cweId: "CWE-312", cvssScore: 8.2,
    category: "Credential Exposure",
    description: "Staging environment configuration is publicly accessible, which often shares similar credentials to production.",
    solution: "Block all .env* files at the web server.",
    validate: (body) => !/<html|<!DOCTYPE/i.test(body.slice(0, 200)) && /^[A-Za-z_]\w*\s*=.+/m.test(body),
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
    servesHtml: true,
    name: "PHP Info Page Exposed",
    severity: "high", cweId: "CWE-200", cvssScore: 7.5,
    category: "Information Disclosure",
    description: "A phpinfo() page is accessible. This reveals PHP version, all loaded modules, server paths, environment variables (including $_ENV secrets), and configuration values—a complete reconnaissance package for attackers.",
    solution: "Delete phpinfo.php from production. Never deploy debug scripts to production servers.",
    validate: (body) => /phpinfo\(\)|PHP Version|<title>phpinfo\(\)/i.test(body),
  },
  {
    path: "/info.php",
    servesHtml: true,
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
    // The file's own signature, not its content type: a server answers any path with octet-stream or a text page. A zip begins
    // "PK" (local header 0x03 0x04, or an empty archive's end record 0x05 0x06).
    validate: (body) => /^PK(?:\x03\x04|\x05\x06)/.test(body),
  },
  {
    path: "/backup.tar.gz",
    name: "Backup Archive Exposed (.tar.gz)",
    severity: "critical", cweId: "CWE-552", cvssScore: 9.1,
    category: "Source Code Exposure",
    description: "A tar.gz backup archive is publicly downloadable.",
    solution: "Remove backup archives from the web root.",
    // A gzip stream begins 0x1f 0x8b. Bodies are decoded as UTF-8, where the 0x8b byte (not valid on its own) arrives as U+FFFD.
    validate: (body) => /^\x1f(?:\x8b|�)/.test(body),
  },

  // ── API documentation ─────────────────────────────────────────────────────
  // NOTE: generic /swagger.json, /openapi.json, /swagger-ui.html, /api-docs, and
  // /graphql entries were removed from here — they duplicated (with much weaker
  // validation) the dedicated apiDocsProbe.ts and graphqlProbe.ts modules, which
  // confirm actual OpenAPI/Swagger-UI/GraphQL structure instead of matching on
  // the mere presence of a keyword. See runAllProbes() in scanner.ts.

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

  // ── Tool and package-manager config that often holds a token ─────────────
  {
    path: "/.npmrc",
    name: ".npmrc Exposed (may hold a registry token)",
    severity: "high", cweId: "CWE-522", cvssScore: 7.5,
    category: "Credential Exposure",
    description: "The npm configuration file is publicly readable. It often holds a registry auth token or a password for a private package registry, which lets anyone publish or download under that account.",
    solution: "Delete the file from the web root and block dotfiles at the web server. Rotate any token it contains, and keep auth tokens in environment variables, not in .npmrc.",
    validate: (body) => /^\s*(?:registry\s*=|\/\/[^\s]+:_(?:auth|authToken|password)\s*=|_authToken\s*=|_auth\s*=)/m.test(body),
  },
  {
    path: "/.mcp.json",
    name: "MCP Server Configuration Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "An MCP server configuration is publicly readable. These files list the tools a project connects to and often carry the credentials they use in their environment blocks.",
    solution: "Remove the file from the web root. Keep MCP credentials in the environment of the process that starts the server, not in a committed or deployed JSON file.",
    validate: (body) => /"mcpServers"\s*:\s*\{/.test(body),
  },
  {
    path: "/.claude/settings.json",
    name: "Claude Code Settings Exposed",
    severity: "medium", cweId: "CWE-200", cvssScore: 5.3,
    category: "Information Disclosure",
    description: "A Claude Code settings file is publicly readable. These files can list the project's permissions, hooks and environment variables, and environment entries sometimes hold tokens.",
    solution: "Remove the .claude directory from the web root. Keep local settings out of the deployed build, and move any token in them into the environment.",
    validate: (body) => /"(?:permissions|hooks|env|mcpServers)"\s*:/.test(body),
  },

];
