/**
 * The benchmark's ground truth: every fault planted in artifacts/vuln-fixture,
 * described in scanner-neutral terms, with a matcher per scanner.
 *
 * WHY THIS FILE IS THE WHOLE BENCHMARK
 *
 * Any vendor can run a competitor's scanner badly and publish the score. The
 * only thing separating an honest benchmark from a rigged one is whether the
 * mapping from "a tool said something" to "the tool found this fault" is
 * written down and checkable. So it lives here, in one file, and the report
 * prints the exact text that satisfied each matcher — not just a tick.
 *
 * MATCHING RULE: be generous to the other tools.
 *
 * Each matcher runs against a haystack built from everything the tool said
 * about a finding — its name, description, evidence, template id, tags,
 * whatever the format carries. Where a tool reports something broader than the
 * planted fault ("CSP header issues" against a specific missing directive), it
 * is credited. When in doubt, credit the other tool. A benchmark that has to
 * be read carefully to be believed is worth nothing.
 *
 * WHAT A BLANK ROW DOES NOT MEAN
 *
 * A tool not reporting an item is NOT evidence that it looked and missed. Most
 * often it means the tool has no check for that class at all — ZAP is a proxy
 * and active-scan engine, Nuclei is a template matcher, SecScan is an external
 * posture scanner, and the three overlap only partly. The report therefore also
 * lists, for every tool, what it found that is NOT in this file. That list is
 * the honest counterweight to the score, and on this fixture it is expected to
 * contain things SecScan does not check for at all.
 *
 * THE BIGGEST CAVEAT, STATED ONCE AND LOUDLY
 *
 * This fixture was built to contain the faults SecScan checks for. It is
 * SecScan's own checklist made executable. That makes it an excellent
 * instrument for measuring SecScan's false negatives — its actual purpose — and
 * an inherently favourable test for SecScan in any comparison. Read the
 * detection rates with that in mind. The per-tool "found, not in ground truth"
 * lists exist precisely because they are the part this bias does not touch.
 */

export interface GroundTruthItem {
  id: string;
  label: string;
  category: string;
  /** Matches SecScan's own finding names. Mirrors verify-vuln-fixture.ts. */
  secscan: RegExp;
  /** Matches ZAP alert name + description + evidence + otherinfo. */
  zap: RegExp | null;
  /** Matches Nuclei template-id + name + tags + matched-at. */
  nuclei: RegExp | null;
  /**
   * Set when the fault is only reachable with something the tool was not
   * given (credentials, an OpenAPI spec, an out-of-band collector). Recorded
   * so the report can separate "did not find it" from "was not equipped to".
   */
  needs?: string;
}

const H = "Headers & policy";
const D = "Exposed files & endpoints";
const S = "Secrets";
const I = "Injection";
const A = "Authorisation & API";
const V = "Versions";

export const GROUND_TRUTH: GroundTruthItem[] = [
  // ── Headers, policy, cookies ────────────────────────────────────────────
  { id: "csp-wildcard", label: "CSP script-src contains a wildcard", category: H,
    secscan: /CSP script-src Contains Wildcard/i,
    zap: /content.?security.?policy|\bCSP\b/i, nuclei: /csp|content-security/i },
  { id: "csp-weak", label: "Weak CSP (unsafe-inline / unsafe-eval)", category: H,
    secscan: /Weak Content-Security-Policy/i,
    zap: /unsafe.?(inline|eval)|content.?security.?policy/i, nuclei: /csp|content-security/i },
  { id: "csp-object-src", label: "CSP missing object-src", category: H,
    secscan: /object-src/i, zap: /object-src|content.?security.?policy/i, nuclei: null },
  { id: "csp-base-uri", label: "CSP missing base-uri", category: H,
    secscan: /base-uri/i, zap: /base-uri|content.?security.?policy/i, nuclei: null },
  { id: "xcto", label: "Missing X-Content-Type-Options", category: H,
    secscan: /X-Content-Type-Options/i, zap: /x-content-type-options|content.?type.?options/i, nuclei: /x-content-type/i },
  { id: "referrer-policy", label: "Missing Referrer-Policy", category: H,
    secscan: /Referrer-Policy Header/i, zap: /referrer.?policy/i, nuclei: /referrer-policy/i },
  { id: "permissions-policy", label: "Missing Permissions-Policy", category: H,
    secscan: /Permissions-Policy Header/i, zap: /permissions.?policy|feature.?policy/i, nuclei: /permissions-policy/i },
  { id: "coop-coep-corp", label: "Missing COOP / COEP / CORP", category: H,
    secscan: /Cross-Origin-(Opener|Embedder|Resource)-Policy/i,
    zap: /cross.?origin.?(opener|embedder|resource)/i, nuclei: /cross-origin/i },
  { id: "cors-wildcard", label: "Wildcard CORS policy (passive)", category: H,
    secscan: /Permissive CORS Policy/i, zap: /cors|cross.?domain.?misconfigur/i, nuclei: /cors/i },
  { id: "cookie-flags", label: "Session cookie missing Secure / HttpOnly / SameSite", category: H,
    secscan: /Session Cookie Missing|Cookie Missing SameSite/i,
    zap: /cookie.*(httponly|secure|samesite)|(httponly|samesite).*cookie/i, nuclei: /cookie/i },
  { id: "csp-inner-route", label: "CSP missing on an internal route", category: H,
    secscan: /Content-Security-Policy Missing on.*Internal Route/i,
    zap: /content.?security.?policy/i, nuclei: /csp|content-security/i },

  // ── Version disclosure and EOL ──────────────────────────────────────────
  { id: "server-version", label: "Server version disclosed", category: V,
    secscan: /Server Version Disclosure/i, zap: /server.?leaks|version.*(header|disclos)|x-powered/i,
    nuclei: /nginx|version|tech-detect/i },
  { id: "x-powered-by", label: "X-Powered-By disclosed", category: V,
    secscan: /X-Powered-By/i, zap: /x-powered-by|server.?leaks/i, nuclei: /x-powered-by|tech-detect/i },
  { id: "nginx-eol", label: "Nginx version is EOL / has a known CVE", category: V,
    secscan: /Nginx.*(?:CVE|End-of-Life)/i, zap: null, nuclei: /nginx.*cve|cve-.*nginx/i },
  { id: "php-eol", label: "PHP version is End-of-Life", category: V,
    secscan: /PHP .* is End-of-Life/i, zap: null, nuclei: /php.*eol/i },

  // ── Active HTTP behaviour ───────────────────────────────────────────────
  { id: "cors-credentials", label: "CORS allows credentials from an arbitrary origin", category: H,
    secscan: /CORS Misconfiguration . Credentials Allowed/i,
    zap: /cors|allow.?credentials/i, nuclei: /cors/i },
  { id: "write-methods", label: "Write HTTP methods advertised", category: D,
    secscan: /Write HTTP Methods Advertised/i, zap: /allow.*(put|delete)|http method/i, nuclei: /http-method|put-method/i },
  { id: "trace", label: "TRACE method enabled", category: D,
    secscan: /TRACE Method Enabled/i, zap: /trace/i, nuclei: /trace/i },
  { id: "connect", label: "CONNECT method enabled", category: D,
    secscan: /CONNECT Method Enabled/i, zap: /connect method/i, nuclei: /connect/i },
  { id: "open-redirect", label: "Open redirect", category: I,
    secscan: /Open Redirect Vulnerability/i, zap: /open.?redirect|external.?redirect/i, nuclei: /open-redirect|redirect/i },
  { id: "robots-sensitive", label: "robots.txt discloses sensitive paths", category: D,
    secscan: /robots\.txt Discloses/i, zap: /robots\.txt/i, nuclei: /robots/i },
  { id: "sri", label: "Missing Subresource Integrity", category: H,
    secscan: /Subresource Integrity/i, zap: /sub.?resource.?integrity|integrity attribute/i, nuclei: null },
  { id: "werkzeug", label: "Werkzeug interactive debugger exposed", category: D,
    secscan: /Werkzeug Interactive Debugger/i, zap: /werkzeug|debugger/i, nuclei: /werkzeug|flask.*debug|debug.*console/i },
  { id: "dir-listing", label: "Directory listing enabled", category: D,
    secscan: /Directory Listing Enabled/i, zap: /directory.?browsing|directory listing/i, nuclei: /directory-listing|dir-listing/i },
  { id: "security-txt", label: "Missing security.txt", category: D,
    secscan: /Missing security\.txt/i, zap: /security\.txt/i, nuclei: /security-txt/i },

  // ── Deserialization markers (cookies on an inner route) ─────────────────
  { id: "deser-java", label: "Java serialized object in a cookie", category: I,
    secscan: /Insecure Deserialization.*Java object|Java Serialized Object/i, zap: /serializ|deserial/i, nuclei: /deserial|serializ/i },
  { id: "deser-ruby", label: "Ruby Marshal object in a cookie", category: I,
    secscan: /Ruby Marshal/i, zap: /marshal/i, nuclei: /deserial|marshal/i },
  { id: "deser-python", label: "Python pickle object in a cookie", category: I,
    secscan: /Python Pickle/i, zap: /pickle/i, nuclei: /deserial|pickle/i },
  { id: "deser-php", label: "PHP serialized object in a cookie", category: I,
    secscan: /PHP Serialized Object/i, zap: /php.*(serializ|object)/i, nuclei: /php-serial/i },

  // ── Exposed files on an inner route ─────────────────────────────────────
  { id: "inner-env", label: ".env exposed on an inner route", category: D,
    secscan: /\.env/i, zap: /\.env|environment file/i, nuclei: /\.env|dotenv|env-file/i },
  { id: "inner-git", label: "git metadata exposed on an inner route", category: D,
    secscan: /\.git/i, zap: /\.git/i, nuclei: /git-config|\.git|git-exposed/i },
  { id: "inner-config", label: "config file exposed on an inner route", category: D,
    //  so "Misconfiguration" does not count as finding a config FILE.
    secscan: /config(uration)?\s*file|config\.(json|yml|yaml|php|ini)/i,
    zap: /config(uration)?\s*file|config\.(json|yml|yaml|php|ini)/i,
    nuclei: /config-file|config\.(json|yml|yaml|php|ini)/i },
  { id: "inner-apidocs", label: "API docs exposed on an inner route", category: D,
    secscan: /API Documentation|Swagger|OpenAPI/i, zap: /swagger|openapi|api.?doc/i, nuclei: /swagger|openapi|api-doc/i },
  { id: "inner-debuglog", label: "debug.log exposed on an inner route", category: D,
    secscan: /debug\.log|Debug Log/i, zap: /debug.?log|log file/i, nuclei: /debug.?log|log-file/i },
  { id: "inner-graphql", label: "GraphQL endpoint exposed on an inner route", category: D,
    secscan: /GraphQL/i, zap: /graphql/i, nuclei: /graphql/i },

  // ── Exposed files at root ───────────────────────────────────────────────
  { id: "root-env", label: ".env exposed at root", category: D,
    secscan: /\.env/i, zap: /\.env|environment file/i, nuclei: /\.env|dotenv|env-file/i },
  { id: "wp-config", label: "wp-config.php exposed", category: D,
    secscan: /wp-config/i, zap: /wp-config|wordpress/i, nuclei: /wp-config|wordpress/i },
  { id: "id-rsa", label: "Private SSH key (id_rsa) exposed", category: S,
    secscan: /id_rsa|SSH Private Key/i, zap: /id_rsa|private key/i, nuclei: /id_rsa|ssh.*key|private-key/i },
  { id: "root-git", label: "git repository exposed at root", category: D,
    secscan: /\.git/i, zap: /\.git/i, nuclei: /git-config|\.git|git-exposed/i },
  { id: "terraform-state", label: "Terraform state file exposed", category: D,
    secscan: /terraform/i, zap: /terraform|tfstate/i, nuclei: /terraform|tfstate/i },
  { id: "actuator-env", label: "Spring actuator/env exposed", category: D,
    secscan: /actuator/i, zap: /actuator|spring/i, nuclei: /actuator|spring/i },
  { id: "phpmyadmin", label: "phpMyAdmin exposed", category: D,
    secscan: /phpMyAdmin/i, zap: /phpmyadmin/i, nuclei: /phpmyadmin/i },
  { id: "crossdomain", label: "crossdomain.xml with a wildcard", category: D,
    secscan: /crossdomain/i, zap: /cross.?domain|crossdomain/i, nuclei: /crossdomain/i },
  { id: "xmlrpc", label: "xmlrpc.php enabled", category: D,
    secscan: /xmlrpc/i, zap: /xmlrpc/i, nuclei: /xmlrpc/i },
  { id: "htpasswd", label: ".htpasswd exposed", category: S,
    secscan: /htpasswd/i, zap: /htpasswd/i, nuclei: /htpasswd/i },
  { id: "backup-archive", label: "Backup archive exposed", category: D,
    secscan: /Backup|\.bak|\.zip|\.tar/i, zap: /backup|\.bak\b/i, nuclei: /backup/i },

  // ── Secrets in JavaScript ───────────────────────────────────────────────
  { id: "js-aws", label: "AWS access key in JavaScript", category: S,
    secscan: /AWS Access Key/i, zap: /aws|access key|akia/i, nuclei: /aws.*key|akia|aws-access/i },
  { id: "js-stripe", label: "Stripe live key in JavaScript", category: S,
    secscan: /Stripe/i, zap: /stripe|sk_live/i, nuclei: /stripe/i },
  { id: "js-github-pat", label: "GitHub personal access token in JavaScript", category: S,
    secscan: /GitHub (Personal Access )?Token/i, zap: /github|ghp_/i, nuclei: /github.*token|ghp_/i },
  { id: "js-db-conn", label: "Database connection string in JavaScript", category: S,
    secscan: /Database Connection String|Connection String/i, zap: /connection string|mongodb:\/\/|postgres:\/\//i,
    nuclei: /connection.?string|mongodb|postgres/i },
  { id: "js-jwt", label: "Hardcoded JWT in JavaScript", category: S,
    secscan: /JWT/i, zap: /jwt|json web token/i, nuclei: /jwt/i },
  { id: "js-private-key", label: "Private key in JavaScript", category: S,
    secscan: /Private Key/i, zap: /private key|begin rsa/i, nuclei: /private-key|begin.*private/i },

  // ── Secrets in __NEXT_DATA__ ────────────────────────────────────────────
  { id: "next-stripe", label: "Stripe key in __NEXT_DATA__", category: S,
    secscan: /Stripe/i, zap: /stripe|sk_live/i, nuclei: /stripe/i },
  { id: "next-aws", label: "AWS key in __NEXT_DATA__", category: S,
    secscan: /AWS/i, zap: /aws|akia/i, nuclei: /aws|akia/i },
  { id: "next-db", label: "DB connection string in __NEXT_DATA__", category: S,
    secscan: /Connection String/i, zap: /connection string|postgres:\/\/|mongodb:\/\//i, nuclei: /connection.?string/i },

  // ── JWT analysis ────────────────────────────────────────────────────────
  { id: "jwt-alg-none", label: "JWT with alg:none accepted", category: A,
    secscan: /alg.*none|None Algorithm/i, zap: /alg.*none/i, nuclei: null },
  { id: "jwt-no-expiry", label: "JWT without an expiry claim", category: A,
    secscan: /No Expiry|Without Expiration/i, zap: /jwt.*expir/i, nuclei: null },
  { id: "jwt-long-life", label: "JWT with an excessive lifetime", category: A,
    secscan: /Lifetime.*Excessive|Excessive.*Lifetime|Long.?Lived/i, zap: /jwt.*(lifetime|expir)/i, nuclei: null },
  { id: "jwt-sensitive", label: "Sensitive data in a JWT payload", category: S,
    secscan: /Sensitive.*JWT|JWT.*Sensitive/i, zap: /jwt.*(sensitive|payload)/i, nuclei: null },

  // ── Source maps, specs, GraphQL ─────────────────────────────────────────
  { id: "source-map", label: "Source map exposed with sourcesContent", category: D,
    secscan: /Source Map/i, zap: /source.?map|\.js\.map/i, nuclei: /source.?map|js-map/i },
  { id: "openapi-spec", label: "OpenAPI specification exposed", category: D,
    secscan: /OpenAPI|Swagger/i, zap: /openapi|swagger/i, nuclei: /openapi|swagger/i },
  { id: "graphql-introspection", label: "GraphQL introspection enabled", category: D,
    secscan: /Introspection/i, zap: /graphql.*introspect|introspect/i, nuclei: /graphql.*introspect|introspect/i },
  { id: "graphql-suggestions", label: "GraphQL field suggestions leak", category: D,
    secscan: /Field Suggestion/i, zap: /graphql.*suggest/i, nuclei: /graphql.*suggest/i },

  // ── Injection ───────────────────────────────────────────────────────────
  { id: "xss-reflected", label: "Reflected cross-site scripting", category: I,
    secscan: /Reflected (Cross-Site Scripting|XSS)/i, zap: /cross.?site.?scripting|\bxss\b/i, nuclei: /xss|cross-site-scripting/i },
  { id: "sqli-error", label: "SQL injection (error-based)", category: I,
    secscan: /SQL Injection/i, zap: /sql.?injection/i, nuclei: /sqli|sql-injection/i },
  { id: "path-traversal", label: "Path traversal / local file inclusion", category: I,
    secscan: /Path Traversal|Local File Inclusion/i, zap: /path.?traversal|directory.?traversal|remote file include|local file include/i,
    // "Generic J2EE LFI Scan Panel - Detect" finds a panel, not a traversal.
    nuclei: /(lfi|path-traversal|traversal)(?!.*panel)/i },
  { id: "ssrf-oob", label: "SSRF confirmed by out-of-band callback", category: I,
    secscan: /Server-Side Request Forgery|SSRF/i, zap: /ssrf|server.?side.?request/i, nuclei: /ssrf/i,
    needs: "an out-of-band collector reachable by the target" },

  // ── API authorisation ───────────────────────────────────────────────────
  { id: "api-no-auth", label: "API served without authentication", category: A,
    secscan: /Without Authentication|Missing Authentication/i, zap: /authenticat/i, nuclei: /unauth|auth.?bypass/i,
    needs: "the OpenAPI spec, to know which endpoints should be protected" },
  { id: "api-sensitive-fields", label: "Sensitive fields returned by the API", category: S,
    secscan: /Sensitive.*(Field|Data).*API|API.*Sensitive/i, zap: /sensitive (data|field|information) (expos|disclos|return)/i, nuclei: /sensitive.*(field|data).*(expos|disclos)/i,
    needs: "the OpenAPI spec" },
  { id: "api-bfla", label: "Write endpoint reachable without authorisation (BFLA)", category: A,
    secscan: /Function.?Level|BFLA|Write Endpoint/i, zap: /authoriz|access control/i, nuclei: /auth.?bypass|unauth/i,
    needs: "two authenticated sessions" },
  { id: "api-sqli", label: "SQL injection in a declared API parameter", category: I,
    secscan: /SQL Injection/i, zap: /sql.?injection/i, nuclei: /sqli|sql-injection/i,
    needs: "the OpenAPI spec, to know the parameter exists" },
  { id: "api-cross-account", label: "API records readable by another account", category: A,
    secscan: /Another Account|Cross-Account|IDOR/i, zap: /access control|idor|authoriz/i, nuclei: /idor|auth.?bypass/i,
    needs: "two authenticated sessions" },
  { id: "idor-page", label: "IDOR on a page-level identifier", category: A,
    secscan: /IDOR|Insecure Direct Object/i, zap: /idor|access control|authoriz/i, nuclei: /idor/i,
    needs: "two authenticated sessions" },
  { id: "enumerable-ids", label: "Records enumerable by editing the identifier", category: A,
    secscan: /Enumerab/i, zap: /enumerat|access control/i, nuclei: /enumerat|idor/i,
    needs: "two authenticated sessions" },
];

export const CATEGORIES = [H, V, D, S, I, A];
