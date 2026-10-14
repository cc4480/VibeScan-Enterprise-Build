/**
 * A small set of dangerous code patterns, chosen for precision. This is not a general static analyser: each rule is a
 * shape that is almost always a flaw, so a hit is worth a developer's time. Anything that would need data-flow analysis
 * to judge (is this innerHTML fed by user input?) is deliberately left out; a noisy rule teaches people to ignore the
 * scanner.
 *
 * The first rule is the one the Lovable-style test app planted: a secret given a client-exposed environment prefix
 * (VITE_, NEXT_PUBLIC_...) is compiled into the browser bundle for every visitor.
 */
import { repoFinding, type RepoFile, type RepoRef } from "./repoFinding";
import { isCodePath, isEnvFilePath, type Rule } from "./repoCodePaths";
import { MORE_RULES } from "./repoCodeRules";
import { isPlaceholderToken } from "./secretPlaceholders";
import type { ScanVulnerability } from "./scanner";

export { isCodePath, isEnvFilePath };

/** A client-exposed prefix on a name that says it is a secret. */
const CLIENT_SECRET_NAME =
  /\b((?:VITE|NEXT_PUBLIC|REACT_APP|EXPO_PUBLIC|GATSBY|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE_?KEY|PASSWORD|PASSWD|ADMIN_?(?:KEY|TOKEN)|DB_URL|DATABASE_URL)[A-Z0-9_]*)\b/;
/** The same name, read from the environment: import.meta.env.NAME, process.env.NAME, env["NAME"]. */
const CLIENT_SECRET_READ = new RegExp(String.raw`\benv\s*(?:\.|\[\s*["'])` + CLIENT_SECRET_NAME.source);
/** Names that merely mention the words and are public by design. */
const PUBLIC_BY_DESIGN_NAME = /(?:PUBLISHABLE|ANON|PUBLIC_KEY|CLIENT_ID|SITE_KEY|RECAPTCHA|TURNSTILE|MEASUREMENT|SENTRY_DSN)/i;

const RULES: Rule[] = [
  {
    name: "Secret Exposed Through a Client-Side Environment Prefix",
    test: (path, text) => {
      if (!isCodePath(path) && !isEnvFilePath(path)) return null;
      const m = (isEnvFilePath(path) ? CLIENT_SECRET_NAME : CLIENT_SECRET_READ).exec(text);
      if (!m || PUBLIC_BY_DESIGN_NAME.test(m[1]!)) return null;
      // In an env file the name must carry a value; in code, reading the variable is the flaw. The name inside a
      // string or comment (a scanner's own pattern list, documentation) reads nothing, so it is not one.
      if (isEnvFilePath(path)) {
        const line = new RegExp(`^\\s*${m[1]}\\s*=\\s*["']?([^\\s"']{8,})`, "m").exec(text);
        if (!line || isPlaceholderToken(line[1]!) || /^(?:your|changeme|example|todo|xxx)/i.test(line[1]!)) return null;
      }
      return { detail: `Variable: ${m[1]}` };
    },
    severity: "high", category: "Exposed Secrets / Credentials", cweId: "CWE-540", cvssScore: 8.1, confidence: 80,
    description: "A variable that names a secret (service role key, secret, private key, password) carries a prefix that tells the build tool to compile it into the browser bundle (VITE_, NEXT_PUBLIC_, REACT_APP_...). Every visitor can read its value in the JavaScript the site serves, whatever the repository's visibility. Lovable's own documentation warns against this and it is the most common route for a service_role key to reach a browser.",
    solution: "Remove the prefix and read the value only in server-side code (a server function, an edge function, an API route). Rotate the key: assume it has been served already.",
  },
  {
    name: "eval or new Function on Request Data",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = /\b(?:eval|new\s+Function)\s*\(\s*(?:req|request|ctx\.request|event)\.(?:body|query|params|headers)\b/.exec(text);
      return m ? { detail: `Code: ${m[0]}` } : null;
    },
    severity: "high", category: "Injection", cweId: "CWE-95", cvssScore: 9.0, confidence: 80,
    description: "Request data is passed straight to eval or the Function constructor, which runs it as code on the server. Anyone who can send a request runs their own code with the server's privileges.",
    solution: "Never evaluate request data. Parse it as data (JSON.parse) and use a lookup table or an explicit allow-list for anything dynamic.",
  },
  {
    name: "SQL Built From Request Data by String Interpolation",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = /\.(?:query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\(\s*`[^`]*\b(?:select|insert|update|delete|where)\b[^`]*\$\{\s*(?:req|request)\.(?:body|query|params)/i.exec(text);
      return m ? { detail: `Code: ${m[0].slice(0, 120)}` } : null;
    },
    severity: "high", category: "Injection", cweId: "CWE-89", cvssScore: 8.6, confidence: 75,
    description: "An SQL statement is assembled with a template literal that interpolates request data, so the data becomes part of the SQL. That is SQL injection: a crafted value reads or changes any table the database user can reach.",
    solution: "Use parameter placeholders ($1, ?) and pass the values separately, or the query builder's bound parameters.",
  },
  {
    name: "CORS Allows Any Origin With Credentials",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const reflected = /cors\(\s*\{[^}]*origin\s*:\s*true[^}]*credentials\s*:\s*true|cors\(\s*\{[^}]*credentials\s*:\s*true[^}]*origin\s*:\s*true/is.test(text);
      const star = /Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']/i.test(text) && /Access-Control-Allow-Credentials["']?\s*[,:]\s*["']true["']/i.test(text);
      return reflected || star ? { detail: reflected ? "cors({ origin: true, credentials: true })" : "Access-Control-Allow-Origin: * with Allow-Credentials: true" } : null;
    },
    severity: "medium", category: "Security Misconfiguration", cweId: "CWE-942", cvssScore: 6.5, confidence: 70,
    description: "The server accepts requests from any website and lets them carry the visitor's cookies. A page on another site can then act as the signed-in user and read the responses.",
    solution: "Name the origins that may call the API (an allow-list) when credentials are allowed.",
  },
  {
    name: "TLS Certificate Verification Disabled",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      // The first match in code: the same words in a comment explain the setting, they are not the setting.
      const m = [...text.matchAll(/rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/g)].find((x) => {
        const lineStart = text.lastIndexOf("\n", x.index! - 1) + 1;
        return !/^\s*(?:\/\/|\/\*|\*|#)/.test(text.slice(lineStart, x.index!));
      });
      if (!m) return null;
      // A probe that reads the certificate, or a comment beside the line saying it is on purpose, is not the flaw this
      // rule is about (trusting a server without checking who it is). The comment has to be within a few lines.
      const lines = text.slice(0, m.index).split("\n");
      const near = [...lines.slice(-6), ...text.slice(m.index).split("\n").slice(0, 3)].join("\n");
      const said = /\b(?:deliberate(?:ly)?|intentional(?:ly)?|on purpose|self-signed|observed,? not trusted|cert(?:ificate)? is (?:observed|inspected|being (?:read|checked)))\b|getPeerCertificate/i.exec(near);
      return { detail: `Code: ${m[0]}`, ...(said ? { deliberate: said[0] } : {}) };
    },
    severity: "medium", category: "Transport Security", cweId: "CWE-295", cvssScore: 5.9, confidence: 75,
    description: "Certificate verification is switched off for outgoing connections, so anyone able to intercept the traffic can impersonate the server the code talks to and read or change what it sends, including credentials.",
    solution: "Remove the override and fix the certificate chain instead (add the CA with the ca option if it is a private one).",
  },
  {
    name: "AI Provider Key Used Directly in Browser Code",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = /dangerouslyAllowBrowser\s*:\s*true/.exec(text);
      return m ? { detail: `Code: ${m[0]}` } : null;
    },
    severity: "medium", category: "AI Feature Security", cweId: "CWE-522", cvssScore: 5.3, confidence: 70,
    description: "The AI provider's SDK is told to run in the browser (dangerouslyAllowBrowser). The key it needs is then shipped to every visitor, who can copy it and spend your quota.",
    solution: "Call the provider from a server route that holds the key, checks the user is signed in and rate-limits requests.",
  },
  ...MORE_RULES,
];

export function codePatternFindings(files: RepoFile[], ref: RepoRef): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    for (const rule of RULES) {
      const hit = rule.test(f.path, f.content);
      if (!hit) continue;
      const key = `${rule.name}|${f.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(repoFinding({ ref, path: f.path, name: rule.name, severity: hit.deliberate ? "info" : rule.severity, category: rule.category, cweId: rule.cweId,
        cvssScore: hit.deliberate ? 0 : rule.cvssScore, confidence: hit.deliberate ? 40 : rule.confidence, description: rule.description,
        detail: hit.deliberate ? `${hit.detail}\nNearby code says this is intended ("${hit.deliberate}"), so it is shown as information. Check that the connection never carries credentials or data an attacker could use.` : hit.detail,
        solution: rule.solution }));
    }
  }
  return out;
}
