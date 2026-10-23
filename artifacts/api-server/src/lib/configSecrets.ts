/**
 * Secrets in the syntaxes configuration files are written in.
 *
 * The GitHub source scan reused the JavaScript secret patterns, which need a QUOTED value after a
 * key such as `secret:`. Realistic secrets in the files that scan reads on purpose all came back
 * with zero findings: an unquoted `.env` (JWT_SECRET=..., API_KEY=...), Django's
 * `SECRET_KEY = '...'`, wp-config.php's `define('DB_PASSWORD', '...')`, appsettings.json's
 * `"Secret": "..."`, docker-compose's `POSTGRES_PASSWORD: ...`. Only vendor-prefixed tokens and
 * database URLs were caught, so a repo full of plain passwords read as clean.
 *
 * This reads KEY=VALUE, KEY: VALUE, `'KEY': 'VALUE'`, define('KEY', 'VALUE'), `.netrc`'s
 * `password VALUE`, `.npmrc`'s `//host/:_authToken=VALUE`, and `Password=...;` inside a connection
 * string. A pair counts only when the KEY names a secret and the VALUE is key material: not a
 * reference (${X}, $X, process.env.X), not a name (MY_JWT_SECRET), not a tutorial default
 * (postgres:postgres), not filler (xxxxxxxx), and — in an example file, where placeholders are the
 * norm — not merely human-chosen either.
 */
import { shannonEntropy, looksLikeAName, looksLikeReference, isPlaceholderToken, isTrivialPassword } from "./secretPlaceholders";
import { redactSecret } from "./jsScanner";
import { isPublicByDesignValue, isPublicByDesignName } from "./publicKeys";
import { namesItselfFake } from "./repoFinding";

export interface ConfigSecretHit {
  key: string;
  /** The value with all but its ends masked. Never the value itself. */
  redacted: string;
  /** 1-based line in the file. */
  line: number;
  /** True in an .example/.sample/.template file. */
  inExampleFile: boolean;
  /** The key or the value itself says it is fake: forged, dummy, a fixture, an example, a probe. */
  namesItselfFake: boolean;
  /** A password that is a plain lowercase word, in a compose, CI or dev file: the throwaway password of a local or test database. */
  devDefault: boolean;
}

/** Files where a database or service is started for development or tests, not production. */
const DEV_CONTEXT = /(?:^|\/)(?:docker-)?compose[^/]*\.ya?ml$|(?:^|\/)\.github\/workflows\/|(?:^|\/)\.devcontainer\/|(?:^|\/)\.gitlab-ci\.ya?ml$|(?:^|\/)\.circleci\/|\.env\.(?:dev|development|test|local|ci)\b|(?:^|\/)Makefile$|(?:^|\/)(?:dev|local|test)[\w.-]*\.(?:ya?ml|env)$/i;
/** A phrase with spaces, or a lowercase snake/kebab identifier: words, not key material. */
const CODE_LABEL = /\s|^[!:@#/]?[A-Za-z]{1,24}$|^[!:@#/]?[A-Za-z]+(?:[_.-][A-Za-z]+)+$/;
/** A human word (or two joined by - or _), all lowercase and no digits: nobody generated that. */
const PLAIN_WORD = /^[a-z]{3,}(?:[-_.][a-z]{2,})?$/;

const MAX_HITS_PER_FILE = 10;

/** Key names, normalised (lower case, no _ - .), that hold something secret. */
const SECRETISH = /secret|passw(?:or)?d|passwd|pwd|token|apikey|privatekey|accesskey|authkey|signingkey|encryptionkey|credential|masterkey|servicerole/;
/** ...unless the key describes the secret rather than holding it: TOKEN_EXPIRY, JWT_SECRET_NAME, PASSWORD_MIN_LENGTH. */
const ABOUT_A_SECRET =
  /(?:expiry|expires|expiration|ttl|url|uri|name|id|length|min|max|file|path|field|header|type|algorithm|version|arn|regex|pattern|policy|required|enabled|disabled|rounds|cost|timeout|minutes|seconds|hours|days|count|limit|prefix|suffix|endpoint|host|port|label|description|message|hint|placeholder|ref)$/;

const normaliseKey = (key: string): string => key.toLowerCase().replace(/[_.\-\s]/g, "");
const holdsSecret = (key: string): boolean => {
  const k = normaliseKey(key);
  // ALGOLIA_SEARCH_API_KEY, STRIPE_PUBLISHABLE_KEY: named for a key the vendor publishes to browsers.
  return SECRETISH.test(k) && !ABOUT_A_SECRET.test(k) && !isPublicByDesignName(k);
};

/** Words, digits and punctuation that mean "no value" or a setting rather than a secret. */
const NOT_A_SECRET_VALUE = /^(?:true|false|null|none|nil|undefined|yes|no|on|off|localhost|\d+|[\w.-]*\.(?:json|pem|txt|key|crt)|same-origin|same-site|include|omit|no-cors|cors|navigate|strict|lax|bearer|basic|digest|default|manual|auto)$/i;

const isExampleFile = (path: string): boolean => /\.(?:example|sample|template|tmpl|dist)$|(?:^|\/)(?:example|sample)[^/]*$/i.test(path);

/** A value that is key material rather than a template, reference, name or default. */
function isSecretValue(raw: string, example: boolean): boolean {
  const value = raw.trim();
  if (value.length < 8 || NOT_A_SECRET_VALUE.test(value)) return false;
  if (/^https?:\/\//i.test(value) && !/@/.test(value)) return false;
  if (/^django-insecure-/i.test(value)) return false; // startproject's generated development key
  if (value.includes("://")) return false; // a database URL: the URL pattern owns that one
  if (/[()]/.test(value)) return false; // a call or a shell command ($(openssl rand -hex 32), clean(process.env.X)): code, not a value
  if (/^[a-z][a-z_]*(?:\.[a-z][a-z_]*){2,}$/.test(value)) return false; // a dotted identifier (auth.sign_in.reset_password): a mapping key, not a value
  if (/(?:process\.env|import\.meta\.env|os\.environ|getenv|System\.getenv)/i.test(value)) return false;
  if (isPublicByDesignValue(value)) return false; // AIza, pk.ey, pk_live_, anon JWT: shipped to browsers on purpose
  if (looksLikeReference(value) || looksLikeAName(value) || isPlaceholderToken(value) || isTrivialPassword(value)) return false;
  // An example file that names its own value as a local or demo one (local-…, demo-…) is a placeholder, not a key.
  if (example && /^(?:local|dev|demo|test|example|sample)[-_]/i.test(value)) return false;
  const entropy = shannonEntropy(value);
  return example ? value.length >= 16 && entropy >= 3.5 : entropy >= 2.5;
}

interface Pair {
  key: string;
  value: string;
  line: number;
  /** The value was written in quotes. */
  quoted: boolean;
}

/** Files that are configuration, where an unquoted KEY=VALUE is how a secret is written. Elsewhere only a quoted literal is one. */
const isConfigSyntax = (path: string): boolean =>
  /(?:^|\/)(?:\.env(?:\.[\w.-]+)?|\.(?:npmrc|netrc|pypirc)|wp-config\.php|(?:local_)?settings\.py|master\.key)$|\.(?:ya?ml|json|toml|ini|cfg|conf|properties|tfvars|env|example|sample|template|tmpl|dist)$|(?:^|\/)(?:docker-)?compose[^/]*\.ya?ml$/i.test(path);

const unquote = (v: string): string => v.replace(/^(["'`])(.*)\1$/, "$2").replace(/[,;]+$/, "");

/** Every KEY/VALUE pair on one line, however the file writes them. */
function pairsOn(text: string, line: number): Pair[] {
  const pairs: Pair[] = [];
  const trimmed = text.trim();
  if (!trimmed) return pairs;

  // .npmrc: //registry.example.org/:_authToken=VALUE (begins with // like a comment, so first)
  const npm = /^\/\/[^\s=]+_(?:authToken|password|auth)\s*=\s*(\S+)/.exec(trimmed);
  if (npm) return [{ key: trimmed.slice(0, trimmed.indexOf("=")).trim(), value: unquote(npm[1]!), line, quoted: false }];

  if (trimmed.startsWith("#") || trimmed.startsWith("--") || trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) return pairs;

  // PHP: define('DB_PASSWORD', 'value');
  for (const m of text.matchAll(/define\(\s*["']([A-Za-z_]\w*)["']\s*,\s*["']([^"']*)["']/g)) {
    pairs.push({ key: m[1]!, value: m[2]!, line, quoted: true });
  }
  // .netrc: password VALUE
  const netrc = /^password\s+(\S+)/i.exec(trimmed);
  if (netrc) pairs.push({ key: "password", value: unquote(netrc[1]!), line, quoted: false });

  // KEY=VALUE, KEY: VALUE, 'KEY': 'VALUE', "Key": "value", anywhere on the line.
  for (const m of text.matchAll(/(?:^|[\s,{(])["'`]?([A-Za-z_][\w.\-]*)["'`]?\s*[:=]\s*("[^"]*"|'[^']*'|`[^`]*`|[^\s,;#}{)"']+)/g)) {
    // ${VAR:?message} and ${VAR:-default} are shell interpolation, not KEY: VALUE; the inside is a reference, never a secret.
    if (text[m.index!] === "{" && text[m.index! - 1] === "$") continue;
    pairs.push({ key: m[1]!, value: unquote(m[2]!), line, quoted: /^["'`]/.test(m[2]!) });
  }
  return pairs;
}

/** A password inside a connection string value: Server=...;User Id=app;Password=VALUE; */
function connectionStringPassword(value: string): string | null {
  const m = /(?:^|[;\s])(?:Password|Pwd)\s*=\s*([^;"'\s]+)/i.exec(value);
  return m ? m[1]! : null;
}

/** Walks parsed JSON, yielding dotted paths so a hit says where in the document it is. */
function* jsonLeaves(node: unknown, path: string[] = []): Generator<[string, string]> {
  if (typeof node === "string") {
    yield [path.join("."), node];
  } else if (Array.isArray(node)) {
    for (const [i, v] of node.entries()) yield* jsonLeaves(v, [...path, String(i)]);
  } else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) yield* jsonLeaves(v, [...path, k]);
  }
}

export function scanConfigSecrets(path: string, content: string): ConfigSecretHit[] {
  const example = isExampleFile(path);
  const configFile = isConfigSyntax(path);
  const hits: ConfigSecretHit[] = [];
  const seen = new Set<string>();
  const add = (key: string, value: string, line: number) => {
    if (hits.length >= MAX_HITS_PER_FILE || seen.has(key)) return;
    seen.add(key);
    hits.push({
      key, redacted: redactSecret(value), line, inExampleFile: example, namesItselfFake: namesItselfFake(`${key} ${value}`),
      devDefault: DEV_CONTEXT.test(path) && /pass(?:word|wd)?|pwd/.test(normaliseKey(key)) && PLAIN_WORD.test(value),
    });
  };

  // JSON that parses is read as a document, so nested keys and quoted commas are not a line-regex's problem.
  if (/\.json$/i.test(path)) {
    let doc: unknown;
    try {
      doc = JSON.parse(content);
    } catch {
      doc = undefined; // appsettings.json allows comments; the line reader below copes with those
    }
    if (doc !== undefined) {
      for (const [keyPath, value] of jsonLeaves(doc)) {
        const leaf = keyPath.split(".").pop() ?? keyPath;
        const inString = connectionStringPassword(value);
        if (inString !== null && isSecretValue(inString, example)) add(`${keyPath} (Password)`, inString, 1);
        else if (holdsSecret(leaf) && isSecretValue(value, example)) add(keyPath, value, 1);
      }
      return hits;
    }
  }

  const allLines = content.split(/\r?\n/);
  allLines.forEach((text, i) => {
    for (const { key, value, line, quoted } of pairsOn(text, i + 1)) {
      if (!quoted && !configFile) continue; // in code, `token = getToken` is an expression, not a committed value
      // In code, a quoted phrase ("Show password", "development key") or a lowercase identifier ("email_signin") is a
      // label, a message or a setting name: nobody generates a secret that reads as words.
      if (!configFile && CODE_LABEL.test(value)) continue;
      // Algolia DocSearch is configured with a search-only key beside its index and app id: public by design.
      if (/api[_-]?key/i.test(key) && /\bindexName\b|\bdocsearch\b/i.test([...allLines.slice(Math.max(0, i - 6), i), ...allLines.slice(i + 1, i + 7)].join("\n"))) continue;
      const inString = connectionStringPassword(value);
      if (inString !== null && isSecretValue(inString, example)) add(`${key} (Password)`, inString, line);
      else if (holdsSecret(key) && isSecretValue(value, example)) add(key, value, line);
    }
  });
  return hits;
}
