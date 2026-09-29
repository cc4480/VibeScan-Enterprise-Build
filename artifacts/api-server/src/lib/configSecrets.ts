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

export interface ConfigSecretHit {
  key: string;
  /** The value with all but its ends masked. Never the value itself. */
  redacted: string;
  /** 1-based line in the file. */
  line: number;
  /** True in an .example/.sample/.template file. */
  inExampleFile: boolean;
}

const MAX_HITS_PER_FILE = 10;

/** Key names, normalised (lower case, no _ - .), that hold something secret. */
const SECRETISH = /secret|passw(?:or)?d|passwd|pwd|token|apikey|privatekey|accesskey|authkey|signingkey|encryptionkey|credential|masterkey/;
/** ...unless the key describes the secret rather than holding it: TOKEN_EXPIRY, JWT_SECRET_NAME, PASSWORD_MIN_LENGTH. */
const ABOUT_A_SECRET =
  /(?:expiry|expires|expiration|ttl|url|uri|name|id|length|min|max|file|path|field|header|type|algorithm|version|arn|regex|pattern|policy|required|enabled|disabled|rounds|cost|timeout|minutes|seconds|hours|days|count|limit|prefix|suffix|endpoint|host|port|label|description|message|hint|placeholder|ref)$/;

const normaliseKey = (key: string): string => key.toLowerCase().replace(/[_.\-\s]/g, "");
const holdsSecret = (key: string): boolean => {
  const k = normaliseKey(key);
  return SECRETISH.test(k) && !ABOUT_A_SECRET.test(k);
};

/** Words, digits and punctuation that mean "no value" or a setting rather than a secret. */
const NOT_A_SECRET_VALUE = /^(?:true|false|null|none|nil|undefined|yes|no|on|off|localhost|\d+|[\w.-]*\.(?:json|pem|txt|key|crt))$/i;

const isExampleFile = (path: string): boolean => /\.(?:example|sample|template|tmpl|dist)$|(?:^|\/)(?:example|sample)[^/]*$/i.test(path);

/** A value that is key material rather than a template, reference, name or default. */
function isSecretValue(raw: string, example: boolean): boolean {
  const value = raw.trim();
  if (value.length < 8 || NOT_A_SECRET_VALUE.test(value)) return false;
  if (/^https?:\/\//i.test(value) && !/@/.test(value)) return false;
  if (/^django-insecure-/i.test(value)) return false; // startproject's generated development key
  if (value.includes("://")) return false; // a database URL: the URL pattern owns that one
  if (looksLikeReference(value) || looksLikeAName(value) || isPlaceholderToken(value) || isTrivialPassword(value)) return false;
  const entropy = shannonEntropy(value);
  return example ? value.length >= 16 && entropy >= 3.5 : entropy >= 2.5;
}

interface Pair {
  key: string;
  value: string;
  line: number;
}

const unquote = (v: string): string => v.replace(/^(["'`])(.*)\1$/, "$2").replace(/[,;]+$/, "");

/** Every KEY/VALUE pair on one line, however the file writes them. */
function pairsOn(text: string, line: number): Pair[] {
  const pairs: Pair[] = [];
  const trimmed = text.trim();
  if (!trimmed) return pairs;

  // .npmrc: //registry.example.org/:_authToken=VALUE (begins with // like a comment, so first)
  const npm = /^\/\/[^\s=]+_(?:authToken|password|auth)\s*=\s*(\S+)/.exec(trimmed);
  if (npm) return [{ key: trimmed.slice(0, trimmed.indexOf("=")).trim(), value: unquote(npm[1]!), line }];

  if (trimmed.startsWith("#") || trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) return pairs;

  // PHP: define('DB_PASSWORD', 'value');
  for (const m of text.matchAll(/define\(\s*["']([A-Za-z_]\w*)["']\s*,\s*["']([^"']*)["']/g)) {
    pairs.push({ key: m[1]!, value: m[2]!, line });
  }
  // .netrc: password VALUE
  const netrc = /^password\s+(\S+)/i.exec(trimmed);
  if (netrc) pairs.push({ key: "password", value: unquote(netrc[1]!), line });

  // KEY=VALUE, KEY: VALUE, 'KEY': 'VALUE', "Key": "value", anywhere on the line.
  for (const m of text.matchAll(/(?:^|[\s,{(])["'`]?([A-Za-z_][\w.\-]*)["'`]?\s*[:=]\s*("[^"]*"|'[^']*'|`[^`]*`|[^\s,;#}{)"']+)/g)) {
    pairs.push({ key: m[1]!, value: unquote(m[2]!), line });
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
  const hits: ConfigSecretHit[] = [];
  const seen = new Set<string>();
  const add = (key: string, value: string, line: number) => {
    if (hits.length >= MAX_HITS_PER_FILE || seen.has(key)) return;
    seen.add(key);
    hits.push({ key, redacted: redactSecret(value), line, inExampleFile: example });
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

  content.split(/\r?\n/).forEach((text, i) => {
    for (const { key, value, line } of pairsOn(text, i + 1)) {
      const inString = connectionStringPassword(value);
      if (inString !== null && isSecretValue(inString, example)) add(`${key} (Password)`, inString, line);
      else if (holdsSecret(key) && isSecretValue(value, example)) add(key, value, line);
    }
  });
  return hits;
}
