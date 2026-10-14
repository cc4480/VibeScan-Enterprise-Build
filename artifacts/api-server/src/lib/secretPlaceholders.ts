/**
 * Telling a placeholder from a secret. Pure helpers for secret-pattern-data.ts and jsScanner.ts.
 *
 * The pattern list found real-looking credentials well and found the ones people paste into
 * documentation just as well. Reproduced by running the repo's own patterns, every one of these
 * was reported as a live credential: sk_live_xxxxxxxxxxxxxxxxxxxxxxxx, ghp_xxxx…, sk-proj-xxxx…,
 * sk-ant-api03-xxxx…, SG.xxxx.xxxx, sentry_token: "aaaa…", Slack's documented webhook
 * T00000000/B00000000/XXXX, Stripe's documented sk_test_4eC39…, and — at CVSS 10 —
 * postgres://postgres:postgres@localhost:5432/mydb. They matter most in the files the GitHub
 * source scan reads on purpose, since .env.example is a candidate path and placeholders are what
 * an example file is FOR. And the name-rejecting rule that already existed missed its own headline
 * case: "VITE_DEEPSEEK_API_KEY": "MY_DEEPSEEK_API_KEY" was critical, because the validator on that
 * pattern never called it.
 */

/** Shannon entropy in bits per character. Real keys score above about 3.5; filler scores well below 3. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  const len = s.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum + p * Math.log2(p);
  }, 0);
}

/** Words that mark a value as a filler phrase rather than key material. All at least two letters. */
const FILLER = new Set([
  "my", "your", "the", "this", "here", "goes", "change", "changeme", "replace", "dummy", "sample", "fake",
  "test", "todo", "value", "token", "secret", "key", "api", "password", "placeholder", "random", "string",
  "long", "very", "generate", "generated", "strong", "secure", "super", "unique", "insert", "enter", "put",
  "jwt", "signing", "example", "default", "some", "any", "real", "actual", "add", "paste", "fill", "xxx",
]);

const isFiller = (w: string): boolean => FILLER.has(w.toLowerCase());

/** "mySecretKeyValueHere" -> ["my", "Secret", "Key", "Value", "Here"] */
const camelWords = (s: string): string[] => s.match(/[A-Z]?[a-z]+|[A-Z]+(?![a-z])/g) ?? [];

/**
 * A value that names a variable or is a filler phrase rather than being a credential:
 * MY_DEEPSEEK_API_KEY, S3_SECRET_ACCESS_KEY, OPENAI_API_KEY_2, your-super-secret-jwt-key,
 * a-very-long-random-string, mySecretKeyValueHere, supersecretjwtkeychangeme.
 *
 * Words joined by _ or - clear the entropy floor, so they need their own rule. A real key nearly
 * always carries a digit inside a word or is not made of separated words, so a run of words is
 * rejected only when it is an ALL-CAPS environment-variable name, or contains a filler word.
 */
export function looksLikeAName(value: string): boolean {
  // "your-super-secret-jwt-key-must-be-very-long!" is as much a filler phrase as the same words without the "!".
  const v = value.trim().replace(/[!.?]+$/, "");

  // ALL-CAPS environment-variable style. Digits are allowed inside a word (S3, _2) as long as at
  // least two of the words are plain letters, which real key material essentially never has.
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) {
    if (v.split("_").filter((w) => /^[A-Z]{2,}$/.test(w)).length >= 2) return true;
  }

  // Separated words. Digit-free, so "correct-horse-battery-staple-9" and real keys are left alone.
  if (/^[A-Za-z]+(?:[_-][A-Za-z]+)+$/.test(v)) {
    if (v === v.toUpperCase()) return true;
    return v.split(/[_-]/).some(isFiller);
  }

  // The same phrase with a bare number in it ("...-key-min-32-chars-long"): a filler word has to be there to say so.
  if (/^[A-Za-z]+(?:[_-](?:[A-Za-z]+|\d{1,3}))+$/.test(v)) return v.split(/[_-]/).some(isFiller);

  // Joined phrases with no separator and no digit.
  if (/^[A-Za-z]{12,}$/.test(v)) {
    const words = camelWords(v);
    // camelCase: three or more short words, one of them filler. A long random string splits into
    // many tiny "words" and needs two filler hits before it counts.
    if (words.length >= 3 && words.length <= 6 && words.some(isFiller)) return true;
    if (words.filter(isFiller).length >= 2) return true;
    // all lower case, no boundaries: two distinct filler words somewhere inside
    const lower = v.toLowerCase();
    const inside = [...FILLER].filter((w) => w.length >= 3 && lower.includes(w));
    return inside.length >= 2;
  }
  return false;
}

/** A reference to where a value comes from, not the value: process.env.X, ${X}, %X%, $X, env('X'), <your key>, {{ x }}. */
export function looksLikeReference(value: string): boolean {
  const v = value.trim();
  return (
    /^(?:process\.env\.|import\.meta\.env\.|os\.environ|System\.getenv|getenv\(|env\(|ENV\[)/i.test(v) ||
    /\$\{[^}]*\}|\{\{[^}]*\}\}|<[^<>]+>/.test(v) ||
    /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(v) ||
    /^%[A-Za-z0-9_]+%$/.test(v)
  );
}

/** Values documentation and SDK READMEs print, which are not anyone's credentials. */
const WELL_KNOWN_DOC_TOKENS = [
  "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
  "pk_test_TYooMQauvdEDq54NiTphI7jx",
  "AKIAIOSFODNN7EXAMPLE",
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
];

const distinct = (s: string): number => new Set(s).size;

/**
 * Is this match a fixed-format token whose material is filler? Applied to the whole match, split on
 * anything that is not a letter or digit, because vendor tokens are made of parts (sk_live_<body>,
 * SG.<id>.<secret>, xoxb-<a>-<b>, T<id>/B<id>/<secret>) and any long part of one or two repeated
 * characters, or a run of eight identical characters, is a template: xxxxxxxx, 00000000, aaaa…
 */
export function isPlaceholderToken(match: string): boolean {
  if (WELL_KNOWN_DOC_TOKENS.some((t) => match.includes(t))) return true;
  if (/EXAMPLE|PLACEHOLDER|REDACTED|CHANGE[_-]?(?:ME|THIS|IT)\b|REPLACE[_-]?(?:ME|THIS)\b|DUMMY|NOTREAL|YOUR[_-]?(?:API[_-]?)?(?:KEY|TOKEN|SECRET)|(?:KEY|TOKEN|SECRET)[_-]?HERE/i.test(match)) {
    return true;
  }
  for (const part of match.split(/[^A-Za-z0-9]+/)) {
    if (part.length >= 8 && distinct(part) <= 2) return true;
    if (part.length >= 12 && distinct(part) <= 3) return true;
    if (/(.)\1{7,}/.test(part)) return true;
  }
  return false;
}

/**
 * Defaults every tutorial uses. A database password from this list is a development instance, not a
 * leak. Up to six trailing characters (admin123, root!) or a second obvious word (devpassword,
 * rootpassword, adminpass, password123) still count: the docker-compose examples people copy.
 */
const TRIVIAL_PASSWORD =
  /^(?:pass(?:word)?|admin|root|toor|postgres|mysql|mongo(?:db)?|secret|changeme|example|test|demo|user|dev|letmein|welcome|qwerty|abc|guest|default)(?:[\w!@#]{0,6}|[_-]?(?:pass(?:word)?|pwd|secret|admin|root|user|db|dev|local|test|demo)\d{0,4}[!@#]?)$/i;

export function isTrivialPassword(password: string, user = ""): boolean {
  return password === user || TRIVIAL_PASSWORD.test(password) || /^\d{4,10}$/.test(password) || distinct(password) <= 2;
}

/** Hosts that reach only the developer's own machine, whatever the credential in front of them. */
export function isLocalHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  return h === "localhost" || h.endsWith(".localhost") || h === "::1" || h === "0.0.0.0" || h === "host.docker.internal" || /^127\./.test(h);
}
