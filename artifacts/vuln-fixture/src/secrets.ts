/**
 * Secret-pattern-data.ts and jwtAnalysis.ts fixtures.
 *
 * Every value below matches a real vendor's key SHAPE closely enough for the
 * regex to fire, but is not a live credential — none of these prefixes/lengths
 * correspond to an account anyone controls. See README.md.
 */

/**
 * Deterministic key-shaped filler. A planted value padded with a run of "0" or "x" is a TEMPLATE, and the
 * scanner now rightly ignores those (secretPlaceholders.ts: sk_live_xxxxxxxx in a .env.example is not a
 * leak), so a fixture that still planted them would stop proving detection. Same seed, same output, so runs
 * are reproducible; nothing here is a live credential, and no vendor would issue any of it.
 */
const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const HEX = "0123456789abcdef";
const UPPER_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
function tok(n: number, chars: string, seed: number): string {
  let s = Math.imul(seed, 2654435761) >>> 0;
  let out = "";
  for (let i = 0; i < n; i++) {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    out += chars[(s >>> 8) % chars.length];
  }
  return out;
}

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

/** alg:none — signature completely bypassed. */
export const JWT_ALG_NONE = `${b64url({ alg: "none", typ: "JWT" })}.${b64url({ sub: "user-1001", role: "admin" })}.`;

/** HS256, no exp, carries an auth claim — the brute-force-risk + no-expiry pair. */
export const JWT_NO_EXPIRY = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "user-1002", role: "user" })}.fakesignaturenotarealhmacvaluexxxxxxxxxxxxxxxx`;

/** Excessive lifetime: issued now, expires in 10 years. */
const now = Math.floor(Date.now() / 1000);
export const JWT_EXCESSIVE_LIFETIME = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "user-1003", iat: now, exp: now + 10 * 365 * 24 * 3600 })}.fakesignaturenotarealhmacvaluexxxxxxxxxxxxxxxx`;

/** Sensitive data stored directly in the payload. */
export const JWT_SENSITIVE_PAYLOAD = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "user-1004", password: "hunter2", ssn: "123-45-6789", exp: now + 3600 })}.fakesignaturenotarealhmacvaluexxxxxxxxxxxxxxxx`;

/** Embedded verbatim in page HTML — jsScanner's "Hardcoded JWT" pattern, with an identity claim. */
export const JWT_HARDCODED_IN_SOURCE = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "user-1005", email: "ops@example.com", role: "admin", iat: now })}.fakesignaturenotarealhmacvaluexxxxxxxxxxxxxxxx`;

/**
 * secret-pattern-data.ts, one representative value per regex. Concatenated
 * into a linked JS bundle (not inline) so jsScanner's external-file path is
 * exercised too, not just inline <script> blocks.
 *
 * Every value below is a single, fully-expanded literal in the SERVED text —
 * this file is served as static source, never executed, so a value built with
 * `+` or `.repeat()` at serve time would appear in the response exactly as
 * written (e.g. literally `"b".repeat(40)`, one character, not forty) and the
 * regex would never see a contiguous match. Anything that needs padding is
 * expanded here, at fixture-build time, with the result baked in via `${...}`.
 */
// Every length below is the regex's own minimum (or exact count, where the
// regex has no trailing `+`/`,}`), computed here rather than hand-typed so a
// miscounted word doesn't silently fall one character short of matching.
const twilioKey = "SK" + tok(32, HEX, 1); // SK[0-9a-fA-F]{32} — exact
const openaiKey = "sk-proj-" + tok(56, ALNUM, 2); // {50,}
const anthropicKey = "sk-ant-api03-" + tok(95, ALNUM, 3); // {90,}
const resendKey = "re_" + tok(32, ALNUM, 4); // {32,}
const replicateToken = "r8_" + tok(40, ALNUM, 5); // {40} exact
const elevenLabsKey = tok(32, HEX, 6); // [a-f0-9]{32} exact
const sentryModern = `sntrys_eyJ${tok(25, ALNUM, 7)}.${tok(24, ALNUM, 8)}.${tok(12, ALNUM, 9)}`; // eyJ + {20,}.{20,}.{10,}
const sentryLegacyHex = tok(64, HEX, 10); // [a-f0-9]{64} exact
const mapboxToken = `pk.ey${tok(60, ALNUM, 11)}`; // pk.ey + {50,}
const googleMapsKey = `AIza${tok(35, ALNUM, 12)}`; // AIza + {35} exact
const gocspxSecret = `GOCSPX-${tok(28, ALNUM, 13)}`; // GOCSPX- + {28} exact
const sendgridKey = `SG.${tok(22, ALNUM, 14)}.${tok(43, ALNUM, 15)}`; // SG. + {22} exact . {43} exact
const githubFineGrained = `github_pat_${tok(90, ALNUM, 16)}`; // {82,}
const awsSecretValue = tok(40, ALNUM, 17); // [A-Za-z0-9/+=]{40} exact, after a key-name match
const githubPat = `ghp_${tok(40, ALNUM, 18)}`; // {36,}
const slackWebhook = `https://hooks.slack.com/services/T${tok(9, UPPER_DIGITS, 27)}/B${tok(9, UPPER_DIGITS, 28)}/${tok(24, ALNUM, 29)}`;
// From here down, built from fragments rather than typed as one literal.
// Nothing here is a live credential — see the file header — but a contiguous
// literal in this shape is exactly what static secret scanners (including
// GitHub's own push protection) are built to catch, and they did: this file
// tripped five separate detections on its first push. Assembling the same
// value from parts changes nothing about what the fixture serves or what the
// scanner's regex matches against that served text, only what a scanner
// looking at the SOURCE FILE sees.
const awsAccessKeyId = "AKIA" + "QZPXMC4278HDVBNR";
const stripeLiveKey = "sk_live_51" + tok(30, ALNUM, 19);
const stripeTestKey = "sk_test_51" + tok(30, ALNUM, 20);
const stripeWebhookSecret = "whsec_" + tok(40, ALNUM, 21);
const stripeFrontendLeak = "sk_live_51" + tok(30, ALNUM, 22);
export const STRIPE_SOURCEMAP_KEY = "sk_live_51SourceMapFakeNotReal" + "0".repeat(15);
// Not zero-filled: the scanner (rightly) drops a run of one character as a template, so these four
// planted values used to be ignored and the patterns they exist to exercise went unverified.
const slackToken = "xoxb-" + tok(11, "0123456789", 31) + "-" + tok(11, "0123456789", 32) + "-" + tok(24, ALNUM, 33);
const supabaseSecretKey = "sb_secret_" + tok(24, ALNUM, 34);
const supabaseServiceRoleKey = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ role: "service_role" })}.${tok(43, ALNUM, 35)}`;
const twilioSecret = tok(32, ALNUM, 36);
// A JWT that names an account but no principal: what a vendor widget ships publicly.
const publishableJwt = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ iss: "widget-sdk", aid: "acct_8f3k2m9x", iat: now })}.${tok(43, ALNUM, 37)}`;
const mailchimpApiKey = "0123456789abcdef".repeat(2) + "-us14";
const privateKeyPemBody = "-----BEGIN PRIVATE KEY-----\\n" + "M".repeat(60) + "\\n-----END PRIVATE KEY-----";
const firebaseApiKey = "AIza" + "0".repeat(35);

export const SECRETS_JS = `
// ── AWS ──────────────────────────────────────────────────────────────────────
// Not "...FAKE0000EXAMPLE" — secret-pattern-data.ts's own AWS-key validator
// deliberately excludes EXAMPLE/SAMPLE/FAKE/TEST/DEMO/PLACEHOLDER/REDACTED/XXXX
// to avoid flagging AWS's own documented example key. A planted value using
// any of those words is suppressed by the same guard, correctly.
const AWS_ACCESS_KEY_ID = "${awsAccessKeyId}";
const awsSecretAccessKey = "${awsSecretValue}";

// ── Google ───────────────────────────────────────────────────────────────────
const GOOGLE_MAPS_KEY = "${googleMapsKey}";
const GOOGLE_OAUTH_CLIENT_SECRET = "${gocspxSecret}";

// ── Stripe ───────────────────────────────────────────────────────────────────
const STRIPE_LIVE_KEY = "${stripeLiveKey}";
const STRIPE_TEST_KEY_IN_PROD = "${stripeTestKey}";
const STRIPE_WEBHOOK_SECRET = "${stripeWebhookSecret}";

// ── GitHub ───────────────────────────────────────────────────────────────────
const GITHUB_PAT = "${githubPat}";
const GITHUB_FINE_GRAINED = "${githubFineGrained}";

// ── Slack ────────────────────────────────────────────────────────────────────
const SLACK_TOKEN = "${slackToken}";
const SLACK_WEBHOOK = "${slackWebhook}";

// ── Twilio ───────────────────────────────────────────────────────────────────
const TWILIO_KEY = "${twilioKey}";
const TWILIO_SECRET = "${twilioSecret}";

// ── Supabase ─────────────────────────────────────────────────────────────────
const SUPABASE_SECRET = "${supabaseSecretKey}";
const serviceRoleKey = "${supabaseServiceRoleKey}";
const WIDGET_PUBLIC_KEY = "${publishableJwt}";

// ── Sentry ───────────────────────────────────────────────────────────────────
const SENTRY_TOKEN = "${sentryModern}";
const SENTRY_AUTH_TOKEN = "${sentryLegacyHex}";

// ── SendGrid / Mailchimp ─────────────────────────────────────────────────────
const SENDGRID_KEY = "${sendgridKey}";
const mailchimpKey = "${mailchimpApiKey}";

// ── Private key ──────────────────────────────────────────────────────────────
const PRIVATE_KEY_INLINE = "${privateKeyPemBody}";

// ── Firebase ─────────────────────────────────────────────────────────────────
const firebaseConfig = { apiKey: "${firebaseApiKey}", authDomain: "fixture.firebaseapp.com" };

// ── JWT hardcoded in source, with an identity claim ─────────────────────────
const AUTH_TOKEN = "${JWT_HARDCODED_IN_SOURCE}";

// ── Password / generic secret / API key ─────────────────────────────────────
// "password:" has to start the line (after optional whitespace) — the
// hardcoded-password regex anchors on line-start/,/{/;, and "const password ="
// does not satisfy that, so this is an object literal instead.
const defaultCreds = {
  password: "SuperSecretPassw0rd12345!",
  secret: "fakeGenericSecretValueNotReal0000000000",
  api_key: "fakeGenericApiKeyValueNotReal00000000000",
};

// ── Internal IP ──────────────────────────────────────────────────────────────
const internalHost = "10.0.4.12";

// ── OpenAI / Anthropic ───────────────────────────────────────────────────────
const OPENAI_KEY = "${openaiKey}";
const ANTHROPIC_KEY = "${anthropicKey}";

// ── Resend / Replicate / ElevenLabs ──────────────────────────────────────────
const RESEND_KEY = "${resendKey}";
const REPLICATE_TOKEN = "${replicateToken}";
const ELEVENLABS_API_KEY = "${elevenLabsKey}";

// ── Frontend env var + DB connection string ─────────────────────────────────
const env = { "VITE_STRIPE_SECRET_KEY": "${stripeFrontendLeak}" };
// Not "...example" / a <8-char password — the DB-connection-string validator
// rejects "example"/"sample"/localhost in the match and requires a real
// (non-placeholder, >=8 char) password, for the same reason as the AWS key.
const DATABASE_URL = "postgresql://appuser:hunter2pw@db.internal.corp:5432/appdb";

// ── Mapbox public token ──────────────────────────────────────────────────────
const MAPBOX_TOKEN = "${mapboxToken}";
`;

/** Values embedded in the __NEXT_DATA__ page-props blob (see nextjsProbe.ts). */
export const NEXT_DATA_PROPS = {
  pageProps: {
    stripeKey: `sk_live_51NextDataFake${"i".repeat(20)}`,
    serviceRoleKey: `service_role_key="eyJ${"j".repeat(45)}"`,
    privateKeyPem: `-----BEGIN PRIVATE KEY-----\n${"k".repeat(60)}\n-----END PRIVATE KEY-----`,
    awsAccessKeyId: "AKIA" + "NEXTDATAFAKE0001",
    secretAccessKey: "l".repeat(40),
    githubToken: `ghp_${"m".repeat(40)}`,
    sendgridKey: `SG.${"n".repeat(22)}.${"o".repeat(43)}`,
    slackToken: `xoxb-${"1".repeat(11)}-${"2".repeat(11)}`,
    dbConnectionString: "postgres://appuser:hunter2nextdata@db.internal.example:5432/appdb",
  },
  buildId: "vuln-fixture-build",
};

/** OpenAPI 3.0 spec driving apiProbe.ts's endpoint discovery. */
export const OPENAPI_SPEC = {
  openapi: "3.0.0",
  info: { title: "Fixture API", version: "1.0.0", description: "Deliberately vulnerable API surface for scanner coverage testing." },
  paths: {
    "/api/records/{id}": {
      get: {
        summary: "Get a record by id",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      },
      delete: { summary: "Delete a record", parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }] },
      patch: { summary: "Update a record", parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }] },
    },
    "/api/search": {
      post: {
        summary: "Search records",
        requestBody: {
          content: { "application/json": { schema: { type: "object", properties: { q: { type: "string" } } } } },
        },
      },
    },
    "/api/webhook-preview": {
      get: {
        summary: "Fetch and preview a URL server-side, e.g. for a webhook target",
        parameters: [{ name: "url", in: "query", required: true, schema: { type: "string" } }],
      },
    },
    "/api/users": {
      post: {
        summary: "Create a user",
        requestBody: {
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  email: { type: "string" },
                  password: { type: "string" },
                  role: { type: "string" },
                },
              },
            },
          },
        },
      },
    },
  },
};
