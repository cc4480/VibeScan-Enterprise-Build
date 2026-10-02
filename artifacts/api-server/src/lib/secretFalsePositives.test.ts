import { describe, it, expect } from "vitest";
import { scanContent } from "./jsScanner";

// Fake, test-only values shaped like the real thing. Each block pairs a benign input that used to be
// reported with a "twin" that is a genuine secret and must still be.
const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
const HDR = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
const SIG = "Xk3l9sQ2vB7nRt0yUe1WmA5cHzPq8dJf4oLg6iYh2Zs";
const jwt = (payload: object) => `${HDR}.${b64(payload)}.${SIG}`;
const ANON = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon", iat: 1700000000, exp: 2000000000 });
const SERVICE = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "service_role", iat: 1700000000, exp: 2000000000 });
const PK_LIVE = "pk_live_51Hq3kLJx8vN2mYtRzWc9aBdE0fGhIjKlMnOpQrStUv";
const AIZA = "AIzaSyD3xampl3K3yForT3stingPurposesOnly12345";
const MAPBOX = "pk.eyJ1IjoiYWNtZSIsImEiOiJjbGFiY2RlZmcwMDAwM3BwbnZ4In0.abcDEF123ghiJKL456mnoPQR";
const POSTHOG = "phc_Zq3XkL8vN2mYtRzWc9aBdE0fGhIjKlMnOpQrSt";
const AWS_SECRET = "wK8fPq3Zx1Vb7LmN0tRyH5uJdG2sAe9cXo4iTvQz";
const AWS_ID = "AKIAQZPXMC4278HDVBNR";

const hits = (src: string) => scanContent(src).map((f) => [f.pattern.name, f.pattern.severity] as const);
const names = (src: string) => hits(src).map(([n]) => n);
const ENV_LEAK = "Secret Environment Variable Leaked in Frontend Bundle";

describe("frontend env var names do not make a public-by-design value a secret", () => {
  it.each([
    ["NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY", PK_LIVE],
    ["NEXT_PUBLIC_SUPABASE_ANON_KEY", ANON],
    ["NEXT_PUBLIC_FIREBASE_API_KEY", AIZA],
    ["NEXT_PUBLIC_MAPBOX_TOKEN", MAPBOX],
    ["NEXT_PUBLIC_POSTHOG_KEY", POSTHOG],
    ["VITE_SUPABASE_PUBLISHABLE_KEY", "sb_publishable_Zq3XkL8vN2mYtRzWc9aBdE0f"],
    ["NEXT_PUBLIC_RECAPTCHA_SITE_KEY", "6LcAbCdEfGhIjKlMnOpQrStUvWxYz0123456789a"],
  ])("%s", (name, value) => {
    expect(names(`window.__ENV={"${name}":"${value}"};`)).not.toContain(ENV_LEAK);
  });

  it.each([
    ["NEXT_PUBLIC_STRIPE_SECRET_KEY", "sk_live_51Hq3kLJx8vN2mYtRzWc9aBdE0fGhIj"],
    ["VITE_SUPABASE_SERVICE_ROLE_KEY", SERVICE],
    ["REACT_APP_AWS_SECRET_KEY", AWS_SECRET],
    ["NEXT_PUBLIC_SUPABASE_KEY", "sb_secret_Zq3XkL8vN2mYtRzWc9aBdE0fGh"],
    ["NEXT_PUBLIC_RECAPTCHA_SECRET", "6LcAbCdEfGhIjKlMnOpQrStUvWxYz0123456789a"],
  ])("still reports %s", (name, value) => {
    expect(names(`window.__ENV={"${name}":"${value}"};`)).toContain(ENV_LEAK);
  });
});

describe("Hardcoded Password ignores interface text", () => {
  const PW = "Hardcoded Password in Source Code";
  it.each([
    `{password:"Enter your password here please"}`,
    `password:"Must contain 8 characters and a symbol"`,
    `{password:"login.form.password"}`,
    `{password:"auth_password_label_text"}`,
    `{password:"enterYourPasswordHere"}`,
  ])("%s", (src) => {
    expect(names(src)).not.toContain(PW);
  });

  it("still reports a hardcoded password", () => {
    expect(names(`const c={password:"Xk9#mP2$vL8@qR4z"};`)).toContain(PW);
  });
});

describe("identifiers are not reported as the credential", () => {
  it("a Twilio API Key SID alone is an identifier, not a HIGH key", () => {
    const out = hits(`var t="SK0123456789abcdef0123456789abcdef";`);
    expect(out.filter(([, s]) => s === "high" || s === "critical")).toEqual([]);
    expect(out.map(([n]) => n)).not.toContain("Twilio API Key Exposed");
  });

  it("a Twilio SID with its secret beside it is still HIGH", () => {
    const out = hits(`var t={apiKey:"SK0123456789abcdef0123456789abcdef",apiSecret:"Zq3XkL8vN2mYtRzWc9aBdE0fGhIjKlMn"};`);
    expect(out).toContainEqual(["Twilio API Key SID and Secret Exposed", "high"]);
  });

  it("an AWS access key ID alone is not CRITICAL", () => {
    const out = hits(`var k="${AWS_ID}";`);
    expect(out.filter(([, s]) => s === "critical")).toEqual([]);
    expect(out.map(([n]) => n)).toEqual(["AWS Access Key ID Found in Client Code"]);
  });

  it("an AWS ID with its secret beside it is still CRITICAL", () => {
    expect(hits(`var c={accessKeyId:"${AWS_ID}",secretAccessKey:"${AWS_SECRET}"};`)).toContainEqual([
      "AWS Secret Access Key Exposed", "critical",
    ]);
    expect(hits(`var c={id:"${AWS_ID}",secret_key:"${AWS_SECRET}"};`)).toContainEqual([
      "AWS Secret Access Key Exposed", "critical",
    ]);
  });

  it.each([
    ["a SHA-1 hash", `secret_key: "356a192b7913b04c54574d18c28d46e6395428ab"`],
    ["a CSRF-style secret_key with no AWS id near it", `var cfg={secret_key:"${AWS_SECRET}"};`],
    ["a hex-only value under an AWS name", `aws_secret_access_key="356a192b7913b04c54574d18c28d46e6395428ab"`],
    ["a repeated-character value under an AWS name", `aws_secret_access_key="${"a1".repeat(20)}"`],
  ])("%s is not an AWS secret", (_l, src) => {
    expect(names(src)).not.toContain("AWS Secret Access Key Exposed");
  });
});

describe("JWTs: samples and publishable roles", () => {
  const JWT_HIGH = "Hardcoded JWT Token in Source";
  const JWTIO =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

  it("the jwt.io sample token is not a credential", () => {
    expect(names(`var t="${JWTIO}";`)).not.toContain(JWT_HIGH);
  });
  it("a Supabase anon JWT is not a credential", () => {
    expect(names(`var t="${ANON}";`)).not.toContain(JWT_HIGH);
  });
  it("a token carrying the sample subject with a different name is still a credential", () => {
    expect(names(`var t="${jwt({ sub: "user-8814", email: "ops@acme.test", role: "admin" })}";`)).toContain(JWT_HIGH);
  });
});

describe("titles say only what was observed", () => {
  it("names the Stripe test key without claiming production", () => {
    const out = hits(`var k="sk_test_51Hq3kLJx8vN2mYtRzWc9aBdE0fGhIj";`);
    expect(out).toContainEqual(["Stripe Test-Mode Secret Key in Client Code", "medium"]);
    expect(out.map(([n]) => n).join()).not.toMatch(/Production/);
  });

  it("names a Firebase config block without claiming open rules", () => {
    const out = hits(`var firebaseConfig = { apiKey: "${AIZA}", projectId: "acme" };`);
    expect(out).toContainEqual(["Firebase Configuration Found in Client Code", "info"]);
    expect(out.map(([n]) => n).join()).not.toMatch(/Open Security Rules/);
  });

  it("does not call a bare re_ identifier a Resend key, but reports one in a key context", () => {
    expect(names(`var x="re_AbCdEfGhIjKlMnOpQrStUvWxYz012345678901";`)).not.toContain("Resend API Key Exposed");
    expect(names(`const resend = new Resend("re_AbCdEfGh_JkMnPqRsTuVwXyZ12345678a");`)).toContain("Resend API Key Exposed");
    // a body with characters outside base58 (0, O, I, l) is not the two-part format
    expect(names(`const resend = new Resend("re_AbCdEfGh_IjKlMnOpQrStUvWxYz012345");`)).not.toContain("Resend API Key Exposed");
    expect(names(`headers:{Authorization:"Bearer re_Zq3XkL8vN2mYtRzWc9aBdE0fGhIjKlMnOp"}`)).toContain("Resend API Key Exposed");
  });
});

describe("env-file content read as client code stays at INFO", () => {
  it("keeps the client-code detectors on the same content at INFO", () => {
    const env = `NEXT_PUBLIC_FIREBASE_API_KEY="AIzaSyD4x9Kq2LmN8pRt3VwYz1AbCdEfGhIjKlM"\nNEXT_PUBLIC_MAPBOX_TOKEN="${MAPBOX}"\n`;
    expect(hits(env).length).toBeGreaterThan(0);
    for (const [, sev] of hits(env)) expect(sev).toBe("info");
  });
});
