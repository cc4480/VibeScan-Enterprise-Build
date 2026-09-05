import { describe, it, expect } from "vitest";
import { analyzeJwts } from "./jwtAnalysis.js";

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj))
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** A structurally valid JWT — real signature bytes, not decoded or checked here. */
function makeJwt(header: object, payload: object, sig = "sig"): string {
  return `${b64url(header)}.${b64url(payload)}.${b64url({ s: sig }).slice(0, 20)}`;
}

const FAR_FUTURE_EXP = Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60;

describe("analyzeJwts — sensitive payload fields", () => {
  it("still flags an access_token embedded in the payload", async () => {
    const jwt = makeJwt(
      { alg: "HS256", typ: "JWT" },
      { sub: "user_1", exp: FAR_FUTURE_EXP, access_token: "abc123" },
    );
    const vulns = await analyzeJwts({}, `<script>const t="${jwt}"</script>`);
    expect(vulns.some((v) => /Sensitive Data Stored in JWT/i.test(v.name))).toBe(true);
  });

  it("still flags dob in the payload", async () => {
    const jwt = makeJwt(
      { alg: "HS256", typ: "JWT" },
      { sub: "user_1", exp: FAR_FUTURE_EXP, dob: "1990-01-01" },
    );
    const vulns = await analyzeJwts({}, `<script>const t="${jwt}"</script>`);
    expect(vulns.some((v) => /Sensitive Data Stored in JWT/i.test(v.name))).toBe(true);
  });

  it("no longer flags a bare 'token' field", async () => {
    // Regression: a bare "token" key is common as an unrelated internal field
    // (a correlation id, a continuation cursor) with no secret value. The
    // more specific forms — access_token, refresh_token, auth_token — still
    // catch the case that actually matters; this one produced findings on
    // payloads carrying nothing sensitive at all.
    const jwt = makeJwt(
      { alg: "HS256", typ: "JWT" },
      { sub: "user_1", exp: FAR_FUTURE_EXP, token: "trace-id-4f9a" },
    );
    const vulns = await analyzeJwts({}, `<script>const t="${jwt}"</script>`);
    expect(vulns.some((v) => /Sensitive Data Stored in JWT/i.test(v.name))).toBe(false);
  });

  it("stays quiet on a payload with no sensitive-looking fields at all", async () => {
    const jwt = makeJwt(
      { alg: "HS256", typ: "JWT" },
      { sub: "user_1", exp: FAR_FUTURE_EXP, role: "member" },
    );
    const vulns = await analyzeJwts({}, `<script>const t="${jwt}"</script>`);
    expect(vulns.some((v) => /Sensitive Data Stored in JWT/i.test(v.name))).toBe(false);
  });
});

describe("analyzeJwts — structural checks (sanity)", () => {
  it("flags alg:none", async () => {
    const jwt = `${b64url({ alg: "none", typ: "JWT" })}.${b64url({ sub: "x" })}.`;
    const vulns = await analyzeJwts({}, `<script>const t="${jwt}"</script>`);
    expect(vulns.some((v) => /alg:none/i.test(v.name))).toBe(true);
  });

  it("flags a missing exp claim", async () => {
    const jwt = makeJwt({ alg: "HS256", typ: "JWT" }, { sub: "user_1" });
    const vulns = await analyzeJwts({}, `<script>const t="${jwt}"</script>`);
    expect(vulns.some((v) => /No Expiry/i.test(v.name))).toBe(true);
  });
});
