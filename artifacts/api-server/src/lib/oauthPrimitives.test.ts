import { describe, it, expect } from "vitest";

import { challengeFor, isValidChallenge, isValidVerifier, verifyPkce } from "./oauthPkce";
import { checkRedirectUri, validateRegistration, normaliseClientName, redirectUriAllowed, describeRedirect } from "./oauthClients";
import { signConsent, verifyConsent, type ConsentPayload } from "./oauthConsent";

const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // RFC 7636 appendix B
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

describe("PKCE", () => {
  it("matches the RFC 7636 test vector", () => {
    expect(challengeFor(VERIFIER)).toBe(CHALLENGE);
    expect(verifyPkce(VERIFIER, CHALLENGE)).toBe(true);
  });

  it("rejects a verifier that is not the one the challenge was made from", () => {
    expect(verifyPkce(VERIFIER.replace("d", "e"), CHALLENGE)).toBe(false);
    expect(verifyPkce("x".repeat(43), CHALLENGE)).toBe(false);
  });

  it("rejects malformed values instead of comparing them", () => {
    for (const v of [undefined, null, 5, "", "short", "a".repeat(129), "has space " + "a".repeat(40), "a".repeat(42) + "!"]) {
      expect(verifyPkce(v, CHALLENGE), String(v)).toBe(false);
      expect(isValidVerifier(v), String(v)).toBe(false);
    }
    expect(verifyPkce(VERIFIER, "tooshort")).toBe(false);
  });

  it("accepts only an S256-shaped challenge, so a 'plain' challenge cannot be smuggled in", () => {
    expect(isValidChallenge(CHALLENGE)).toBe(true);
    expect(isValidChallenge(VERIFIER + "extra")).toBe(false);
    expect(isValidChallenge("a".repeat(44))).toBe(false);
    expect(isValidChallenge(undefined)).toBe(false);
  });
});

describe("redirect URIs", () => {
  it.each([
    "https://claude.ai/api/mcp/auth_callback",
    "https://example.com/callback?x=1",
    "http://localhost:53421/callback",
    "http://127.0.0.1/cb",
    "http://[::1]:8080/cb",
    "cursor://anysphere.cursor-retrieval/oauth/callback",
    "vscode://vscode.github-authentication/did-authenticate",
  ])("allows %s", (uri) => {
    expect(checkRedirectUri(uri).ok).toBe(true);
  });

  it.each([
    ["javascript:alert(1)", /not allowed/],
    ["data:text/html,<script>", /not allowed/],
    ["file:///etc/passwd", /not allowed/],
    ["http://evil.example/cb", /localhost/],
    ["http://localhost.evil.example/cb", /localhost/],
    ["https://a.example/cb#frag", /fragment/],
    ["https://user:pw@a.example/cb", /credentials/],
    ["not a url", /not a URL|whitespace/],
    ["https://a.example/cb\nInjected: header", /whitespace|control/],
    ["", /length/],
    ["https://a.example/" + "x".repeat(2100), /length/],
  ])("refuses %s", (uri, reason) => {
    const r = checkRedirectUri(uri);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(reason);
  });

  it("matches a registered address exactly, never by prefix", () => {
    const client = { redirectUris: ["https://app.example/cb"] };
    expect(redirectUriAllowed(client, "https://app.example/cb")).toBe(true);
    expect(redirectUriAllowed(client, "https://app.example/cb/")).toBe(false);
    expect(redirectUriAllowed(client, "https://app.example/cb/../x")).toBe(false);
    expect(redirectUriAllowed(client, "https://app.example/cbx")).toBe(false);
    expect(redirectUriAllowed(client, "https://app.example.evil.example/cb")).toBe(false);
    expect(redirectUriAllowed(client, undefined)).toBe(false);
  });

  it("describes where the person is going back to, by host", () => {
    expect(describeRedirect("https://claude.ai/api/mcp/auth_callback")).toEqual({ host: "claude.ai", kind: "web" });
    expect(describeRedirect("http://localhost:53421/cb")).toEqual({ host: "localhost:53421", kind: "local" });
    expect(describeRedirect("cursor://anysphere.cursor-retrieval/oauth/callback").kind).toBe("app");
  });
});

describe("client registration", () => {
  const ok = { client_name: "Cursor", redirect_uris: ["http://127.0.0.1:1234/cb"] };

  it("accepts a normal editor registration", () => {
    const r = validateRegistration({ ...ok, token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] });
    expect(r).toMatchObject({ ok: true, name: "Cursor", redirectUris: ["http://127.0.0.1:1234/cb"] });
  });

  it("requires redirect URIs, caps how many, and de-duplicates", () => {
    expect(validateRegistration({}).ok).toBe(false);
    expect(validateRegistration({ redirect_uris: [] }).ok).toBe(false);
    expect(validateRegistration({ redirect_uris: Array.from({ length: 6 }, (_, i) => `https://a.example/${i}`) }).ok).toBe(false);
    const dup = validateRegistration({ redirect_uris: ["https://a.example/cb", "https://a.example/cb"] });
    expect(dup.ok && dup.redirectUris).toEqual(["https://a.example/cb"]);
  });

  it("refuses a bad redirect URI anywhere in the list", () => {
    const r = validateRegistration({ redirect_uris: ["https://a.example/cb", "javascript:alert(1)"] });
    expect(r).toMatchObject({ ok: false, error: "invalid_redirect_uri" });
  });

  it("is for public clients only: no secrets, no other grants", () => {
    expect(validateRegistration({ ...ok, token_endpoint_auth_method: "client_secret_basic" }).ok).toBe(false);
    expect(validateRegistration({ ...ok, grant_types: ["client_credentials"] }).ok).toBe(false);
    expect(validateRegistration({ ...ok, grant_types: ["password"] }).ok).toBe(false);
    expect(validateRegistration({ ...ok, response_types: ["token"] }).ok).toBe(false);
  });

  it("cleans the name it will show on the consent screen", () => {
    expect(normaliseClientName("  Claude\u0000 <b>Code</b>\n  ")).toBe("Claude bCode/b");
    expect(normaliseClientName("")).toBe("An app");
    expect(normaliseClientName("x".repeat(200))).toHaveLength(80);
    expect(normaliseClientName(undefined)).toBe("An app");
  });
});

describe("consent token", () => {
  const payload: ConsentPayload = { userId: "u1", clientId: "mcp_abc", redirectUri: "https://a.example/cb", codeChallenge: CHALLENGE, state: "st" };

  it("round-trips for the user it was issued to", () => {
    expect(verifyConsent(signConsent(payload), "u1")).toEqual(payload);
  });

  it("is refused for a different user", () => {
    expect(verifyConsent(signConsent(payload), "u2")).toBeNull();
  });

  it("expires after ten minutes", () => {
    const t = signConsent(payload, 1_000_000);
    expect(verifyConsent(t, "u1", 1_000_000 + 9 * 60_000)).toEqual(payload);
    expect(verifyConsent(t, "u1", 1_000_000 + 11 * 60_000)).toBeNull();
  });

  it("detects tampering with the payload, the signature or the format", () => {
    const t = signConsent(payload);
    const [body, sig] = t.split(".") as [string, string];
    const forged = Buffer.from(JSON.stringify({ ...payload, redirectUri: "https://evil.example/cb", exp: Date.now() + 60_000 })).toString("base64url");
    expect(verifyConsent(`${forged}.${sig}`, "u1")).toBeNull();
    expect(verifyConsent(`${body}.${sig.slice(0, -2)}AA`, "u1")).toBeNull();
    for (const bad of [undefined, null, 5, "", "nodot", "." + sig, "a".repeat(5000)]) expect(verifyConsent(bad, "u1")).toBeNull();
  });
});
