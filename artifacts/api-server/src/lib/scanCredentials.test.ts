import { describe, it, expect, beforeAll } from "vitest";
import { randomBytes } from "node:crypto";

// crypto.ts reads ENCRYPTION_KEY when it is first imported, so set it before
// the module under test is pulled in.
beforeAll(() => {
  process.env.ENCRYPTION_KEY ||= randomBytes(32).toString("base64");
});

const {
  validateCredentials,
  encryptCredentials,
  decryptCredentials,
  toScanHttpCredentials,
  looksSignedOut,
} = await import("./scanCredentials.js");

const base = { mode: "session" as const, authorized: true };

describe("validateCredentials", () => {
  it("refuses without the authorisation attestation", () => {
    const result = validateCredentials({ ...base, authorized: false, cookie: "sid=x" });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/authorised/i);
  });

  it("accepts a cookie or a bearer token in session mode", () => {
    expect(validateCredentials({ ...base, cookie: "sid=abc" }).ok).toBe(true);
    expect(validateCredentials({ ...base, bearerToken: "tok" }).ok).toBe(true);
  });

  it("refuses session mode with neither", () => {
    expect(validateCredentials({ ...base }).ok).toBe(false);
    expect(validateCredentials({ ...base, cookie: "   " }).ok).toBe(false);
  });

  it("requires a login URL, username and password in form mode", () => {
    const form = { mode: "form" as const, authorized: true };
    expect(validateCredentials({ ...form }).ok).toBe(false);
    expect(validateCredentials({ ...form, loginUrl: "https://x.example/login" }).ok).toBe(false);
    expect(
      validateCredentials({ ...form, loginUrl: "https://x.example/login", username: "u" }).ok,
    ).toBe(false);
    expect(
      validateCredentials({
        ...form,
        loginUrl: "https://x.example/login",
        username: "u",
        password: "p",
      }).ok,
    ).toBe(true);
  });

  it("refuses to post a password to a plain-HTTP login page", () => {
    const result = validateCredentials({
      mode: "form",
      authorized: true,
      loginUrl: "http://insecure.example/login",
      username: "u",
      password: "p",
    });
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/HTTPS/);
  });

  it("still allows http on localhost, where there is no network to sniff", () => {
    expect(
      validateCredentials({
        mode: "form",
        authorized: true,
        loginUrl: "http://localhost:3000/login",
        username: "u",
        password: "p",
      }).ok,
    ).toBe(true);
  });

  it("rejects a malformed login URL", () => {
    expect(
      validateCredentials({
        mode: "form",
        authorized: true,
        loginUrl: "not a url",
        username: "u",
        password: "p",
      }).ok,
    ).toBe(false);
  });
});

describe("encryptCredentials", () => {
  it("round-trips", () => {
    const input = { ...base, cookie: "sid=secret", bearerToken: "tok" };
    expect(decryptCredentials(encryptCredentials(input))).toEqual(input);
  });

  it("does not leave the secret readable in the stored blob", () => {
    const blob = encryptCredentials({ ...base, cookie: "sid=super-secret-value" });
    expect(blob).not.toContain("super-secret-value");
  });

  it("returns null for a blob it cannot decrypt, rather than throwing", () => {
    // What a row written under a different ENCRYPTION_KEY looks like.
    expect(decryptCredentials("not-a-valid-blob")).toBeNull();
  });
});

describe("toScanHttpCredentials", () => {
  it("maps a cookie and a bearer token onto headers", async () => {
    const creds = await toScanHttpCredentials({ ...base, cookie: "sid=abc", bearerToken: "tok" });
    expect(creds).toEqual({ cookie: "sid=abc", headers: { Authorization: "Bearer tok" } });
  });

  it("yields null when session mode carries nothing usable", async () => {
    expect(await toScanHttpCredentials({ ...base })).toBeNull();
  });

  it("never returns the password itself", async () => {
    const creds = await toScanHttpCredentials({ ...base, cookie: "sid=abc" });
    expect(JSON.stringify(creds)).not.toMatch(/password/i);
  });
});

describe("looksSignedOut", () => {
  it("spots a redirect to a login route", () => {
    expect(looksSignedOut("<html></html>", "https://app.example/login?next=/dash")).toBe(true);
    expect(looksSignedOut("<html></html>", "https://app.example/sign-in")).toBe(true);
  });

  it("spots a login form in the response body", () => {
    const body = `<h1>Please log in</h1><form><input type="password" name="p"></form>`;
    expect(looksSignedOut(body, "https://app.example/dashboard")).toBe(true);
  });

  it("does not fire on an ordinary authenticated page", () => {
    expect(looksSignedOut("<h1>Dashboard</h1><p>Welcome back</p>", "https://app.example/dashboard"))
      .toBe(false);
  });

  it("does not fire on a page that merely mentions logging in", () => {
    // A password field alone, or the words alone, are not enough.
    expect(looksSignedOut("<p>You were logged in at 10am</p>", "https://app.example/audit")).toBe(false);
  });
});
