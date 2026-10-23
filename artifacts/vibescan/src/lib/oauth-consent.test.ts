import { describe, it, expect } from "vitest";
import { outcomeOf, signInUrl, whereTo, isSafeReturn, isReturnFor } from "./oauth-consent";

const preview = { client: { name: "Cursor" }, redirect: { host: "127.0.0.1:5000", kind: "local" }, account: "a@b.c", access: ["x"], consent: "tok" };

describe("outcomeOf: what the page does with the server's answer", () => {
  it("sends someone who is not signed in to sign in, and back to this exact request", () => {
    const o = outcomeOf(401, { error: "login_required" }, "/oauth/authorize?client_id=mcp_1&state=a%26b");
    expect(o).toEqual({ kind: "signin", to: "/sign-in?returnTo=%2Foauth%2Fauthorize%3Fclient_id%3Dmcp_1%26state%3Da%2526b" });
  });

  it("shows an error, and does not redirect, when the app or its return address is not valid", () => {
    expect(outcomeOf(400, { error: "invalid_redirect_uri", error_description: "This app asked to return to an address it did not register." }, "/x")).toEqual({
      kind: "invalid",
      message: "This app asked to return to an address it did not register.",
    });
    expect(outcomeOf(400, {}, "/x")).toEqual({ kind: "invalid", message: "This link is not valid." });
    expect(outcomeOf(500, null, "/x").kind).toBe("invalid");
  });

  it("goes back to the app when the server built an error redirect", () => {
    expect(outcomeOf(200, { redirectUrl: "http://127.0.0.1:5000/cb?error=invalid_scope" }, "/x")).toEqual({ kind: "back", url: "http://127.0.0.1:5000/cb?error=invalid_scope" });
  });

  it("shows the consent screen for a good request", () => {
    expect(outcomeOf(200, preview, "/x")).toEqual({ kind: "consent", preview });
  });

  it("refuses anything it does not recognise instead of guessing", () => {
    expect(outcomeOf(200, {}, "/x").kind).toBe("invalid");
    expect(outcomeOf(200, { consent: "t" }, "/x").kind).toBe("invalid");
    expect(outcomeOf(200, "html", "/x").kind).toBe("invalid");
  });
});

describe("signInUrl", () => {
  it("keeps the whole authorization request through sign-in", () => {
    const url = signInUrl("/oauth/authorize?a=1&b=2");
    expect(new URLSearchParams(url.split("?")[1]).get("returnTo")).toBe("/oauth/authorize?a=1&b=2");
  });
});

describe("whereTo", () => {
  it("names the kind of place, and warns about a web address", () => {
    expect(whereTo({ host: "localhost:1", kind: "local" })).toContain("your own computer");
    expect(whereTo({ host: "cursor://x", kind: "app" })).toContain("cursor://x");
    expect(whereTo({ host: "claude.ai", kind: "web" })).toContain("Only continue if you started this");
  });
});

describe("isSafeReturn", () => {
  it("allows web, loopback and app addresses", () => {
    for (const u of ["https://claude.ai/cb?code=1", "http://127.0.0.1:5000/cb", "cursor://anysphere.cursor-retrieval/cb?code=1"]) expect(isSafeReturn(u), u).toBe(true);
  });

  it("never navigates to a script, data or file address", () => {
    for (const u of ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "vbscript:x", "not a url", ""]) expect(isSafeReturn(u), u).toBe(false);
  });
});

describe("isReturnFor: the return address must be the one the preview showed", () => {
  const web = { host: "claude.ai", kind: "web" } as const;
  const local = { host: "127.0.0.1:5000", kind: "local" } as const;
  const app = { host: "cursor://anysphere.cursor-retrieval", kind: "app" } as const;

  it("accepts the registered address for its kind", () => {
    expect(isReturnFor("https://claude.ai/cb?code=1", web)).toBe(true);
    expect(isReturnFor("http://127.0.0.1:5000/cb?code=1", local)).toBe(true);
    expect(isReturnFor("cursor://anysphere.cursor-retrieval/cb?code=1", app)).toBe(true);
  });

  it("refuses another site over https, even though the scheme is fine", () => {
    expect(isReturnFor("https://evil.example/cb?code=1", web)).toBe(false);
    expect(isReturnFor("https://claude.ai.evil.example/cb", web)).toBe(false);
  });

  it("refuses a different port, a downgraded scheme, or another app", () => {
    expect(isReturnFor("http://127.0.0.1:6000/cb", local)).toBe(false);
    expect(isReturnFor("https://127.0.0.1:5000/cb", local)).toBe(false);
    expect(isReturnFor("https://claude.ai/cb", local)).toBe(false);
    expect(isReturnFor("vscode://other.app/cb", app)).toBe(false);
  });

  it("refuses script, data and unknown addresses whatever the preview says", () => {
    expect(isReturnFor("javascript:alert(1)", web)).toBe(false);
    expect(isReturnFor("data:text/html,x", { host: "unknown", kind: "app" })).toBe(false);
    expect(isReturnFor("not a url", web)).toBe(false);
  });
});
