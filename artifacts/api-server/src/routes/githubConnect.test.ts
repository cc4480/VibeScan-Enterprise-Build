import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import { generateKeyPairSync } from "node:crypto";

const saveLinks = vi.fn(async () => {});
const removeLink = vi.fn(async () => true);
vi.mock("../lib/githubLinks", () => ({
  saveLinks: (...a: unknown[]) => saveLinks(...(a as [])),
  removeLink: (...a: unknown[]) => removeLink(...(a as [])),
  linkedInstallations: async () => [],
}));

import githubConnectRouter from "./githubConnect";

// A throwaway key made for the test; nothing here is a GitHub credential.
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });

function makeApp(userId: string | null = "user-a") {
  const app = express();
  app.use(cookieParser());
  app.use((req, _res, next) => {
    (req as unknown as { log: unknown }).log = { info: () => {}, warn: () => {}, error: () => {} };
    (req as unknown as { isAuthenticated: () => boolean }).isAuthenticated = () => userId !== null;
    (req as unknown as { user: unknown }).user = userId ? { id: userId, email: `${userId}@example.com` } : undefined;
    next();
  });
  app.use("/api", githubConnectRouter);
  return app;
}

const cookieFor = (state: string, userId: string) => `gh_connect=${Buffer.from(JSON.stringify({ state, userId })).toString("base64url")}`;

const OLD = { ...process.env };
const realFetch = globalThis.fetch;

beforeEach(() => {
  saveLinks.mockClear();
  removeLink.mockClear();
  process.env["GITHUB_APP_ID"] = "4242";
  process.env["GITHUB_APP_PRIVATE_KEY"] = privateKey;
  process.env["GITHUB_APP_SLUG"] = "test-app";
  process.env["GITHUB_APP_CLIENT_ID"] = "Iv1.testclient";
  process.env["GITHUB_APP_CLIENT_SECRET"] = "not-a-real-secret";
});

afterEach(() => {
  process.env = { ...OLD };
  globalThis.fetch = realFetch;
});

describe("GET /api/github/connect", () => {
  it("sends a signed-out visitor to sign in first", async () => {
    const res = await request(makeApp(null)).get("/api/github/connect");
    expect(res.status).toBe(302);
    expect(res.headers["location"]).toBe("/sign-in?returnTo=%2Fscan");
  });

  it("says Connect GitHub is unavailable when the OAuth client is not configured", async () => {
    delete process.env["GITHUB_APP_CLIENT_SECRET"];
    const res = await request(makeApp()).get("/api/github/connect");
    expect(res.headers["location"]).toBe("/scan?github=unavailable");
  });

  it("sends the person to the App's install page with a state it also keeps in a short-lived cookie", async () => {
    const res = await request(makeApp()).get("/api/github/connect");
    expect(res.status).toBe(302);
    const location = new URL(res.headers["location"] as string);
    expect(location.origin + location.pathname).toBe("https://github.com/apps/test-app/installations/new");
    const state = location.searchParams.get("state")!;
    expect(state.length).toBeGreaterThan(20);
    const cookie = (res.headers["set-cookie"] as unknown as string[]).find((c) => c.startsWith("gh_connect="))!;
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/Path=\/api\/github/);
    const stored = JSON.parse(Buffer.from(cookie.split(";")[0]!.split("=")[1]!, "base64url").toString());
    expect(stored).toEqual({ state, userId: "user-a" });
  });
});

describe("GET /api/github/callback: only the trip this browser started, for this account", () => {
  it("refuses a return with no cookie", async () => {
    const res = await request(makeApp()).get("/api/github/callback?state=abc&code=xyz");
    expect(res.headers["location"]).toBe("/scan?github=expired");
    expect(saveLinks).not.toHaveBeenCalled();
  });

  it("refuses a state that does not match the cookie", async () => {
    const res = await request(makeApp()).get("/api/github/callback?state=forged&code=xyz").set("Cookie", cookieFor("real-state", "user-a"));
    expect(res.headers["location"]).toBe("/scan?github=expired");
    expect(saveLinks).not.toHaveBeenCalled();
  });

  it("refuses a cookie started by a different account", async () => {
    const res = await request(makeApp("user-b")).get("/api/github/callback?state=s1&code=xyz").set("Cookie", cookieFor("s1", "user-a"));
    expect(res.headers["location"]).toBe("/scan?github=expired");
    expect(saveLinks).not.toHaveBeenCalled();
  });

  it("asks GitHub to authorise when it came back without a code, keeping the same state", async () => {
    const res = await request(makeApp()).get("/api/github/callback?state=s1&installation_id=5&setup_action=update").set("Cookie", cookieFor("s1", "user-a"));
    expect(res.headers["location"]).toBe("https://github.com/login/oauth/authorize?client_id=Iv1.testclient&state=s1");
    expect(saveLinks).not.toHaveBeenCalled();
  });

  it("records only the installations of this App that GitHub lists for the person's own token", async () => {
    const calls: string[] = [];
    globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
      const u = String(url);
      calls.push(u);
      if (u.includes("/login/oauth/access_token")) return new Response(JSON.stringify({ access_token: "user-token" }), { status: 200 });
      if (u.includes("/user/installations")) {
        return new Response(JSON.stringify({ installations: [
          { id: 111, app_id: 4242, account: { login: "alice" } },
          { id: 222, app_id: 9999, account: { login: "other-app" } },
        ] }), { status: 200 });
      }
      return new Response("{}", { status: 404 });
    }) as unknown as typeof fetch;
    // The installation_id in the query is ignored: what counts is GitHub's own list.
    const res = await request(makeApp()).get("/api/github/callback?state=s1&code=c1&installation_id=999999").set("Cookie", cookieFor("s1", "user-a"));
    expect(res.headers["location"]).toBe("/scan?github=connected");
    expect(saveLinks).toHaveBeenCalledWith("user-a", [{ installationId: 111, accountLogin: "alice" }]);
    expect(calls.some((c) => c.includes("/user/installations"))).toBe(true);
  });

  it("says so when the person has no installation of this App", async () => {
    globalThis.fetch = vi.fn(async (url: string | URL | Request) =>
      String(url).includes("access_token")
        ? new Response(JSON.stringify({ access_token: "t" }), { status: 200 })
        : new Response(JSON.stringify({ installations: [] }), { status: 200 })) as unknown as typeof fetch;
    const res = await request(makeApp()).get("/api/github/callback?state=s1&code=c1").set("Cookie", cookieFor("s1", "user-a"));
    expect(res.headers["location"]).toBe("/scan?github=none");
    expect(saveLinks).not.toHaveBeenCalled();
  });

  it("reports an error, and records nothing, when GitHub rejects the code", async () => {
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({ error: "bad_verification_code" }), { status: 200 })) as unknown as typeof fetch;
    const res = await request(makeApp()).get("/api/github/callback?state=s1&code=used").set("Cookie", cookieFor("s1", "user-a"));
    expect(res.headers["location"]).toBe("/scan?github=error");
    expect(saveLinks).not.toHaveBeenCalled();
  });
});

describe("DELETE /api/github/installations/:id", () => {
  it("needs a signed-in account", async () => {
    const res = await request(makeApp(null)).delete("/api/github/installations/111");
    expect(res.status).toBe(401);
  });

  it("rejects an id that is not a number", async () => {
    const res = await request(makeApp()).delete("/api/github/installations/abc");
    expect(res.status).toBe(400);
    expect(removeLink).not.toHaveBeenCalled();
  });

  it("forgets the connection for this account only", async () => {
    const res = await request(makeApp()).delete("/api/github/installations/111");
    expect(res.status).toBe(200);
    expect(removeLink).toHaveBeenCalledWith("user-a", 111);
  });
});
