/**
 * Connect GitHub, over real HTTP against a REAL Postgres (BILLING_TEST_DATABASE_URL): the real routes, the real
 * links table, and a real local server that answers like GitHub (lib/githubStub.testkit.ts) in place of github.com.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import { generateKeyPairSync } from "node:crypto";
import { dbSuiteOf, useRealDb, openDb } from "../lib/realDb.testkit";
import { startGithubStub, useRealGithub, type GithubStub } from "../lib/githubStub.testkit";

useRealDb();

// A throwaway key made for the test; nothing here is a GitHub credential.
const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
const REDIRECT = encodeURIComponent("https://secscan.us/api/github/callback");
const OLD = { ...process.env };

dbSuiteOf(describe)("Connect GitHub (real Postgres, local GitHub)", () => {
  let dbMod: typeof import("@workspace/db");
  let router: import("express").IRouter;
  let links: typeof import("../lib/githubLinks");
  let gh: GithubStub;
  const users: string[] = [];
  let n = 0;
  const newUser = () => {
    const id = `ghc-${Date.now()}-${++n}`;
    users.push(id);
    return id;
  };

  function makeApp(userId: string | null) {
    const app = express();
    app.use(cookieParser());
    app.use((req, _res, next) => {
      (req as unknown as { log: unknown }).log = { info: () => {}, warn: () => {}, error: () => {} };
      (req as unknown as { isAuthenticated: () => boolean }).isAuthenticated = () => userId !== null;
      (req as unknown as { user: unknown }).user = userId ? { id: userId, email: `${userId}@example.com` } : undefined;
      next();
    });
    app.use("/api", router);
    return app;
  }
  const cookieFor = (state: string, userId: string, stage?: "start" | "installing") =>
    `gh_connect=${Buffer.from(JSON.stringify({ state, userId, ...(stage ? { stage } : {}) })).toString("base64url")}`;
  const storedCookie = (res: request.Response) => {
    const cookie = (res.headers["set-cookie"] as unknown as string[]).find((c) => c.startsWith("gh_connect="))!;
    return { raw: cookie, value: JSON.parse(Buffer.from(cookie.split(";")[0]!.split("=")[1]!, "base64url").toString()) };
  };

  beforeAll(async () => {
    dbMod = await openDb();
    links = await import("../lib/githubLinks");
    router = (await import("./githubConnect")).default;
    gh = await startGithubStub();
  }, 60_000);

  beforeEach(() => {
    gh.clear();
    process.env["GITHUB_API_URL"] = gh.api;
    process.env["GITHUB_WEB_URL"] = gh.web;
    process.env["GITHUB_RAW_URL"] = gh.raw;
    process.env["GITHUB_APP_ID"] = "4242";
    process.env["GITHUB_APP_PRIVATE_KEY"] = privateKey;
    process.env["GITHUB_APP_SLUG"] = "test-app";
    process.env["GITHUB_APP_CLIENT_ID"] = "Iv1.testclient";
    process.env["GITHUB_APP_CLIENT_SECRET"] = "not-a-real-secret";
  });

  afterAll(async () => {
    await gh.stop();
    useRealGithub();
    process.env = { ...OLD };
    const { inArray } = await import("drizzle-orm");
    if (users.length) await dbMod.db.delete(dbMod.githubInstallationsTable).where(inArray(dbMod.githubInstallationsTable.userId, users));
    await dbMod?.pool?.end?.();
  });

  describe("GET /api/github/connect", () => {
    it("sends a signed-out visitor to sign in first", async () => {
      const res = await request(makeApp(null)).get("/api/github/connect");
      expect(res.status).toBe(302);
      expect(res.headers["location"]).toBe("/sign-in?returnTo=%2Fscan");
    });

    it("says Connect GitHub is unavailable when the OAuth client is not configured", async () => {
      delete process.env["GITHUB_APP_CLIENT_SECRET"];
      const res = await request(makeApp(newUser())).get("/api/github/connect");
      expect(res.headers["location"]).toBe("/scan?github=unavailable");
    });

    it("starts by asking GitHub who the person is, with a state it also keeps in a short-lived cookie", async () => {
      const user = newUser();
      const res = await request(makeApp(user)).get("/api/github/connect");
      expect(res.status).toBe(302);
      const location = new URL(res.headers["location"] as string);
      // Authorise first, not the install page: an existing installation is found and the person returns at once.
      expect(location.origin + location.pathname).toBe(`${gh.web}/login/oauth/authorize`);
      expect(location.searchParams.get("client_id")).toBe("Iv1.testclient");
      expect(location.searchParams.get("redirect_uri")).toBe("https://secscan.us/api/github/callback");
      const state = location.searchParams.get("state")!;
      expect(state.length).toBeGreaterThan(20);
      const cookie = storedCookie(res);
      expect(cookie.raw).toMatch(/HttpOnly/);
      expect(cookie.raw).toMatch(/Path=\/api\/github/);
      expect(cookie.value).toEqual({ state, userId: user, stage: "start" });
    });
  });

  describe("GET /api/github/connect?manage=1", () => {
    it("goes straight to GitHub's page for choosing repositories, and remembers it did", async () => {
      const user = newUser();
      const res = await request(makeApp(user)).get("/api/github/connect?manage=1");
      const location = new URL(res.headers["location"] as string);
      expect(location.origin + location.pathname).toBe(`${gh.web}/apps/test-app/installations/new`);
      expect(storedCookie(res).value).toEqual({ state: location.searchParams.get("state"), userId: user, stage: "installing" });
    });
  });

  describe("GET /api/github/callback: only the trip this browser started, for this account", () => {
    it("refuses a return with no cookie", async () => {
      const res = await request(makeApp(newUser())).get("/api/github/callback?state=abc&code=xyz");
      expect(res.headers["location"]).toBe("/scan?github=expired");
      expect(gh.requests).toHaveLength(0);
    });

    it("refuses a state that does not match the cookie", async () => {
      const user = newUser();
      const res = await request(makeApp(user)).get("/api/github/callback?state=forged&code=xyz").set("Cookie", cookieFor("real-state", user));
      expect(res.headers["location"]).toBe("/scan?github=expired");
      expect(gh.requests).toHaveLength(0);
      expect(await links.linkedInstallations(user)).toEqual([]);
    });

    it("refuses a cookie started by a different account", async () => {
      const a = newUser();
      const b = newUser();
      const res = await request(makeApp(b)).get("/api/github/callback?state=s1&code=xyz").set("Cookie", cookieFor("s1", a));
      expect(res.headers["location"]).toBe("/scan?github=expired");
      expect(await links.linkedInstallations(b)).toEqual([]);
    });

    it("asks GitHub to authorise when it came back without a code, keeping the same state", async () => {
      const user = newUser();
      const res = await request(makeApp(user)).get("/api/github/callback?state=s1&installation_id=5&setup_action=update").set("Cookie", cookieFor("s1", user));
      expect(res.headers["location"]).toBe(`${gh.web}/login/oauth/authorize?client_id=Iv1.testclient&state=s1&redirect_uri=${REDIRECT}`);
      expect(await links.linkedInstallations(user)).toEqual([]);
    });

    it("records only the installations of this App that GitHub lists for the person's own token", async () => {
      const user = newUser();
      gh.on("POST", "web", "/login/oauth/access_token", { json: { access_token: "user-token" } });
      gh.on("GET", "api", "/user/installations", { json: { installations: [
        { id: 111, app_id: 4242, account: { login: "alice" } },
        { id: 222, app_id: 9999, account: { login: "other-app" } },
      ] } });
      // The installation_id in the query is ignored: what counts is GitHub's own list.
      const res = await request(makeApp(user)).get("/api/github/callback?state=s1&code=c1&installation_id=999999").set("Cookie", cookieFor("s1", user));
      expect(res.headers["location"]).toBe("/scan?github=connected");
      expect(await links.linkedInstallations(user)).toEqual([{ installationId: 111, accountLogin: "alice" }]);
      expect(gh.requests.find((r) => r.path === "/user/installations")!.headers["authorization"]).toBe("Bearer user-token");
    });

    const noInstallations = () => {
      gh.on("POST", "web", "/login/oauth/access_token", { json: { access_token: "t" } });
      gh.on("GET", "api", "/user/installations", { json: { installations: [] } });
    };

    it("sends a person with nothing installed on to the install page, once, keeping the same state", async () => {
      noInstallations();
      const user = newUser();
      const res = await request(makeApp(user)).get("/api/github/callback?state=s1&code=c1").set("Cookie", cookieFor("s1", user, "start"));
      expect(res.headers["location"]).toBe(`${gh.web}/apps/test-app/installations/new?state=s1`);
      expect(await links.linkedInstallations(user)).toEqual([]);
      expect(storedCookie(res).value).toEqual({ state: "s1", userId: user, stage: "installing" });
    });

    it("says so, instead of looping, when they come back from the install page still with nothing", async () => {
      noInstallations();
      const user = newUser();
      const res = await request(makeApp(user)).get("/api/github/callback?state=s1&code=c1").set("Cookie", cookieFor("s1", user, "installing"));
      expect(res.headers["location"]).toBe("/scan?github=none");
      expect(await links.linkedInstallations(user)).toEqual([]);
    });

    it("connects an installation that already exists without ever visiting the install page", async () => {
      gh.on("POST", "web", "/login/oauth/access_token", { json: { access_token: "t" } });
      gh.on("GET", "api", "/user/installations", { json: { installations: [{ id: 111, app_id: 4242, account: { login: "alice" } }] } });
      const user = newUser();
      const res = await request(makeApp(user)).get("/api/github/callback?state=s1&code=c1").set("Cookie", cookieFor("s1", user, "start"));
      expect(res.headers["location"]).toBe("/scan?github=connected");
      expect(await links.linkedInstallations(user)).toEqual([{ installationId: 111, accountLogin: "alice" }]);
    });

    it("treats a cookie from before stages existed as the start of the trip", async () => {
      noInstallations();
      const user = newUser();
      const res = await request(makeApp(user)).get("/api/github/callback?state=s1&code=c1").set("Cookie", cookieFor("s1", user));
      expect(res.headers["location"]).toBe(`${gh.web}/apps/test-app/installations/new?state=s1`);
    });

    it("reports an error, and records nothing, when GitHub rejects the code", async () => {
      gh.on("POST", "web", "/login/oauth/access_token", { json: { error: "bad_verification_code" } });
      const user = newUser();
      const res = await request(makeApp(user)).get("/api/github/callback?state=s1&code=used").set("Cookie", cookieFor("s1", user));
      expect(res.headers["location"]).toBe("/scan?github=error");
      expect(await links.linkedInstallations(user)).toEqual([]);
    });
  });

  describe("GET /api/github/repos", () => {
    it("needs a signed-in account", async () => {
      expect((await request(makeApp(null)).get("/api/github/repos")).status).toBe(401);
    });

    it("says how each connection stands, so an uninstalled App is not shown as 'nothing shared'", async () => {
      const user = newUser();
      await links.saveLinks(user, [
        { installationId: 1, accountLogin: "alice" },
        { installationId: 2, accountLogin: "old-org" },
        { installationId: 3, accountLogin: "empty" },
      ]);
      gh.on("POST", "api", "/app/installations/1/access_tokens", { status: 201, json: { token: "tok1" } });
      gh.on("POST", "api", "/app/installations/2/access_tokens", { status: 404, json: {} });
      gh.on("POST", "api", "/app/installations/3/access_tokens", { status: 201, json: { token: "tok3" } });
      gh.on("GET", "api", "/installation/repositories", { json: { repositories: [] } });

      const res = await request(makeApp(user)).get("/api/github/repos");
      expect(res.status).toBe(200);
      const by = Object.fromEntries((res.body.connections as Array<{ installationId: number; status: string }>).map((c) => [c.installationId, c.status]));
      expect(by).toEqual({ 1: "ok", 2: "gone", 3: "ok" });
      expect(res.body.available).toBe(true);
      expect(res.body.repositories).toEqual([]);
    });
  });

  describe("DELETE /api/github/installations/:id", () => {
    it("needs a signed-in account", async () => {
      expect((await request(makeApp(null)).delete("/api/github/installations/111")).status).toBe(401);
    });

    it("rejects an id that is not a number", async () => {
      const user = newUser();
      await links.saveLinks(user, [{ installationId: 111, accountLogin: "alice" }]);
      expect((await request(makeApp(user)).delete("/api/github/installations/abc")).status).toBe(400);
      expect(await links.linkedInstallations(user)).toHaveLength(1);
    });

    it("forgets the connection for this account only", async () => {
      const mine = newUser();
      const theirs = newUser();
      await links.saveLinks(mine, [{ installationId: 111, accountLogin: "alice" }]);
      await links.saveLinks(theirs, [{ installationId: 111, accountLogin: "alice" }]);
      const res = await request(makeApp(mine)).delete("/api/github/installations/111");
      expect(res.status).toBe(200);
      expect(await links.linkedInstallations(mine)).toEqual([]);
      expect(await links.linkedInstallations(theirs)).toHaveLength(1);
    });
  });
});
