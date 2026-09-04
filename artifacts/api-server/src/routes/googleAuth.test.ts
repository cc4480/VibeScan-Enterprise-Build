import { describe, it, expect, beforeEach, afterEach } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import googleAuthRouter from "./googleAuth";

/**
 * These cover the parts that are ours rather than openid-client's: whether the
 * routes exist at all when unconfigured, and whether the post-sign-in redirect
 * can be pointed off-site. The token exchange itself belongs to openid-client
 * and is not re-tested here.
 */
function makeApp() {
  const app = express();
  app.use(cookieParser());
  // The real app attaches a logger via pino-http; the routes only use
  // req.log.{info,warn,error}.
  app.use((req, _res, next) => {
    (req as unknown as { log: unknown }).log = {
      info: () => {},
      warn: () => {},
      error: () => {},
    };
    next();
  });
  app.use("/api", googleAuthRouter);
  return app;
}

const OLD = { ...process.env };

beforeEach(() => {
  delete process.env["GOOGLE_CLIENT_ID"];
  delete process.env["GOOGLE_CLIENT_SECRET"];
  process.env["APP_ORIGIN"] = "https://secscan.us";
});

afterEach(() => {
  process.env = { ...OLD };
});

describe("google sign-in when not configured", () => {
  it("reports unavailable rather than 404 on the start route", async () => {
    // A 404 would look like the feature does not exist; 503 says it exists and
    // is not switched on, which is the difference between "wrong build" and
    // "missing environment variable" when someone is debugging a deploy.
    const res = await request(makeApp()).get("/api/auth/google");
    expect(res.status).toBe(503);
  });

  it("reports unavailable on the callback too", async () => {
    const res = await request(makeApp()).get("/api/auth/google/callback?code=x");
    expect(res.status).toBe(503);
  });
});

describe("google sign-in callback guards", () => {
  beforeEach(() => {
    process.env["GOOGLE_CLIENT_ID"] = "test-client-id";
    process.env["GOOGLE_CLIENT_SECRET"] = "test-secret";
  });

  it("refuses a callback with no PKCE cookie", async () => {
    // Without the cookie there is no code verifier and no expected state, so
    // there is nothing to validate the response against.
    const res = await request(makeApp()).get("/api/auth/google/callback?code=x&state=y");
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/expired/i);
  });

  it("refuses a malformed PKCE cookie rather than throwing", async () => {
    const res = await request(makeApp())
      .get("/api/auth/google/callback?code=x&state=y")
      .set("Cookie", "g_pkce=not-base64-json");
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/malformed/i);
  });
});

describe("returnTo handling", () => {
  beforeEach(() => {
    process.env["GOOGLE_CLIENT_ID"] = "test-client-id";
    process.env["GOOGLE_CLIENT_SECRET"] = "test-secret";
  });

  /**
   * The start route stores returnTo in the cookie it sets, so the sanitising is
   * observable there without completing a token exchange. An open redirect on a
   * sign-in route is worth a test of its own: it is the classic way to make a
   * phishing link look like it belongs to the site.
   */
  async function storedReturnTo(query: string): Promise<string | undefined> {
    const res = await request(makeApp()).get(`/api/auth/google${query}`);
    const setCookie = res.headers["set-cookie"];
    const header = Array.isArray(setCookie) ? setCookie.join(";") : String(setCookie ?? "");
    const match = /g_pkce=([^;]+)/.exec(header);
    if (!match?.[1]) return undefined;
    const parsed = JSON.parse(
      Buffer.from(decodeURIComponent(match[1]), "base64url").toString(),
    ) as { returnTo: string };
    return parsed.returnTo;
  }

  it("keeps a same-site path", async () => {
    expect(await storedReturnTo("?returnTo=/dashboard")).toBe("/dashboard");
  });

  it("rejects an absolute URL to another site", async () => {
    expect(await storedReturnTo("?returnTo=https://evil.example/x")).toBe("/");
  });

  it("rejects a protocol-relative URL", async () => {
    // "//evil.example" passes a naive startsWith("/") check and still leaves
    // the site, which is exactly why that check is not the one used.
    expect(await storedReturnTo("?returnTo=//evil.example")).toBe("/");
  });

  it("falls back to the root when absent", async () => {
    expect(await storedReturnTo("")).toBe("/");
  });
});
