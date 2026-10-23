import { serve } from "./http.testkit";
import { describe, it, expect } from "vitest";
import http from "node:http";
import { scanFetch, runWithScanHttp, sessionWasLost } from "./http.js";

describe("session expiry mid-scan", () => {
  // A target whose session dies after N authenticated requests, standing in for
  // a real session timing out partway through a long scan.
  async function expiringTarget(validFor: number) {
    // Budget is per session version, so signing in again genuinely yields a
    // working session. A single global counter would make every replacement
    // session born already expired — modelling a login that can never succeed.
    const servedPerSession = new Map<string, number>();
    return serve((req, res) => {
      const cookie = req.headers.cookie ?? "";
      const version = /sid=v(\d+)/.exec(cookie)?.[1];
      const used = version === undefined ? 0 : servedPerSession.get(version) ?? 0;
      const stillValid = version !== undefined && used < validFor;
      if (stillValid) servedPerSession.set(version!, used + 1);

      res.writeHead(200, { "content-type": "text/html" });
      res.end(
        stillValid
          ? "<h1>Members area</h1>"
          : `<h1>Please log in</h1><form><input type="password" name="p"></form>`,
      );
    });
  }

  const detectSignedOut = (body: string) =>
    /<input[^>]+type=["']password["']/i.test(body) && /log in/i.test(body);

  // The URL the scan asked for has to reach the callback, not just the URL it
  // ended up at. Without it the callback cannot tell "I requested /login and
  // got a login page" (expected) from "I requested /account and was bounced to
  // one" (a dead session) — which is what made every authenticated scan report
  // a spurious expiry. looksSignedOut's own handling is covered in
  // scanCredentials.test.ts; this pins the wiring that feeds it.
  it("passes the requested URL, not just the final one, to detectSignedOut", async () => {
    const { port } = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<h1>ok</h1>");
    });

    const seen: Array<{ finalUrl: string; requestedUrl: string }> = [];

    await runWithScanHttp(
      {
        targetUrl: `http://localhost:${port}/`,
        credentials: { cookie: "sid=1" },
        detectSignedOut: (_body, finalUrl, requestedUrl) => {
          seen.push({ finalUrl, requestedUrl });
          return false;
        },
      },
      async () => {
        await scanFetch(`http://localhost:${port}/login`);
      },
    );

    expect(seen).toHaveLength(1);
    expect(seen[0]!.requestedUrl).toBe(`http://localhost:${port}/login`);
  });

  it("signs back in and retries, so the caller gets the authenticated page", async () => {
    const { port } = await expiringTarget(1);
    let logins = 0;

    const body = await runWithScanHttp(
      {
        targetUrl: `http://localhost:${port}/`,
        credentials: { cookie: "sid=v1" },
        detectSignedOut,
        onSessionLost: async () => {
          logins++;
          return { cookie: `sid=v${logins + 1}` };
        },
      },
      async () => {
        await scanFetch(`http://localhost:${port}/a`); // consumes the first session
        const second = await scanFetch(`http://localhost:${port}/b`); // sees expiry, re-auths
        return second?.body ?? "";
      },
    );

    expect(logins).toBe(1);
    expect(body).toContain("Members area");
  });

  it("records the loss even when re-authentication is impossible", async () => {
    // A pasted cookie has no renewal path, so onSessionLost is absent.
    const { port } = await expiringTarget(0);

    const lost = await runWithScanHttp(
      {
        targetUrl: `http://localhost:${port}/`,
        credentials: { cookie: "sid=v1" },
        detectSignedOut,
      },
      async () => {
        await scanFetch(`http://localhost:${port}/a`);
        return sessionWasLost();
      },
    );

    expect(lost).toBe(true);
  });

  it("gives up rather than looping when every attempt still looks signed out", async () => {
    const { port } = await expiringTarget(0);
    let logins = 0;

    await runWithScanHttp(
      {
        targetUrl: `http://localhost:${port}/`,
        credentials: { cookie: "sid=v1" },
        detectSignedOut,
        onSessionLost: async () => {
          logins++;
          return { cookie: "sid=v9" }; // never actually works
        },
      },
      async () => {
        for (let i = 0; i < 6; i++) await scanFetch(`http://localhost:${port}/p${i}`);
      },
    );

    // Capped per scan, so a permanently broken login cannot spawn one sign-in
    // per request for the rest of the scan.
    expect(logins).toBeLessThanOrEqual(2);
  });

  it("signs in once when several probes hit the expiry together", async () => {
    const { port } = await expiringTarget(0);
    let logins = 0;

    await runWithScanHttp(
      {
        targetUrl: `http://localhost:${port}/`,
        credentials: { cookie: "sid=v1" },
        detectSignedOut,
        onSessionLost: async () => {
          logins++;
          await new Promise((r) => setTimeout(r, 20));
          return { cookie: "sid=v2" };
        },
      },
      async () => {
        await Promise.all(
          Array.from({ length: 8 }, (_, i) => scanFetch(`http://localhost:${port}/c${i}`)),
        );
      },
    );

    expect(logins).toBe(1);
  });

  it("does not sign in again for a reply that was sent with the old session", async () => {
    // Deterministic version of the race above: /fast answers at once and
    // triggers the re-login; /slow was sent with the same dead session but
    // answers only after that re-login finished. The slow reply must be
    // retried with the new session, not spend a second sign-in.
    const { port } = await serve((req, res) => {
      const reply = () => {
        const fresh = /sid=v2/.test(req.headers.cookie ?? "");
        res.writeHead(200, { "content-type": "text/html" });
        res.end(fresh ? "<h1>Members area</h1>" : `<h1>Please log in</h1><form><input type="password" name="p"></form>`);
      };
      if (req.url?.startsWith("/slow") && !/sid=v2/.test(req.headers.cookie ?? "")) setTimeout(reply, 150);
      else reply();
    });
    let logins = 0;

    const bodies = await runWithScanHttp(
      {
        targetUrl: `http://localhost:${port}/`,
        credentials: { cookie: "sid=v1" },
        detectSignedOut,
        onSessionLost: async () => {
          logins++;
          await new Promise((r) => setTimeout(r, 10));
          return { cookie: "sid=v2" };
        },
      },
      async () =>
        Promise.all([scanFetch(`http://localhost:${port}/slow`), scanFetch(`http://localhost:${port}/fast`)]).then((rs) =>
          rs.map((r) => r?.body ?? ""),
        ),
    );

    expect(logins).toBe(1);
    // Both callers still get the authenticated page.
    expect(bodies.every((b) => b.includes("Members area"))).toBe(true);
  });

  it("leaves an unauthenticated scan alone", async () => {
    const { port } = await expiringTarget(0);
    const lost = await runWithScanHttp(
      { targetUrl: `http://localhost:${port}/`, detectSignedOut },
      async () => {
        await scanFetch(`http://localhost:${port}/a`);
        return sessionWasLost();
      },
    );
    // No credentials were supplied, so there was no session to lose.
    expect(lost).toBe(false);
  });
});
