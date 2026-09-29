import { describe, it, expect, afterEach } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { runWithScanHttp } from "./http.js";
import { attemptAutoSecondAccount } from "./autoSecondAccount.js";

const servers: http.Server[] = [];

async function serve(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<number> {
  const srv = http.createServer(handler);
  servers.push(srv);
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  return (srv.address() as AddressInfo).port;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
  });
}

describe("attemptAutoSecondAccount", () => {
  it("signs up and returns credentials when the target grants an immediate session", async () => {
    const port = await serve(async (req, res) => {
      if (req.url === "/signup" && req.method === "GET") {
        res.writeHead(200, { "content-type": "text/html" });
        res.end(
          `<h1>Sign up</h1><form method="POST" action="/signup">
             <input type="email" name="email">
             <input type="password" name="password">
             <input type="hidden" name="csrf" value="tok123">
             <button>Create account</button>
           </form>`,
        );
        return;
      }
      if (req.url === "/signup" && req.method === "POST") {
        const body = await readBody(req);
        // URL-encoded form body: '@' is percent-encoded as %40.
        expect(body).toContain("csrf=tok123");
        expect(decodeURIComponent(body)).toContain("@example.com");
        res.writeHead(302, { Location: "/dashboard", "Set-Cookie": "sid=freshsession; Path=/" });
        res.end();
        return;
      }
      // The session has to DO something: the dashboard is a page only a signed-in visitor gets. The
      // first version of this test served a 404 here and passed on the cookie alone, which is the
      // very defect the hardening below removes.
      if (req.url === "/dashboard") {
        if ((req.headers.cookie ?? "").includes("sid=freshsession")) {
          res.writeHead(200, { "content-type": "text/html" }).end("<h1>Your dashboard</h1><p>Orders, invoices and team members.</p>");
        } else {
          res.writeHead(302, { Location: "/signup" }).end();
        }
        return;
      }
      res.writeHead(404).end();
    });

    const targetUrl = `http://127.0.0.1:${port}/`;
    const result = await runWithScanHttp({ targetUrl }, () => attemptAutoSecondAccount(targetUrl));

    expect(result.secondary).not.toBeNull();
    expect(result.secondary?.cookie).toContain("sid=freshsession");
  });

  it("aborts cleanly and returns no secondary when email verification is required", async () => {
    const port = await serve(async (req, res) => {
      if (req.url === "/signup" && req.method === "GET") {
        res.writeHead(200, { "content-type": "text/html" });
        res.end(
          `<h1>Register</h1><form method="POST" action="/signup">
             <input type="email" name="email"><input type="password" name="password">
           </form>`,
        );
        return;
      }
      if (req.url === "/signup" && req.method === "POST") {
        res.writeHead(200, { "content-type": "text/html" });
        res.end("<p>Almost there! We sent a confirmation link to your email.</p>");
        return;
      }
      res.writeHead(404).end();
    });

    const targetUrl = `http://127.0.0.1:${port}/`;
    const result = await runWithScanHttp({ targetUrl }, () => attemptAutoSecondAccount(targetUrl));

    expect(result.secondary).toBeNull();
    expect(result.skippedReason).toMatch(/verification/i);
  });

  it("does not mistake a login form for a signup form", async () => {
    const port = await serve((req, res) => {
      if (req.url === "/signup") {
        res.writeHead(200, { "content-type": "text/html" });
        // A page at a signup path that is actually just a login form, with no
        // signup language anywhere.
        res.end(
          `<h1>Log in</h1><form method="POST" action="/login">
             <input type="email" name="email"><input type="password" name="password">
           </form>`,
        );
        return;
      }
      res.writeHead(404).end();
    });

    const targetUrl = `http://127.0.0.1:${port}/`;
    const result = await runWithScanHttp({ targetUrl }, () => attemptAutoSecondAccount(targetUrl));

    expect(result.secondary).toBeNull();
    expect(result.skippedReason).toMatch(/no self-serve signup/i);
  });

  it("returns no secondary when no signup path exists at all", async () => {
    const port = await serve((_req, res) => {
      res.writeHead(404).end();
    });

    const targetUrl = `http://127.0.0.1:${port}/`;
    const result = await runWithScanHttp({ targetUrl }, () => attemptAutoSecondAccount(targetUrl));

    expect(result.secondary).toBeNull();
  });
});
