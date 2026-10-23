import { describe, it, expect, afterEach } from "vitest";
import { attemptAutoSecondAccount } from "./autoSecondAccount.js";
import { serve, closeServers, readBody } from "./testkit";
import { SIGNUP_FORM, whoami, run, serveElsewhere } from "./autoSecondAccount.testkit";

afterEach(closeServers);

// ─── Hardening: every case below was reproduced against the first version ─────
//
// Two independent reviewers simulated this module against stub servers. Each test here is one of
// their scenarios, written to FAIL on that version (it returned a "secondary" for every one of
// the rejected cases, and posted throwaway credentials to login forms and third parties).

describe("attemptAutoSecondAccount: email verification, however it is signalled", () => {
  const VERIFY_MESSAGES = [
    "We sent a confirmation link to your email.",
    "Check your inbox",
    "Please verify your account",
    "Please confirm your e-mail address",
    "We have sent you a confirmation email",
    "You must activate your account before signing in",
    "Enter the 6-digit code we sent to you",
    `{"status":"pending_verification","email_verified":false}`,
  ];
  it.each(VERIFY_MESSAGES)("aborts on the message %j even with a session cookie", async (message) => {
    const port = await serve(async (req, res) => {
      if (req.method === "GET" && req.url === "/signup") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM()); return; }
      if (req.method === "POST") { await readBody(req); res.writeHead(200, { "Set-Cookie": "sid=fresh; Path=/" }).end(message); return; }
      if (whoami(req, res)) return;
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(r.secondary).toBeNull();
    expect(r.skippedReason).toMatch(/verification/i);
  });

  it("aborts when the 302 destination, which was never in the POST response, says to check your email", async () => {
    const port = await serve(async (req, res) => {
      if (req.method === "GET" && req.url === "/signup") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM()); return; }
      if (req.method === "POST") { await readBody(req); res.writeHead(302, { Location: "/welcome", "Set-Cookie": "sid=unverified123; Path=/" }).end(); return; }
      if (req.url === "/welcome") { res.writeHead(200, { "content-type": "text/html" }).end("<h1>Thanks!</h1><p>Please check your inbox to finish.</p>"); return; }
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(r.secondary).toBeNull();
    expect(r.skippedReason).toMatch(/verification/i);
  });

  it("aborts when the redirect target's URL says so (/check-your-email), without reading a body", async () => {
    const port = await serve(async (req, res) => {
      if (req.method === "GET" && req.url === "/signup") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM()); return; }
      if (req.method === "POST") { await readBody(req); res.writeHead(302, { Location: "/check-your-email", "Set-Cookie": "sid=unverified123; Path=/" }).end(); return; }
      res.writeHead(200, { "content-type": "text/html" }).end("<h1>Thanks</h1>");
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(r.secondary).toBeNull();
    expect(r.skippedReason).toMatch(/verification/i);
  });

  it("does not take 'consent' for 'email ... sent': a JSON success with a real session is accepted", async () => {
    // The old pattern had no word boundary before 'sent', so "email" followed by "consent" on one line
    // aborted a signup that had produced a working session, and the ledger blamed verification.
    const port = await serve(async (req, res) => {
      if (req.method === "GET" && req.url === "/signup") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM()); return; }
      if (req.method === "POST") { await readBody(req); res.writeHead(200, { "content-type": "application/json", "Set-Cookie": "sid=fresh; Path=/" }).end(`{"ok":true,"user":{"email":"x@example.com"},"consent":true}`); return; }
      if (whoami(req, res)) return;
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(r.skippedReason).toBeUndefined();
    expect(r.secondary?.cookie).toBe("sid=fresh");
  });

  it("ignores wording that lives only inside a <script> block", async () => {
    const port = await serve(async (req, res) => {
      if (req.method === "GET" && req.url === "/signup") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM()); return; }
      if (req.method === "POST") { await readBody(req); res.writeHead(200, { "content-type": "text/html", "Set-Cookie": "sid=fresh; Path=/" }).end(`<p>Welcome</p><script>var m="check your email if you want reminders";</script>`); return; }
      if (whoami(req, res)) return;
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    expect((await run(t, () => attemptAutoSecondAccount(t))).secondary?.cookie).toBe("sid=fresh");
  });
});

describe("attemptAutoSecondAccount: stays on the target", () => {
  it("does not POST the throwaway credentials to a third-party form action", async () => {
    const thirdParty: string[] = [];
    const idpPort = await serveElsewhere(async (req, res) => {
      thirdParty.push(`${req.method} ${req.url}`);
      await readBody(req);
      res.writeHead(200, { "Set-Cookie": "did=abc" }).end("ok");
    });
    const port = await serve(async (req, res) => {
      if (req.method === "GET" && req.url === "/signup") {
        res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM(`http://127.0.0.2:${idpPort}/dbconnections/signup`));
        return;
      }
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(thirdParty).toEqual([]);
    expect(r.secondary).toBeNull();
    expect(r.submitted).toBeFalsy();
  });

  it("does not use a signup page it was redirected to on another host", async () => {
    const seen: string[] = [];
    const idpPort = await serveElsewhere(async (req, res) => {
      seen.push(`${req.method} ${req.url}`);
      await readBody(req);
      if (req.method === "GET") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM("/signup")); return; }
      res.writeHead(200, { "Set-Cookie": "did=abc" }).end("ok");
    });
    const port = await serve((req, res) => {
      if (req.url === "/signup") { res.writeHead(302, { Location: `http://127.0.0.2:${idpPort}/signup` }).end(); return; }
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(seen).toEqual([]);
    expect(r.secondary).toBeNull();
  });

  it("never sends the scan's own signed-in credentials to the signup page or the POST", async () => {
    const cookiesSeen: Array<string | undefined> = [];
    const port = await serve(async (req, res) => {
      cookiesSeen.push(req.headers.cookie);
      if (req.method === "GET" && req.url === "/signup") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM()); return; }
      if (req.method === "POST") { await readBody(req); res.writeHead(302, { Location: "/dashboard", "Set-Cookie": "sid=fresh; Path=/" }).end(); return; }
      if (whoami(req, res)) return;
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    await run(t, () => attemptAutoSecondAccount(t), { credentials: { cookie: "sid=ALICE-PRIMARY", headers: { Authorization: "Bearer alice" } } });
    expect(cookiesSeen.filter((c) => c?.includes("ALICE"))).toEqual([]);
  });
});

describe("attemptAutoSecondAccount: never throws", () => {
  it("survives a malformed form action and still tries the next path", async () => {
    const posts: string[] = [];
    const port = await serve(async (req, res) => {
      if (req.method === "POST") { posts.push(req.url ?? ""); await readBody(req); res.writeHead(302, { Location: "/dashboard", "Set-Cookie": "sid=fresh; Path=/" }).end(); return; }
      if (req.url === "/signup") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM("http://")); return; }
      if (req.url === "/register") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM("/register")); return; }
      if (whoami(req, res)) return;
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(posts).toEqual(["/register"]);
    expect(r.secondary?.cookie).toBe("sid=fresh");
  });

  it("returns a result, not an exception, for an unparseable base URL", async () => {
    await expect(attemptAutoSecondAccount("not a url")).resolves.toMatchObject({ secondary: null });
  });
});

describe("attemptAutoSecondAccount: forms as real sites write them", () => {
  it("reads unquoted attributes and ignores data-* look-alikes", async () => {
    let body = "";
    const port = await serve(async (req, res) => {
      if (req.method === "GET" && req.url === "/signup") {
        res.writeHead(200, { "content-type": "text/html" }).end(
          `<h1>Sign up</h1><form method=post action=/signup>
             <input data-name="foo" name=email type=email>
             <input data-type="text" type=password name=password>
             <input type=text name=username>
             <input type=checkbox name=terms value=yes>
             <input type=checkbox name=newsletter value=on>
             <button>Create account</button></form>`,
        );
        return;
      }
      if (req.method === "POST") { body = await readBody(req); res.writeHead(302, { Location: "/dashboard", "Set-Cookie": "sid=fresh; Path=/" }).end(); return; }
      if (whoami(req, res)) return;
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(r.secondary?.cookie).toBe("sid=fresh");
    const params = new URLSearchParams(body);
    expect(params.get("email")).toMatch(/@example\.com$/);
    expect(params.get("foo")).toBeNull();
    expect(params.get("password")).toBeTruthy();
    expect(params.get("username")).toMatch(/^secscan-/);
    expect(params.get("terms")).toBe("yes");
    expect(params.has("newsletter")).toBe(false);
  });
});
