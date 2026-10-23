import { describe, it, expect, afterEach } from "vitest";
import { attemptAutoSecondAccount } from "./autoSecondAccount.js";
import { serve, closeServers, readBody } from "./testkit";
import { SIGNUP_FORM, whoami, run } from "./autoSecondAccount.testkit";

afterEach(closeServers);

// ─── Hardening: every case below was reproduced against the first version ─────
//
// Two independent reviewers simulated this module against stub servers. Each test here is one of
// their scenarios, written to FAIL on that version (it returned a "secondary" for every one of
// the rejected cases, and posted throwaway credentials to login forms and third parties).

describe("attemptAutoSecondAccount: a rejected or empty signup is not a session", () => {
  it.each([
    ["419 CSRF failure that still sets laravel_session and XSRF-TOKEN", 419, ["laravel_session=eyJ; Path=/", "XSRF-TOKEN=abc; Path=/"]],
    ["422 validation failure that sets a session cookie", 422, ["laravel_session=eyJ; Path=/"]],
    ["400 'email taken' that CLEARS a cookie", 400, ["session=; Max-Age=0; Path=/", "session=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/"]],
    ["500 with an anonymous connect.sid", 500, ["connect.sid=s%3Aanon; Path=/"]],
  ])("returns no account for a %s", async (_label, status, cookies) => {
    let posts = 0;
    const port = await serve(async (req, res) => {
      if (req.url === "/signup" && req.method === "GET") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM()); return; }
      if (req.url === "/signup" && req.method === "POST") {
        posts++;
        await readBody(req);
        res.writeHead(status, { "content-type": "text/html", "Set-Cookie": cookies }).end("<p>There was a problem with your submission.</p>");
        return;
      }
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(r.secondary).toBeNull();
    expect(posts).toBe(1);
  });

  it("returns no account when the cookie is empty even on a 200", async () => {
    const port = await serve(async (req, res) => {
      if (req.method === "GET" && req.url === "/signup") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM()); return; }
      if (req.method === "POST") { await readBody(req); res.writeHead(200, { "Set-Cookie": "session=; Path=/" }).end("ok"); return; }
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    expect((await run(t, () => attemptAutoSecondAccount(t))).secondary).toBeNull();
  });

  it("returns no account when the cookie does not turn the visitor into a signed-in user", async () => {
    // A 302 with a real-looking cookie, but the landing page is the same for everyone: the reviewers'
    // 'anonymous-equivalent identity', which made the IDOR probe read 'ran, 0 findings' about nothing.
    const port = await serve(async (req, res) => {
      if (req.method === "GET" && req.url === "/signup") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM()); return; }
      if (req.method === "POST") { await readBody(req); res.writeHead(302, { Location: "/dashboard", "Set-Cookie": "tracking=abc123; Path=/" }).end(); return; }
      res.writeHead(200, { "content-type": "text/html" }).end(`<h1>Acme</h1><p>The same page for everyone, whoever you are, with our product and pricing.</p>`);
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(r.secondary).toBeNull();
    expect(r.skippedReason).toMatch(/signed in|session/i);
  });

  it("does accept a real session that lands somewhere different from an anonymous visitor", async () => {
    const port = await serve(async (req, res) => {
      if (req.method === "GET" && req.url === "/signup") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM()); return; }
      if (req.method === "POST") { await readBody(req); res.writeHead(302, { Location: "/dashboard", "Set-Cookie": "sid=fresh; Path=/" }).end(); return; }
      if (whoami(req, res)) return;
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(r.secondary?.cookie).toBe("sid=fresh");
    expect(r.submitted).toBe(true);
    expect(r.email).toMatch(/^secscan-test-[0-9a-f]{12}@example\.com$/);
  });

  it("takes a session set on the SECOND redirect hop", async () => {
    const port = await serve(async (req, res) => {
      if (req.method === "GET" && req.url === "/signup") { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM()); return; }
      if (req.method === "POST") { await readBody(req); res.writeHead(302, { Location: "/auth/callback" }).end(); return; }
      if (req.url === "/auth/callback") { res.writeHead(302, { Location: "/dashboard", "Set-Cookie": "sid=fresh; Path=/" }).end(); return; }
      if (whoami(req, res)) return;
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(r.secondary?.cookie).toBe("sid=fresh");
  });
});

describe("attemptAutoSecondAccount: never a login form", () => {
  it("does not POST credentials to /login when /signup redirects there, even though the page says 'Sign up'", async () => {
    const posts: string[] = [];
    const port = await serve(async (req, res) => {
      if (req.method === "POST") { posts.push(req.url ?? ""); await readBody(req); res.writeHead(200, { "Set-Cookie": "flash=Invalid+credentials; Path=/" }).end("Invalid credentials"); return; }
      if (req.url === "/signup") { res.writeHead(302, { Location: "/login" }).end(); return; }
      if (req.url === "/login") {
        res.writeHead(200, { "content-type": "text/html" }).end(
          `<nav>Login / Register</nav><h1>Log in</h1><form method="POST" action="/login">
             <input type="email" name="email"><input type="password" name="password"><button>Log in</button></form>
           <p>Don't have an account? <a href="/register">Sign up</a></p><footer>Join our newsletter</footer>`,
        );
        return;
      }
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(posts).toEqual([]);
    expect(r.secondary).toBeNull();
    expect(r.submitted).toBeFalsy();
    expect(r.skippedReason).toMatch(/no self-serve signup/i);
  });

  it("does not POST to a login form served AT the signup path whose footer says 'Register'", async () => {
    const posts: string[] = [];
    const port = await serve(async (req, res) => {
      if (req.method === "POST") { posts.push(req.url ?? ""); await readBody(req); res.writeHead(200).end("no"); return; }
      if (req.url === "/signup") {
        res.writeHead(200, { "content-type": "text/html" }).end(
          `<h1>Welcome back</h1><form method="POST" action="/login"><input type="email" name="email"><input type="password" name="password"><button>Log in</button></form>
           <footer><a href="/register">Register</a> · Join us</footer>`,
        );
        return;
      }
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(posts).toEqual([]);
    expect(r.secondary).toBeNull();
  });

  it("picks the register form when a login form comes first on the same page", async () => {
    const posts: string[] = [];
    const port = await serve(async (req, res) => {
      if (req.method === "POST") {
        posts.push(req.url ?? ""); await readBody(req);
        if (req.url === "/register") { res.writeHead(302, { Location: "/dashboard", "Set-Cookie": "sid=fresh; Path=/" }).end(); return; }
        res.writeHead(200).end("bad login"); return;
      }
      if (req.url === "/signup") {
        res.writeHead(200, { "content-type": "text/html" }).end(
          `<form method="POST" action="/login"><input type="email" name="email"><input type="password" name="password"><button>Log in</button></form>
           <hr><h2>New here?</h2>
           <form method="POST" action="/register"><input type="email" name="email"><input type="password" name="password"><input type="password" name="password_confirmation"><button>Create account</button></form>`,
        );
        return;
      }
      if (whoami(req, res)) return;
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(posts).toEqual(["/register"]);
    expect(r.secondary?.cookie).toBe("sid=fresh");
  });

  it("does not take a single-password form with both 'Log in' and 'Sign up' wording inside it", async () => {
    const posts: string[] = [];
    const port = await serve(async (req, res) => {
      if (req.method === "POST") { posts.push(req.url ?? ""); await readBody(req); res.writeHead(200).end("no"); return; }
      if (req.url === "/signup") {
        res.writeHead(200, { "content-type": "text/html" }).end(
          `<form method="POST" action="/auth"><input type="email" name="email"><input type="password" name="password">
             <button>Log in</button> <span>No account? Sign up</span></form>`,
        );
        return;
      }
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    expect((await run(t, () => attemptAutoSecondAccount(t))).secondary).toBeNull();
    expect(posts).toEqual([]);
  });
});

describe("attemptAutoSecondAccount: one attempt, one account", () => {
  it("sends exactly one POST when the signup created the account but returned no cookie, though six paths alias the form", async () => {
    let posts = 0;
    const port = await serve(async (req, res) => {
      if (req.method === "POST") { posts++; await readBody(req); res.writeHead(302, { Location: "/login?registered=1" }).end(); return; }
      if (req.method === "GET" && /^\/(signup|sign-up|register|join|auth\/signup|auth\/register)$/.test(req.url ?? "")) {
        res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM(req.url));
        return;
      }
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(posts).toBe(1);
    expect(r.secondary).toBeNull();
    expect(r.submitted).toBe(true);
    expect(r.email).toMatch(/@example\.com$/);
    // Says a form WAS submitted, so the ledger cannot claim no attempt was made.
    expect(r.skippedReason).toMatch(/submitted/i);
  });

  it("does not resubmit on the next path after a POST that timed out on our side", async () => {
    let posts = 0;
    const port = await serve(async (req, res) => {
      if (req.method === "POST") { posts++; await readBody(req); setTimeout(() => res.writeHead(302, { Location: "/dashboard", "Set-Cookie": "sid=fresh" }).end(), 1_500); return; }
      if (req.method === "GET" && /^\/(signup|register|join)$/.test(req.url ?? "")) { res.writeHead(200, { "content-type": "text/html" }).end(SIGNUP_FORM(req.url)); return; }
      res.writeHead(404).end();
    });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t, { timeoutMs: 300 }));
    expect(posts).toBe(1);
    expect(r.secondary).toBeNull();
    expect(r.submitted).toBe(true);
  });

  it("does not POST at all when no page had a signup form, so nothing was created", async () => {
    const port = await serve(async (_req, res) => { res.writeHead(404).end(); });
    const t = `http://127.0.0.1:${port}/`;
    const r = await run(t, () => attemptAutoSecondAccount(t));
    expect(r.submitted).toBeFalsy();
    expect(r.email).toBeUndefined();
  });
});
