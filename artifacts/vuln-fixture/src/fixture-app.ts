import { sessionFromCookie } from "./fixture-sessions.js";
import type { Express } from "express";

/** The signed-in app: dashboard, planted paths, and the account page. */


export function mountApp(app: Express): void {
  // ─────────────────────────────────────────────────────────────────────────────
  // crawler-data.ts inner-route probes, nested under /app/ so the directory
  // prefix isn't "/" (which would just collide with the root-level findings
  // above). /app/dashboard is the page linked from home and actually crawled;
  // the rest are the sibling files the crawler probes once it's there.
  // ─────────────────────────────────────────────────────────────────────────────
  app.get("/app/dashboard", (_req, res) => {
    // Also misses a header the root has (CSP), for crawler.ts's own
    // "Content-Security-Policy Missing on Internal Routes" finding.
    res.removeHeader("Content-Security-Policy");

    // deserializationProbe.ts — a native serialized object in a cookie the server
    // issues (CWE-502). Planted HERE rather than on the root because the probe is
    // only reached from crawler.ts, which inspects crawled and probed pages; a
    // root-page cookie never passes through it.
    //
    // Every value below is a REAL serialized object, not a lookalike shaped to the
    // regex: they decode to the genuine magic bytes (Java AC ED 00 05, Ruby Marshal
    // 04 08, pickle protocol-2 80 02), each carrying {"user":"admin"}. A fixture
    // that matched the marker without being the thing the marker stands for would
    // verify the regex and nothing else. None is a gadget chain — the probe is
    // detection-only, and so is this.
    //
    // Four separate cookie names because the probe reports one format per cookie
    // and dedupes on name+format, so a single cookie could only ever prove one
    // marker. Between them these exercise both paths: the three base64 markers
    // that depend on the start-of-value anchor, and the PHP grammar marker that is
    // only reachable after URL-decoding.
    res.setHeader("Set-Cookie", [
      "jsession_state=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEdXNlcnQABWFkbWlueA==; Path=/",
      "_rails_session=BAh7BjoJdXNlciIKYWRtaW4GOgZFVA==; Path=/",
      "py_state=gAJ9cQBYBAAAAHVzZXJxAVgFAAAAYWRtaW5xAnMu; Path=/",
      `php_prefs=${encodeURIComponent('O:8:"stdClass":1:{s:4:"user";s:5:"admin";}')}; Path=/`,
    ]);

    res.type("text/html").send(`<!doctype html><html><head><title>Dashboard</title></head><body><h1>Dashboard</h1></body></html>`);
  });
  app.get("/app/.env", (_req, res) => {
    res.type("text/plain").send("DB_PASSWORD=hunter2\nAPI_KEY=fake-not-real-0000000000\n");
  });
  app.get("/app/swagger.json", (_req, res) => res.json({ swagger: "2.0", info: { title: "App API" }, paths: {} }));
  app.get("/app/openapi.json", (_req, res) => res.json({ openapi: "3.0.0", info: { title: "App API" }, paths: {} }));
  app.get("/app/api-docs", (_req, res) => res.json({ openapi: "3.0.0", paths: { "/x": {} } }));
  app.get("/app/.git/HEAD", (_req, res) => res.type("text/plain").send("ref: refs/heads/main\n"));
  // crawler-data.ts inner-route config probe: this one carries a credential-shaped key, so it IS a
  // sensitive exposure. A config that only holds public runtime settings must not be reported
  // (see the clean twin at /uploads/config.json below).
  app.get("/app/config.json", (_req, res) =>
    res.json({ apiUrl: "https://api.internal.example", featureFlags: { newUi: true }, dbPassword: "fixture-db-passw0rd-1234" }),
  );
  // Clean twin: public runtime configuration (an API URL and a feature flag). Nothing here is secret,
  // so no finding may name this path.
  app.get("/uploads/config.json", (_req, res) =>
    res.json({ apiUrl: "https://api.public.example", featureFlags: { newUi: true } }),
  );
  app.get("/app/debug.log", (_req, res) => {
    res.type("text/plain").send("[DEBUG] request received\n[ERROR] unhandled exception in handler\n[WARN] retrying\n".repeat(3));
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // accessControlProbe.ts — an HTML page naming a record (/account/1001), whose
  // content ignores the caller's identity: any signed-in session sees account
  // #1001's data, and any nearby id (mutateIdentifiers) does too, so this covers
  // both IDOR and "records enumerable by editing the identifier" from the one
  // bug. Anonymous is denied. Ids outside 1000-1099 do not exist and answer 404,
  // as a real record store does: the probe requests a made-up id to tell a
  // record from a layout that renders for anything.
  // ─────────────────────────────────────────────────────────────────────────────
  app.get("/account/:id", (req, res) => {
    const session = sessionFromCookie(req);
    if (!session) {
      res.status(401).type("text/html").send(
        `<html><body><h1>Sign in required</h1><form><input type="password" name="password"></form><p>You must log in to view this account.</p></body></html>`,
      );
      return;
    }
    if (!/^10\d\d$/.test(req.params.id)) {
      res.status(404).type("text/html").send(`<html><body><h1>Not found</h1></body></html>`);
      return;
    }
    // Deliberately does not check whether req.params.id belongs to `session` —
    // that is the bug. Renders account #1001 regardless of who asked or which
    // existing id was in the URL.
    res.type("text/html").send(
      `<html><body><h1>Account #1001</h1><p>Name: Alice Example</p><p>Email: alice@example.com</p>` +
        `<p>SSN: 078-05-1120</p><p>Plan: Enterprise</p><p>Balance: $4,213.00</p></body></html>`,
    );
  });
}
