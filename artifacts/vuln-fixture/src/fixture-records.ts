import type { Express } from "express";
import express from "express";

/** Records API, users and login. */


export function mountRecords(app: Express): void {
  // ─────────────────────────────────────────────────────────────────────────────
  // apiProbe.ts — the OpenAPI-declared /api/records/{id}. GET returns sensitive
  // fields to ANYONE (no auth check at all, and ignores identity — both the
  // "served without authentication" and the API-level IDOR finding come from
  // this one handler). DELETE on a nonexistent id is accepted (idempotent, 204)
  // without checking auth first — the BFLA finding. (A bare 404 would prove
  // nothing: any router answers 404 to a verb it never routed.)
  // ─────────────────────────────────────────────────────────────────────────────
  const RECORDS: Record<string, unknown> = {
    "1": { id: "1", owner: "alice@example.com", email: "alice@example.com", password_hash: "$2b$10$fakeHashNotReal000000000000000000000", ssn: "078-05-1120", balance: 4213 },
  };

  app.get("/api/records/:id", (req, res) => {
    // No auth check, and always the same record regardless of :id — the API
    // equivalent of the /account/:id bug above, and what makes both the
    // unauthenticated-access and cross-account comparisons fire from one route.
    res.json(RECORDS["1"]);
  });
  app.delete("/api/records/:id", (req, res) => {
    // Auth is never checked, and deleting a record that is not there is a
    // success (idempotent delete), so an unauthenticated DELETE of a nonexistent
    // id answers 2xx — the BFLA signature apiProbe.ts tests for.
    delete RECORDS[req.params.id];
    res.status(204).end();
  });
  app.patch("/api/records/:id", (req, res) => {
    if (!RECORDS[req.params.id]) {
      res.status(404).json({ error: "not found" });
      return;
    }
    Object.assign(RECORDS[req.params.id] as object, req.body ?? {});
    res.json(RECORDS[req.params.id]);
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // apiProbe.ts mass assignment — the OpenAPI spec already declares "role" on
  // this body, which is what the check reads; this handler also actually
  // applies it, so the bug is real and not just declared.
  // ─────────────────────────────────────────────────────────────────────────────
  app.post("/api/users", (req, res) => {
    const { email, role } = req.body ?? {};
    res.status(201).json({ id: "1003", email, role: role ?? "user" });
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // Login, for a real credentialed scan (session cookie / login-form mode)
  // rather than the verify script's direct-credential path. Two fixed accounts.
  // ─────────────────────────────────────────────────────────────────────────────
  app.get("/login", (_req, res) => {
    res.type("text/html").send(
      `<html><body><form method="post" action="/login"><input name="email"><input name="password" type="password"><button type="submit">Sign in</button></form></body></html>`,
    );
  });
  app.post("/login", express.urlencoded({ extended: false }), (req, res) => {
    const email = String(req.body?.email ?? "");
    const token = email === "bob@example.com" ? "bob-session-token" : "alice-session-token";
    res.setHeader("Set-Cookie", `session=${token}; Path=/`);
    res.redirect(302, "/account/1001");
  });

  // healthEndpointProbe.ts. Both in one app, in the order the probe tries them:
  // /api/health is the CLEAN twin (a bare status, which must be passed over),
  // /api/system/health leaks runtime details (the shape seen on a real site).
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", checks: { database: "ok", memory: "ok" } });
  });
  app.get("/api/system/health", (_req, res) => {
    res.json({ status: "Online", version: "public beta", uptimeSeconds: 45090, instance: "c7e7ccb7", memory: { rssMb: 100 } });
  });
}
