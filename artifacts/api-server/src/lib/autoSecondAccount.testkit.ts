/**
 * Stub-target helpers for the autoSecondAccount tests (session, safety). A signed-in visitor is told
 * from an anonymous one by GET /api/me, / and /dashboard.
 */
import type http from "node:http";
import { runWithScanHttp } from "./http.js";
import { serve } from "./testkit";

export type Req = http.IncomingMessage;
export type Res = http.ServerResponse;


export const SIGNUP_FORM = (action = "/signup", extra = "") =>
  `<h1>Create your account</h1><form method="POST" action="${action}">
     <input type="email" name="email"><input type="password" name="password">${extra}
     <button>Sign up</button></form>`;

/** GET /api/me, / and /dashboard tell a signed-in visitor from an anonymous one. */
export function whoami(req: Req, res: Res, sid = "fresh"): boolean {
  const signedIn = (req.headers.cookie ?? "").includes(`sid=${sid}`);
  if (req.url === "/api/me") {
    if (signedIn) res.writeHead(200, { "content-type": "application/json" }).end(`{"id":"2001","email":"new@example.com"}`);
    else res.writeHead(401, { "content-type": "application/json" }).end(`{"error":"sign in"}`);
    return true;
  }
  if (req.url === "/" || req.url === "/dashboard") {
    res.writeHead(200, { "content-type": "text/html" }).end(
      signedIn
        ? `<h1>Welcome back</h1><p>Your orders, your invoices, your settings and your team members are listed below.</p>`
        : `<h1>Acme</h1><p>Please read about our product, our pricing and our customers before you decide.</p>`,
    );
    return true;
  }
  return false;
}

export const run = <T>(targetUrl: string, fn: () => Promise<T>, init: Record<string, unknown> = {}) =>
  runWithScanHttp({ targetUrl, ...init }, fn);

/** A server on 127.0.0.2: another host as far as the scan's scope is concerned, still loopback. */
export const serveElsewhere = (handler: (req: Req, res: Res) => void): Promise<number> => serve(handler, "127.0.0.2");
