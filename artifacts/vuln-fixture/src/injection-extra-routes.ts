/**
 * Routes for the template-injection, header-injection and reflected-XSS content-type
 * checks (injectionExtra.ts, injectionProbe.ts). Each vulnerable route has a clean twin
 * that does the same job safely; the scanner must report the first and not the second.
 *
 *   /tpl?name=       evaluates ${a*b} and {{a*b}} in its input       VULNERABLE (SSTI)
 *   /hello?name=     shows the same input as escaped text            clean twin
 *   /lang?set=       writes the value into a header without care     VULNERABLE (CRLF)
 *   /lang2?set=      URL-encodes the value before using it           clean twin
 *   /api/echo?echoq= returns the input, angle brackets intact, as     clean twin (JSON is not HTML)
 *                    application/json
 */
import type { Express } from "express";

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
// What a vulnerable template engine does with its input: it computes it.
const evaluate = (s: string) =>
  s.replace(/\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}|\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}/g, (_m, a, b, c, d) => String(Number(a ?? c) * Number(b ?? d)));

export const INJECTION_EXTRA_LINKS = `
  <a href="/tpl?name=guest">Greeting</a>
  <a href="/hello?name=guest">Greeting (static)</a>
  <a href="/lang?set=en">Language</a>
  <a href="/lang2?set=en">Language (static)</a>
  <a href="/api/echo?echoq=hello">Echo</a>`;

export function mountInjectionExtras(app: Express): void {
  app.get("/tpl", (req, res) => {
    const name = String(req.query.name ?? "");
    res.type("text/html").send(`<html><body><h1>Hello ${escapeHtml(evaluate(name))}</h1></body></html>`);
  });
  app.get("/hello", (req, res) => {
    res.type("text/html").send(`<html><body><h1>Hello ${escapeHtml(String(req.query.name ?? ""))}</h1></body></html>`);
  });

  // Node refuses a line break in setHeader, so the vulnerable route writes the raw
  // response itself, which is exactly what a hand-built or very old server does.
  app.get("/lang", (req, res) => {
    const value = String(req.query.set ?? "");
    res.socket?.write(`HTTP/1.1 302 Found\r\nLocation: /?lang=${value}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
    res.socket?.end();
  });
  app.get("/lang2", (req, res) => {
    res.redirect(302, `/?lang=${encodeURIComponent(String(req.query.set ?? ""))}`);
  });

  app.get("/api/echo", (req, res) => {
    res.json({ echo: String(req.query.echoq ?? "") });
  });
}
