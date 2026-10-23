/**
 * An API that only a running browser can find (runtimeApiChecks in the verify script).
 *
 * /assets/boot.js assembles the URL from parts at runtime, so no string literal in any
 * shipped file names it and the bundle scan cannot see it. Rendering the page in a real
 * browser and watching its requests can. The endpoint is a search-shaped route that
 * leaks a database error for a stray quote, so a probe that reaches it reports it.
 */
import type { Express } from "express";

export const BOOT_JS = `
// no literal "/api/..." string anywhere: the path is put together when the page runs
fetch(["", "api", "runtime", "lookup"].join("/") + "?term=hello");
`;

export function mountRuntimeApi(app: Express): void {
  app.get("/assets/boot.js", (_req, res) => { res.type("application/javascript").send(BOOT_JS); });
  app.get("/api/runtime/lookup", (req, res) => {
    const term = String(req.query.term ?? "");
    if (term.includes("'")) {
      res.status(500).type("text/plain").send(`SQLITE_ERROR: near "'": syntax error while compiling: SELECT * FROM notes WHERE title = '${term}'`);
      return;
    }
    res.json({ results: [] });
  });
}
