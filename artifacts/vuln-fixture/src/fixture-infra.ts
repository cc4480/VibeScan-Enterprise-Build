import type { Express } from "express";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

/** Benchmark infrastructure: /manifest.json and /about. */


export function mountInfra(app: Express): void {
   // Express's own default; we set our own EOL banner below.

  // ─────────────────────────────────────────────────────────────────────────────
  // Public benchmark infrastructure — /manifest.json and /about.
  //
  // Not a planted finding. This is the actual point of the secscan-me
  // deployment: a stranger fetches the fault list here, scans the app with
  // whatever tool they like, and checks the result themselves — the entire
  // argument for a public target instead of a vendor-published number is that
  // nobody has to trust this file's PROVENANCE, only read it.
  //
  // /about doubles as the authorisation notice (see deploy/secscan-me/README.md
  // — the conventional places for that, /security.txt and /robots.txt, are each
  // a planted finding here, so putting it there would break the fault it is
  // supposed to coexist with).
  // ─────────────────────────────────────────────────────────────────────────────
  const HERE = dirname(fileURLToPath(import.meta.url));
  // dist/server.js in the built image, src/server.ts under tsx — either way the
  // generated manifest sits one level up, at the package root.
  const MANIFEST_PATH = join(HERE, "..", "manifest.json");

  app.get("/manifest.json", (_req, res) => {
    if (!existsSync(MANIFEST_PATH)) {
      res.status(503).json({
        error: "manifest not generated for this instance",
        hint: "npx tsx artifacts/api-server/scripts/benchmark/generate-manifest.ts",
      });
      return;
    }
    res.type("application/json").send(readFileSync(MANIFEST_PATH, "utf8"));
  });

  app.get("/about", (_req, res) => {
    res.type("text/html").send(`<!doctype html>
  <html><head><title>About this host</title></head><body>
  <h1>This host is a public security-scanner benchmark target</h1>
  <p>Scanning it is authorised — that is the whole point of it existing. Every
  planted fault is listed, with no exploit details withheld, at
  <a href="/manifest.json">/manifest.json</a>.</p>
  <p>None of the planted vulnerabilities are real in the sense of granting an
  attacker anything beyond this container: there is no real database behind the
  SQL injection, no real file read behind the path traversal, and every "leaked"
  secret is a fake literal. See the project this target belongs to for the full
  methodology and the benchmark results it produced.</p>
  </body></html>`);
  });
}
