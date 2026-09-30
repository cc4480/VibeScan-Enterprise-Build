import type { Express } from "express";

/** The catch-all 404 (must be registered last). */


export function mountTail(app: Express): void {
  // ─────────────────────────────────────────────────────────────────────────────
  // 404 for everything else — real, not a catch-all shell, EXCEPT for the
  // error-disclosure probe: a random nonexistent path must leak the Werkzeug
  // fingerprint (probes.ts checkErrorDisclosure), while the homepage baseline
  // must not carry it, which it doesn't (this only runs when nothing else
  // matched, so "/" never reaches here).
  // ─────────────────────────────────────────────────────────────────────────────
  app.use((req, res) => {
    res.status(500).type("text/html").send(
      `<html><body><h1>Internal Server Error</h1><pre>Traceback (most recent call last):\n  File "/app/main.py", line 42, in handle\n    raise Exception("unhandled")\nwerkzeug.debug: Debugger caught an exception in handle (${req.path})</pre></body></html>`,
    );
  });
}
