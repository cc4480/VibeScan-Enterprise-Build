import type { Express } from "express";
import { SENSITIVE_PATHS } from "./sensitive-paths.js";
import { INJECTION_EXTRA_LINKS } from "./injection-extra-routes.js";
import { NEXT_DATA_PROPS, JWT_ALG_NONE, JWT_NO_EXPIRY, JWT_EXCESSIVE_LIFETIME, JWT_SENSITIVE_PAYLOAD } from "./secrets.js";

/** The home page and the pages the crawler reaches from it: files, uploads, errors, downloads. */


export function mountPages(app: Express): void {
  // ─────────────────────────────────────────────────────────────────────────────
  // Home page: __NEXT_DATA__ (nextjsProbe.ts), JWTs (jwtAnalysis.ts), links for
  // the crawler to find (/app/dashboard for crawler-data.ts's inner-route
  // probes, /account/1001 for accessControlProbe.ts, /uploads/ for directory
  // listing), no Open Graph / Twitter Card / JSON-LD (structuredData.ts INFO
  // findings, earned by omission).
  // ─────────────────────────────────────────────────────────────────────────────
  // checkOpenRedirect tests the SCAN TARGET URL itself with each known redirect
  // parameter appended — not a separate path — so this has to live on "/".
  const OPEN_REDIRECT_PARAM_NAMES = [
    "redirect", "url", "next", "goto", "return", "returnUrl", "returnTo",
    "r", "redirect_uri", "callback", "continue", "dest", "destination", "forward",
  ];

  // ─────────────────────────────────────────────────────────────────────────────
  // Discoverability policy — read this before adding or unlinking a route.
  //
  // Found the hard way: a cross-scanner benchmark run against this fixture
  // scored ZAP at 18/74 and Nuclei at 9/74 against SecScan's 68/74, and the gap
  // looked like a detection story until the raw ZAP crawl log was checked. ZAP
  // never requested /download, /login or /app/graphql at all — not "found and
  // missed", never asked for the URL — because nothing on the page linked to
  // them. SecScan "found" them from a hardcoded wordlist in pathTraversal.ts.
  // That is not a detection win; it is SecScan knowing its own fixture's paths.
  //
  // So every route here is EITHER:
  //   - a real app feature, linked from <nav> below so any ordinary crawler
  //     (ZAP's spider, Nuclei's crawl mode, a stranger scoring this target)
  //     finds it the same way SecScan does; OR
  //   - a deliberately unlinked "hidden" path — admin/backup/staging/internal-*
  //     and the SENSITIVE_PATHS block — findable only by forced-browsing a
  //     wordlist, which is exactly how a real attacker finds a real backup
  //     directory nobody meant to expose. ZAP and Nuclei can both do this (ZAP
  //     via its Forced Browse add-on, not enabled in our default scan config;
  //     Nuclei via its own path-fuzzing templates) — the three tools' differing
  //     wordlists there are a genuine, fair, publishable capability difference.
  //     Linking these from the nav would misrepresent what they are.
  //
  // A route that is a real feature and gets left unlinked "for now" silently
  // turns back into the ZAP/Nuclei-crawl-never-visits-it bug this comment
  // exists to prevent. If in doubt, link it.
  // ─────────────────────────────────────────────────────────────────────────────
  app.get("/", (req, res) => {
    const target = (Object.entries(req.query).find(([k]) => OPEN_REDIRECT_PARAM_NAMES.includes(k)) ?? [])[1];
    if (typeof target === "string") {
      res.redirect(302, target);
      return;
    }
    res.send(`<!doctype html>
  <html><head><title>Fixture</title>
  <script id="__NEXT_DATA__" type="application/json">${JSON.stringify(NEXT_DATA_PROPS)}</script>
  </head><body>
  <div id="__next"></div>
  <h1>vuln-fixture</h1>
  <nav>
    <a href="/app/dashboard">Dashboard</a>
    <a href="/account/1001">My account</a>
    <a href="/uploads/">Uploads</a>
    <a href="/search?q=test">Search</a>${INJECTION_EXTRA_LINKS}
    <a href="/download?file=invoice-2026-01.pdf">Download invoice</a>
    <a href="/login">Sign in</a>
    <a href="/app/graphql">API explorer</a>
  </nav>
  <footer><a href="/about">About this host</a> &middot; <a href="/manifest.json">Fault manifest</a></footer>
  <!-- Session tokens, visible in page HTML: jwtAnalysis.ts reads headers + html -->
  <span data-token="${JWT_ALG_NONE}"></span>
  <span data-token="${JWT_NO_EXPIRY}"></span>
  <span data-token="${JWT_EXCESSIVE_LIFETIME}"></span>
  <span data-token="${JWT_SENSITIVE_PAYLOAD}"></span>
  <script src="/assets/app.js"></script>
  <script src="/assets/boot.js"></script>
  <script src="/assets/support.js"></script>
  <script src="/assets/ai-widget.js"></script>
  <script src="/assets/ai-chat.js"></script>
  <script src="https://cdn.example.net/analytics.js"></script>
  </body></html>`);
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // Sensitive file exposure — every path in probes-data.ts, matched exactly.
  // Anything not in the map below falls through to the catch-all 404 at the
  // bottom, deliberately: a real 404 for everything else is what keeps
  // detectCatchAll from seeing a catch-all shape here at all, so none of these
  // get suppressed as "just the SPA shell".
  // ─────────────────────────────────────────────────────────────────────────────
  for (const [path, file] of Object.entries(SENSITIVE_PATHS)) {
    app.get(path, (_req, res) => {
      res.type(file.contentType ?? "text/plain").send(file.body);
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // crossdomain.xml also needs the wildcard-DELETE... no: served above via the
  // sensitive-paths loop. Directory listing (probes.ts checkDirectoryListing) —
  // one of DIRECTORY_LISTING_DIRS with an autoindex-shaped body.
  // ─────────────────────────────────────────────────────────────────────────────
  app.get("/uploads/", (_req, res) => {
    res.type("text/html").send(
      `<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1>` +
        `<a href="?C=N;O=D">Name</a>\n<a href="../">[To Parent Directory]</a>\n` +
        `<a href="invoice-2026-01.pdf">invoice-2026-01.pdf</a> 14-Jan-2026 03:11 84K\n</body></html>`,
    );
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // Error disclosure (probes.ts checkErrorDisclosure) — the Flask/Werkzeug
  // debugger fingerprint, on every otherwise-unmatched path. This is what makes
  // the catch-all check itself safe: it fires only when a RANDOM nonexistent
  // path returns the leak and the real homepage does not, so it has to live in
  // the 404 handler at the bottom, not on a named route. See the end of this
  // file.
  // ─────────────────────────────────────────────────────────────────────────────

  // ─────────────────────────────────────────────────────────────────────────────
  // Path traversal (pathTraversal.ts) — one of PROBE_ENDPOINTS + PROBE_PARAMS,
  // unsanitised. classifyTraversalBody looks for `root:x:0:0:` — any ".." in the
  // param serves it; a benign value serves an ordinary "not found".
  // ─────────────────────────────────────────────────────────────────────────────
  app.get("/download", (req, res) => {
    const file = String(req.query.file ?? "");
    if (file.includes("..")) {
      res.type("text/plain").send(
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
      );
    } else {
      res.status(200).type("text/plain").send(`File not found: ${file}`);
    }
  });
}
