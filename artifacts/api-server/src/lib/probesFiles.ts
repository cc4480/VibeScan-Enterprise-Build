/** Probes that fetch well-known files and paths: sensitive files, robots.txt, security.txt, directory listings. */
import type { ScanVulnerability } from "./scanner";
import { detectCatchAll, matchesCatchAll } from "./spaCatchAll";
import { SENSITIVE_PATHS } from "./probes-data";
import { safeGet, vuln } from "./probesCore";

export async function checkSensitiveFiles(baseUrl: string): Promise<ScanVulnerability[]> {
  let origin: string;
  let expectedHost: string;
  try {
    const parsed = new URL(baseUrl);
    origin = parsed.origin;
    expectedHost = parsed.hostname;
  } catch {
    return [];
  }

  // Fingerprint catch-all routing BEFORE probing real paths. SPAs (client-side
  // routing) and multi-tenant platforms (GitHub/npm/PyPI, where any path
  // segment is treated as a username) return HTTP 200 + the same shell page
  // for virtually any path — without this, every probed path below (admin
  // panels, .env variants, etc.) looks "exposed."
  const catchAll = await detectCatchAll(origin).catch(() => null);

  const results = await Promise.allSettled(
    SENSITIVE_PATHS.map(async (p): Promise<ScanVulnerability | null> => {
      const url = `${origin}${p.path}`;
      const result = await safeGet(url, { redirect: "follow" });
      if (!result || result.status !== 200) return null;

      // Redirected to a different host = catch-all (login page etc.)
      try {
        const finalHost = new URL(result.finalUrl).hostname;
        if (finalHost !== expectedHost) return null;
      } catch {
        return null;
      }

      // Suppress if the response is just the catch-all shell, not real content
      if (matchesCatchAll(result.body, catchAll, url)) return null;

      const ct = result.headers["content-type"] ?? "";

      // A sensitive FILE that comes back as a full HTML document is the SPA /
      // catch-all shell, never the file — a real .env, .properties or
      // .bash_history is not an HTML page. matchesCatchAll above compares body
      // size and <title> against a baseline, but a modern SPA varies both per
      // path (per-route meta, OG tags, titles), so that check misses on the
      // large sites it matters most for. This structural guard does not: it
      // caught vercel.com's 2.5 MB marketing shell being read as an exposed
      // Spring application.properties (its prose contains "security.") and an
      // exposed .bash_history (its prose contains "git"/"npm"/"docker"). Paths
      // whose genuine content IS html — phpinfo, server-status, admin panels —
      // opt out with servesHtml.
      if (!p.servesHtml && /<!doctype\s+html|<html[\s>]/i.test(result.body.slice(0, 4000))) {
        return null;
      }

      if (!p.validate(result.body, ct)) return null;

      const wstgId = /phpmyadmin|adminer|admin\s+panel|admin\s+interface|management\s+interface/i.test(p.name)
        ? "WSTG-CONF-05"
        : "WSTG-CONF-04";
      return vuln({
        name: p.name,
        severity: p.severity,
        category: p.category,
        description: p.description,
        evidence: `GET ${origin}${p.path} → HTTP 200 (${result.body.length.toLocaleString()} bytes)\nContent-Type: ${ct || "not set"}`,
        solution: p.solution,
        cweId: p.cweId,
        cvssScore: p.cvssScore,
        wstgId,
      });
    }),
  );

  return results
    .filter((r): r is PromiseFulfilledResult<ScanVulnerability | null> => r.status === "fulfilled")
    .map((r) => r.value)
    .filter((v): v is ScanVulnerability => v !== null);
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. ROBOTS.TXT ANALYSIS
// ─────────────────────────────────────────────────────────────────────────────

export async function checkRobotsTxt(baseUrl: string): Promise<ScanVulnerability[]> {
  let origin: string;
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return [];
  }

  const result = await safeGet(`${origin}/robots.txt`);
  if (!result || result.status !== 200 || result.body.length < 10) return [];

  const lines = result.body.split("\n");
  const disallowedPaths = lines
    .filter((l) => /^Disallow:\s*/i.test(l))
    .map((l) => l.replace(/^Disallow:\s*/i, "").trim())
    .filter((p) => p && p !== "/" && p.length > 1);

  // Deliberately excludes /api/ and "dashboard". Both are ordinary parts of a
  // public site — google.com's robots.txt disallows /maps/api/js/ and
  // /maps/reserve/partner-dashboard, which are documented public endpoints, and
  // matching them produced a "discloses sensitive paths" finding on the most
  // scrutinised site on the internet. A path being under /api/ says nothing
  // about whether it is meant to be private; the patterns below name things
  // that are not supposed to face the public at all.
  //
  // The words match as whole path tokens, not as substrings. wikipedia.org disallows
  // /wiki/Wikipedia:Administratoren/Probleme/ and /wiki/Wikipedia:Requests_for_adminship/, which are
  // discussion pages about the role, and a bare /admin/ matched them. A real admin path still matches:
  // /admin/, /wp-admin/, /index.php/admin/, */store/admin, /administrator/.
  const word = (w: string) => new RegExp(`(?:^|[/\\-_.*:?=&])${w}(?:$|[/\\-_.*:?=&])`, "i");
  const sensitivePatterns = [
    word("admin(?:istrator)?"), word("backups?"), word("configs?"), word("private"), word("secrets?"),
    word("internal"), word("database"), /\/db\//i, /\.sql/i,
    word("staging"), /\/dev\//i, /\/logs?\//i, word("debug"),
    /\/tmp\//i, /\/test\//i, /\.env/i, word("credentials"),
  ];

  const sensitivePaths = disallowedPaths.filter((p) =>
    sensitivePatterns.some((rx) => rx.test(p)),
  );

  if (sensitivePaths.length === 0) return [];

  return [vuln({
    name: "robots.txt Discloses Sensitive Application Paths",
    severity: "info",
    category: "Information Disclosure",
    description: `The robots.txt file contains ${sensitivePaths.length} path(s) that reveal sensitive areas of the application: ${sensitivePaths.slice(0, 5).join(", ")}${sensitivePaths.length > 5 ? "…" : ""}. Ironically, listing paths in robots.txt to hide them from search engines makes them more discoverable to attackers who always check this file first.`,
    evidence: `GET ${origin}/robots.txt → HTTP 200\n${sensitivePaths.slice(0, 8).map((p) => `Disallow: ${p}`).join("\n")}`,
    solution: "Do not use robots.txt to obscure sensitive paths — it achieves the opposite. Properly secure those endpoints with authentication. Consider using `Disallow: /` globally if you don't want any indexing, rather than listing individual sensitive paths.",
    cweId: "CWE-200",
    wstgId: "WSTG-INFO-01",
  })];
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

export const DIRECTORY_LISTING_DIRS = [
  "/uploads/", "/images/", "/files/", "/backup/", "/backups/",
  "/logs/", "/static/", "/assets/", "/media/", "/data/",
  "/tmp/", "/cache/", "/downloads/", "/export/", "/exports/",
];

export const DIRECTORY_LISTING_PATTERNS = [
  /Index of \//i,
  /<title>Directory listing/i,
  /\[To Parent Directory\]/i,
  /httpd\s+Directory\s+Listing/i,
  /\?C=N&amp;O=D/,
  // "<hr><pre>" deliberately removed: it is Apache/nginx autoindex's actual
  // layout, but it is also what a markdown renderer produces for "---"
  // followed by a code block — extremely common on documentation pages,
  // changelogs and blog posts. The remaining five patterns are all specific
  // to a real autoindex page (the sort-link query string, the exact
  // "[To Parent Directory]" text, the httpd-specific title) and stay
  // sufficient on their own.
];

export async function checkDirectoryListing(
  targetUrl: string,
): Promise<ScanVulnerability[]> {
  let origin: string;
  try {
    origin = new URL(targetUrl).origin;
  } catch {
    return [];
  }

  const results = await Promise.allSettled(
    DIRECTORY_LISTING_DIRS.map(async (dir) => {
      const url = origin + dir;
      const res = await safeGet(url, { redirect: "follow" }, 6_000);
      if (!res || res.status < 200 || res.status >= 300) return null;
      const matched = DIRECTORY_LISTING_PATTERNS.some((rx) => rx.test(res.body));
      if (!matched) return null;
      return vuln({
        name: "Directory Listing Enabled",
        severity: "medium",
        category: "Information Disclosure",
        description: `Directory listing is enabled at ${dir}. This exposes the complete file structure of that directory, allowing attackers to enumerate all files — including backup archives, configuration files, log files, and uploaded content that should not be public.`,
        evidence: `GET ${url} → HTTP 200\nDirectory index page returned (autoindex enabled)`,
        solution: "Disable directory listing at the web server. Nginx: remove the 'autoindex on' directive. Apache: add 'Options -Indexes' to the relevant directory block or .htaccess.",
        cweId: "CWE-548",
        cvssScore: 5.3,
        wstgId: "WSTG-CONF-04",
      });
    }),
  );

  return results
    .filter((r): r is PromiseFulfilledResult<ScanVulnerability | null> => r.status === "fulfilled")
    .map((r) => r.value)
    .filter((v): v is ScanVulnerability => v !== null)
    .slice(0, 3);
}

export async function checkSecurityTxt(
  targetUrl: string,
): Promise<ScanVulnerability[]> {
  let origin: string;
  try {
    origin = new URL(targetUrl).origin;
  } catch {
    return [];
  }

  const paths = ["/.well-known/security.txt", "/security.txt"];
  // What each path actually returned, so the evidence can say so.
  //
  // This used to report "not found" for both paths regardless of what happened.
  // mozilla.org serves /.well-known/security.txt with HTTP 200 — it simply is not
  // RFC 9116 (it uses Email:/Main info: rather than Contact:/Expires:). The
  // finding is right; claiming the file is absent is not, and anyone who checks
  // sees a file sitting there and reports the scanner as broken.
  const observed: string[] = [];
  // A path we were refused or could not reach says nothing about whether the file exists. npmjs.com
  // answers a scanner 403 (a Cloudflare challenge) on both paths while /.well-known/security.txt is a
  // valid file; reporting it "missing" on that was wrong. Only a definitive answer (404, 410, a page
  // with no RFC 9116 fields) supports "missing", so any refusal or failure makes the result unknown.
  let couldNotTell = false;
  for (const p of paths) {
    const res = await safeGet(origin + p, { redirect: "follow" }, 6_000);
    if (!res) {
      observed.push(`GET ${origin}${p} → no response`);
      couldNotTell = true;
      continue;
    }
    if (res.status === 401 || res.status === 403 || res.status === 429 || res.status >= 500) couldNotTell = true;
    if (res.status >= 200 && res.status < 300) {
      if (/Contact:|Expires:|Policy:/i.test(res.body)) return [];
      // A catch-all host answers 200 with its app shell for any path; say so, or the reader goes
      // looking for a security.txt file that was never there.
      const isPage = /^\s*<(!doctype\s+html|html[\s>])/i.test(res.body.slice(0, 1_000));
      observed.push(
        isPage
          ? `GET ${origin}${p} → HTTP ${res.status} with an HTML page (the site's catch-all answer for unknown paths), not a security.txt file`
          : `GET ${origin}${p} → HTTP ${res.status}, but no RFC 9116 fields (Contact:/Expires:/Policy:) in the body`,
      );
      continue;
    }
    observed.push(`GET ${origin}${p} → HTTP ${res.status}`);
  }

  if (couldNotTell) return [];

  return [vuln({
    name: "Missing security.txt (RFC 9116)",
    severity: "info",
    category: "Information Disclosure",
    description: "No security.txt file was found at /.well-known/security.txt or /security.txt. RFC 9116 defines this as the standard way for security researchers to report vulnerabilities to your organisation. Without it, researchers may not know how to contact you responsibly, leading to public disclosure before you can patch.",
    evidence: observed.join("\n"),
    solution: "Create /.well-known/security.txt with at minimum: Contact (email or form URL), Expires (date after which the file is stale), and optionally Policy (URL of your vulnerability disclosure policy). Generator: https://securitytxt.org/",
    cweId: "CWE-205",
    cvssScore: 0,
  })];
}
