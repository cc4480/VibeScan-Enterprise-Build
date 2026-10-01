/** High-value path probing on inner routes. */
import type { ScanVulnerability } from "./scanner";
import { PATH_PROBES, looksLikeHtmlDocument } from "./crawler-data";
import { detectCatchAll, matchesCatchAll, type CatchAllFingerprint } from "./spaCatchAll";
import { probeUrl, vuln } from "./crawlerFetch";

// Destructive-action filtering moved to lib/destructive.ts, which covers more
// verbs and also inspects the query string. It is shared with the injection and
// traversal probes, which fire payloads at discovered paths and had no such
// guard — a far bigger risk than crawling once a session is attached.

/**
 * Curated high-value paths probed on every deep scan regardless of whether
 * they appear in the site's HTML — many sensitive endpoints are never linked
 * from the homepage but are reachable by direct URL.
 *
 * Exported so tests and the report UI can reference the canonical list.
 */
export const HIGH_VALUE_PROBE_PATHS: string[] = [
  // Admin / management interfaces
  "/admin", "/administrator", "/wp-admin",
  // API roots (versioned and unversioned)
  "/api", "/api/v1", "/api/v2", "/api/v3",
  // GraphQL
  "/graphql", "/gql",
  // Health / liveness / readiness probes (often unprotected)
  "/health", "/healthz", "/status", "/ping", "/ready", "/live",
  // Authentication entry points
  "/login", "/auth", "/signin",
  // Application dashboard
  "/dashboard",
  // Observability endpoints (often leaked in dev)
  "/metrics",
  // Debug surfaces
  "/debug", "/console",
];

/**
 * Run sensitive file probes relative to a discovered path's directory prefix.
 * E.g. for page "/api/v1/users", probes are run under "/api/v1/".
 * timeoutMs caps each individual probe request to respect the overall crawl budget.
 */
export async function probePathSensitiveFiles(
  pageUrl: string,
  origin: string,
  expectedHostname: string,
  timeoutMs: number,
  // Directories already probed this crawl, so sibling pages share one round of probes.
  probedDirs: Set<string> = new Set(),
): Promise<ScanVulnerability[]> {
  let pathname: string;
  try {
    pathname = new URL(pageUrl).pathname;
  } catch {
    return [];
  }

  // Get the directory prefix (everything up to and including the last slash)
  const lastSlash = pathname.lastIndexOf("/");
  const dirPrefix = lastSlash > 0 ? pathname.slice(0, lastSlash + 1) : "/";

  // Skip probing root prefix — root-level probes are already handled by probes.ts
  if (dirPrefix === "/") return [];
  if (probedDirs.has(dirPrefix)) return [];
  probedDirs.add(dirPrefix);

  // Same guard as root probing: a directory whose unknown paths all answer 200
  // with one app shell has no exposed files, however the shell's text reads.
  const catchAll: CatchAllFingerprint | null = await detectCatchAll(
    `${origin}${dirPrefix.replace(/\/$/, "")}`,
  ).catch(() => null);

  const findings: ScanVulnerability[] = [];

  await Promise.allSettled(
    PATH_PROBES.map(async (probe) => {
      const probeUrl = `${origin}${dirPrefix}${probe.suffix.replace(/^\//, "")}`;
      const result = await probeUrlFn(probeUrl, timeoutMs);
      if (!result || result.status !== 200) return;

      // Ensure we didn't get redirected off-domain (catch-all login pages, etc.)
      // Must check result.finalUrl (the URL after redirects), not the original probeUrl
      try {
        const finalHostname = new URL(result.finalUrl).hostname;
        if (finalHostname !== expectedHostname) return;
      } catch {
        return;
      }

      if (matchesCatchAll(result.body, catchAll, probeUrl)) return;
      // A file that comes back as a full HTML document is the app shell, not the file.
      if (!probe.servesHtml && looksLikeHtmlDocument(result.body)) return;

      const ct = result.headers["content-type"] ?? "";
      if (!probe.validate(result.body, ct, result.status)) return;

      findings.push(vuln({
        name: probe.name,
        severity: probe.severity,
        category: probe.category,
        description: probe.description(dirPrefix),
        evidence: `GET ${origin}${dirPrefix}${probe.suffix.replace(/^\//, "")} → HTTP 200 (${result.body.length.toLocaleString()} bytes)\nContent-Type: ${ct || "not set"}`,
        solution: probe.solution,
        cweId: probe.cweId,
        cvssScore: probe.cvssScore,
        wstgId: probe.wstgId,
      }));
    }),
  );

  return findings;
}

// Named alias to avoid shadowing the import at module level
export const probeUrlFn = probeUrl;
