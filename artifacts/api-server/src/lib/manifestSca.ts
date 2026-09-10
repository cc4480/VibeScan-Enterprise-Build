/**
 * Software composition analysis from a manifest the target exposed itself.
 *
 * SecScan is black box, so it normally infers dependencies from fingerprints: a
 * version string in a script URL, a banner, a meta tag. That is a guess, and it
 * is scored as one — `version_heuristic` sits at confidence 48 for exactly that
 * reason.
 *
 * But two of our own findings hand over the real thing, and until now we threw
 * it away:
 *
 *   probes-data.ts  "Package Manifest Exposed (package.json)", whose own
 *                   description says an attacker "can identify dependencies
 *                   with known CVEs and target your specific stack". We told
 *                   the customer that, and then did not do it.
 * (An exposed .map lists node_modules/<pkg>/ paths too, but sourceMaps.ts does
 * not surface the maps it already fetched, and refetching them for this would
 * double the requests. Left for when that module exposes them.)
 *
 * A manifest is not a fingerprint. When package.json says "lodash": "4.17.20"
 * that IS the version, so findings from this path carry a confidence a guess
 * never earns, and they name the file that leaked it.
 *
 * Deliberately narrow: this reads what the target already published. It never
 * fetches a manifest that was not already found exposed, and never guesses a
 * version it did not read.
 */

import { randomUUID } from "node:crypto";
import {
  queryOsv,
  extractCvss,
  cvssToSeverity,
  extractFixedVersion,
  cveIds,
  type OsvVuln,
} from "./cveCheck";
import type { ScanVulnerability } from "./scanner";
import { scanFetch } from "./http";

/** A package and the exact version the target's own file declared. */
export interface ManifestPackage {
  name: string;
  version: string;
}

/** Cap on packages from one manifest, so a huge tree cannot stall a scan. */
const MAX_PACKAGES = 60;

/** Concurrent OSV lookups. OSV is public and free; this stays polite. */
const OSV_CONCURRENCY = 6;

/**
 * A dependency range pinned to a single exact version, or null.
 *
 * Only exact versions are usable. "^4.17.20" means "whatever resolved at
 * install time", which we cannot see, and asking OSV about the floor of the
 * range would attribute vulnerabilities the site may not have. A caret or tilde
 * range is skipped rather than guessed at — this module exists to stop
 * guessing.
 */
export function exactVersion(range: unknown): string | null {
  if (typeof range !== "string") return null;
  const v = range.trim();
  // Rejects ranges, tags, URLs, git specs, and workspace/file protocols.
  if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(v)) return null;
  return v;
}

/**
 * Packages declared in an exposed package.json.
 *
 * devDependencies are included: the file being public means the whole document
 * leaked, and a dev dependency that reached a deployed bundle is exactly the
 * kind of thing worth surfacing. peerDependencies and optionalDependencies are
 * not, since neither states what is actually installed.
 */
export function parsePackageJson(body: string): ManifestPackage[] {
  let doc: unknown;
  try {
    doc = JSON.parse(body);
  } catch {
    return [];
  }
  if (!doc || typeof doc !== "object") return [];

  const out: ManifestPackage[] = [];
  const seen = new Set<string>();
  for (const field of ["dependencies", "devDependencies"] as const) {
    const block = (doc as Record<string, unknown>)[field];
    if (!block || typeof block !== "object") continue;
    for (const [name, range] of Object.entries(block as Record<string, unknown>)) {
      const version = exactVersion(range);
      if (!version) continue;
      const key = name + "@" + version;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name, version });
    }
  }
  return out.slice(0, MAX_PACKAGES);
}

/** Semver-ish comparison, good enough to pick the highest fixed version. */
function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** Runs `worker` over `items` with a fixed concurrency ceiling. */
async function mapLimit<T, R>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = [];
  let cursor = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const i = cursor++;
      const item = items[i];
      if (item !== undefined) results[i] = await worker(item);
    }
  });
  await Promise.all(runners);
  return results;
}

/**
 * One finding per vulnerable package — never one per advisory.
 *
 * Eleven advisories against one dependency describe one action: upgrade it.
 * Listing them separately makes a report look eleven times worse than the work
 * it actually implies, which is how a scanner trains people to stop reading it.
 */
function findingFor(
  pkg: ManifestPackage,
  vulns: OsvVuln[],
  source: string,
): ScanVulnerability | null {
  if (vulns.length === 0) return null;

  const scored = vulns
    .map((v) => ({ v, cvss: extractCvss(v) }))
    .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));
  const worst = scored[0];
  if (!worst) return null;
  const severity = cvssToSeverity(worst.cvss);

  // The highest fixed version across all the advisories: upgrading to the fix
  // for the worst one can still leave another unpatched.
  const fixes = vulns.map(extractFixedVersion).filter((f): f is string => !!f);
  const fixed = fixes.sort(compareVersions).pop() ?? null;

  const ids = [...new Set(vulns.flatMap(cveIds))].slice(0, 6);
  const idList = ids.length
    ? ids.join(", ")
    : vulns.map((v) => v.id).slice(0, 6).join(", ");

  const plural = vulns.length === 1 ? "advisory" : "advisories";
  return {
    id: randomUUID(),
    name: `Vulnerable dependency: ${pkg.name} ${pkg.version}`,
    severity,
    category: "Vulnerable Components",
    description:
      `${pkg.name} ${pkg.version} has ${vulns.length} known ${plural} against it (${idList}). ` +
      `This is not inferred from a fingerprint: the version was read from ${source}, ` +
      `which this site publishes, so the same list is available to anyone who looks. ` +
      (worst.v.summary ? `The most severe: ${worst.v.summary}` : ""),
    evidence:
      `${source} declares "${pkg.name}": "${pkg.version}"\n` +
      `OSV advisories: ${idList}` +
      (worst.cvss ? `\nHighest CVSS: ${worst.cvss}` : ""),
    solution: fixed
      ? `Upgrade ${pkg.name} to ${fixed} or later. Also stop serving ${source} publicly — it is what makes this list trivial to compile.`
      : `Update ${pkg.name} to a patched release. Also stop serving ${source} publicly — it is what makes this list trivial to compile.`,
    cweId: "CWE-1395",
    cvssScore: worst.cvss,
    wstgId: "WSTG-CONF-01",
    // A declared exact version is an observation, not a guess — but not 100
    // either: the manifest states what was asked for, and the deployed bundle
    // could differ.
    confidence: 90,
  };
}

/**
 * Match an exposed manifest's packages against OSV.
 *
 * Returns one finding per vulnerable package. Failures are swallowed per
 * package so a single unreachable lookup cannot lose the rest.
 */
export async function scaFromManifest(
  packages: ManifestPackage[],
  source: string,
): Promise<ScanVulnerability[]> {
  if (packages.length === 0) return [];
  const results = await mapLimit(packages, OSV_CONCURRENCY, async (pkg) => {
    try {
      return findingFor(pkg, await queryOsv(pkg.name, pkg.version, "npm"), source);
    } catch {
      return null;
    }
  });
  return results.filter((f): f is ScanVulnerability => f !== null);
}

/**
 * Fetch the target's package.json, if it serves one, and match it against OSV.
 *
 * Runs only when active probing is unlocked, because it is a request the site
 * did not ask for. It is the same path probes-data.ts already tests, so this
 * adds one request to a scan that makes dozens.
 *
 * A site that answers every path with its SPA shell needs no special handling:
 * an HTML document is not JSON, JSON.parse fails, and the result is no
 * packages and no findings.
 */
export async function scaFromExposedManifest(origin: string): Promise<ScanVulnerability[]> {
  const res = await scanFetch(`${origin}/package.json`, { timeoutMs: 8_000 }).catch(() => null);
  if (!res || res.status !== 200 || !res.body) return [];
  const packages = parsePackageJson(res.body);
  if (packages.length === 0) return [];
  return scaFromManifest(packages, "/package.json");
}
