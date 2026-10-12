/**
 * Dependency vulnerabilities from the repository's own lockfile or manifest.
 *
 * The live scan can only guess versions from a banner or a script URL. A lockfile is the real list, with exact versions,
 * so a match against OSV here is evidence, not inference, and says which file named the package. It reuses the same
 * OSV lookup and finding builder as the exposed-manifest check (manifestSca.ts).
 *
 * Direct dependencies from package.json come first (those are the ones the owner chose and can update); the
 * lockfile's transitive packages fill what is left of a fixed budget, so a big lockfile costs a bounded number of lookups.
 */
import { scaFromManifest, exactVersion, type ManifestPackage } from "./manifestSca";
import type { RepoFile } from "./repoFinding";
import type { ScanVulnerability } from "./scanner";

/** Lookups per repository. OSV answers one package at a time here. */
export const MAX_PACKAGES = 150;

export const isManifestPath = (p: string) => /(?:^|\/)package\.json$/i.test(p) && !/(?:^|\/)node_modules\//.test(p);
export const isLockfilePath = (p: string) => /(?:^|\/)package-lock\.json$/i.test(p) && !/(?:^|\/)node_modules\//.test(p);

/** package.json: the dependency names the owner chose (exact versions only; a range is not a version). */
export function directDependencies(body: string): ManifestPackage[] {
  try {
    const j = JSON.parse(body) as Record<string, Record<string, unknown> | undefined>;
    const out: ManifestPackage[] = [];
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
      for (const [name, range] of Object.entries(j[field] ?? {})) {
        const version = exactVersion(range);
        if (version) out.push({ name, version });
      }
    }
    return out;
  } catch { return []; }
}

/** package-lock.json (lockfileVersion 2 or 3): every installed package and its resolved version. */
export function lockedPackages(body: string): ManifestPackage[] {
  try {
    const j = JSON.parse(body) as { packages?: Record<string, { version?: string; dev?: boolean; link?: boolean }> };
    const out: ManifestPackage[] = [];
    for (const [key, p] of Object.entries(j.packages ?? {})) {
      if (!key || p.link || !p.version) continue;
      const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      if (name && /^\d+\.\d+\.\d+/.test(p.version)) out.push({ name, version: p.version });
    }
    return out;
  } catch { return []; }
}

export async function dependencyFindings(files: RepoFile[]): Promise<{ findings: ScanVulnerability[]; considered: number; looked: number; source: string | null }> {
  const lock = files.find((f) => isLockfilePath(f.path));
  const manifests = files.filter((f) => isManifestPath(f.path));
  const direct = manifests.flatMap((m) => directDependencies(m.content));
  const locked = lock ? lockedPackages(lock.content) : [];
  const seen = new Set<string>();
  const ordered: ManifestPackage[] = [];
  // A direct dependency is looked up at the version the lockfile resolved, when there is one (it is the installed one).
  const resolved = new Map(locked.map((p) => [p.name, p.version]));
  for (const p of [...direct.map((d) => ({ name: d.name, version: resolved.get(d.name) ?? d.version })), ...locked]) {
    const key = `${p.name}@${p.version}`;
    if (!seen.has(key)) { seen.add(key); ordered.push(p); }
  }
  if (ordered.length === 0) return { findings: [], considered: 0, looked: 0, source: null };
  const budget = ordered.slice(0, MAX_PACKAGES);
  const source = lock?.path ?? manifests[0]!.path;
  const findings = await scaFromManifest(budget, source);
  return { findings, considered: ordered.length, looked: budget.length, source };
}
