/**
 * Dependency vulnerabilities from the repository's own lockfiles and manifests.
 *
 * The live scan can only guess versions from a banner or a script URL. A lockfile is the real list, with exact versions,
 * so a match against OSV here is evidence, not inference, and says which file named the package. It reuses the same
 * OSV lookup and finding builder as the exposed-manifest check (manifestSca.ts).
 *
 * Read: npm (package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock, package.json), Python (poetry.lock, uv.lock,
 * Pipfile.lock, pinned requirements*.txt), Go (go.mod), Rust (Cargo.lock), Ruby (Gemfile.lock) and PHP (composer.lock).
 * Direct dependencies come first (those are the ones the owner chose and can update); transitive packages follow, from
 * every lockfile in the repository (a monorepo has several). OSV's malicious-package records are reported as critical.
 */
import { scaFromManifest, exactVersion, type ManifestPackage } from "./manifestSca";
import { isTestOrExamplePath, type RepoFile, type RepoRef } from "./repoFinding";
import type { ScanVulnerability } from "./scanner";
import { isLockfile, isManifest, parseLockfile, parsePackageLock, parseRequirements, parseGoMod } from "./repoDepParsers";
import { markDevOnly } from "./repoDepGraph";

/** A safety ceiling on lookups per repository, far above any real project (a large monorepo has a few thousand packages). */
export const MAX_PACKAGES = 5000;

export const isManifestPath = isManifest;
export const isLockfilePath = isLockfile;

/** package.json: the dependency names the owner chose (exact versions only; a range is not a version). */
export function directDependencies(body: string): ManifestPackage[] {
  try {
    const j = JSON.parse(body) as Record<string, Record<string, unknown> | undefined>;
    const out: ManifestPackage[] = [];
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
      for (const [name, range] of Object.entries(j[field] ?? {})) {
        const version = exactVersion(range);
        if (version) out.push({ name, version, ecosystem: "npm", ...(field === "devDependencies" ? { dev: true } : {}) });
      }
    }
    return out;
  } catch { return []; }
}

/** package-lock.json (any lockfileVersion): every installed package and its resolved version. */
export const lockedPackages = parsePackageLock;

const baseName = (p: string) => p.slice(p.lastIndexOf("/") + 1).toLowerCase();

/** What one manifest pins by hand. */
function manifestPackages(file: RepoFile): ManifestPackage[] {
  const name = baseName(file.path);
  const list = name === "package.json" ? directDependencies(file.content) : name === "go.mod" ? parseGoMod(file.content) : parseRequirements(file.path, file.content);
  return list.map((p) => ({ ...p, source: file.path }));
}

export async function dependencyFindings(files: RepoFile[], ref?: Pick<RepoRef, "owner" | "repo">): Promise<{ findings: ScanVulnerability[]; considered: number; looked: number; source: string | null }> {
  const locks = files.filter((f) => isLockfile(f.path));
  const manifests = files.filter((f) => isManifest(f.path));
  // A dependency file in an examples, tests or docs folder describes a sample, not what the project installs in production.
  const sampleOnly = (p: ManifestPackage): ManifestPackage => (p.source && isTestOrExamplePath(p.source) ? { ...p, dev: true } : p);
  // The lockfile's own dev flags where it has them (npm), the dependency graph where it does not (bun, pnpm, yarn, uv, poetry).
  const manifestBeside = (f: RepoFile) => files.find((m) => m.path === f.path.slice(0, f.path.lastIndexOf("/") + 1) + "package.json")?.content;
  const locked = locks.flatMap((f) => markDevOnly(f.path, f.content, parseLockfile(f.path, f.content), manifestBeside(f)).map((p) => sampleOnly({ ...p, source: f.path })));
  const direct = manifests.flatMap(manifestPackages).map(sampleOnly);

  // A direct dependency is looked up at the version a lockfile resolved, when there is one (it is the installed one).
  const resolved = new Map<string, string>();
  for (const p of locked) if (!resolved.has(`${p.ecosystem}|${p.name}`)) resolved.set(`${p.ecosystem}|${p.name}`, p.version);

  // One entry per package and version. It counts as a development dependency only if every place it appears says so.
  const ordered = new Map<string, ManifestPackage>();
  for (const p of [...direct.map((d) => ({ ...d, version: resolved.get(`${d.ecosystem}|${d.name}`) ?? d.version })), ...locked]) {
    const key = `${p.ecosystem}|${p.name}@${p.version}`;
    const seen = ordered.get(key);
    if (!seen) ordered.set(key, p);
    else if (seen.dev && !p.dev) delete seen.dev;
  }
  const all = [...ordered.values()];
  if (all.length === 0) return { findings: [], considered: 0, looked: 0, source: null };
  const budget = all.slice(0, MAX_PACKAGES);
  const source = locks[0]?.path ?? manifests[0]!.path;
  const findings = await scaFromManifest(budget, source, ref ? { repository: `${ref.owner}/${ref.repo}` } : {});
  return { findings, considered: all.length, looked: budget.length, source };
}
