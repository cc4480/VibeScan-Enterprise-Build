/**
 * Readers for the dependency files of a repository: which package, at which exact version, in which ecosystem.
 *
 * Only an exact version is used. A range ("^4.17.0", ">=2") says what is allowed, not what is installed, and asking
 * OSV about it would attribute advisories the project may not have. Lockfiles state the installed version, which is
 * why they are preferred; a manifest contributes only what it pins (package.json with exact versions, requirements.txt
 * with ==, go.mod). Each reader is a pure function over the file's text and never throws: a file it cannot read gives [].
 *
 * Ecosystem names are OSV's: npm, PyPI, Go, crates.io, RubyGems, Packagist.
 */
import type { ManifestPackage } from "./manifestSca";

/** Files that state installed versions. Never scanned for secrets (their hashes are not secrets) and allowed to be large. */
export const LOCKFILE_PATH = /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|poetry\.lock|uv\.lock|Pipfile\.lock|Cargo\.lock|Gemfile\.lock|composer\.lock)$/i;
/** Files that pin versions by hand. */
export const MANIFEST_PATH = /(?:^|\/)(?:package\.json|requirements(?:[-_.][\w.-]*)?\.txt|go\.mod)$/i;
const VENDORED = /(?:^|\/)(?:node_modules|vendor|third_party)\//i;

export const isLockfile = (p: string): boolean => LOCKFILE_PATH.test(p) && !VENDORED.test(p);
export const isManifest = (p: string): boolean => MANIFEST_PATH.test(p) && !VENDORED.test(p);

const baseName = (p: string) => p.slice(p.lastIndexOf("/") + 1);
const pkg = (ecosystem: string, name: string, version: string, dev?: boolean): ManifestPackage => ({ name, version, ecosystem, ...(dev ? { dev: true } : {}) });

// ── npm ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

/** package-lock.json: lockfileVersion 2/3 ("packages") and 1 (nested "dependencies"). */
export function parsePackageLock(body: string): ManifestPackage[] {
  let doc: { packages?: Record<string, { version?: string; dev?: boolean; link?: boolean }>; dependencies?: Record<string, unknown> };
  try { doc = JSON.parse(body); } catch { return []; }
  const out: ManifestPackage[] = [];
  const exact = /^\d+\.\d+\.\d+/;
  if (doc.packages && typeof doc.packages === "object") {
    for (const [key, p] of Object.entries(doc.packages)) {
      if (!key || p.link || !p.version || !exact.test(p.version)) continue;
      const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      if (name) out.push(pkg("npm", name, p.version, p.dev));
    }
    return out;
  }
  const walk = (deps: Record<string, unknown> | undefined) => {
    for (const [name, raw] of Object.entries(deps ?? {})) {
      const d = raw as { version?: string; dev?: boolean; dependencies?: Record<string, unknown> };
      if (d?.version && exact.test(d.version)) out.push(pkg("npm", name, d.version, d.dev));
      if (d?.dependencies) walk(d.dependencies);
    }
  };
  walk(doc.dependencies);
  return out;
}

const NOT_A_REGISTRY_PACKAGE = /@(?:workspace|patch|file|link|portal|git|github|http|https|exec):/i;

/** yarn.lock, classic ("version \"1.2.3\"") and berry ("version: 1.2.3"). */
export function parseYarnLock(body: string): ManifestPackage[] {
  const out: ManifestPackage[] = [];
  let name: string | null = null;
  for (const line of body.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      name = null;
      const spec = line.replace(/:\s*$/, "").split(/,\s*/)[0]!.trim().replace(/^["']|["']$/g, "");
      if (!spec || spec.startsWith("__metadata") || NOT_A_REGISTRY_PACKAGE.test(spec)) continue;
      const at = spec.indexOf("@", 1);
      // "foo@npm:bar@^1" is an alias for another package: what it resolves to is not "foo".
      if (at <= 0 || /@npm:.*@/.test(spec)) continue;
      name = spec.slice(0, at);
      continue;
    }
    const m = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (m && name) { out.push(pkg("npm", name, m[1]!)); name = null; }
  }
  return out;
}

/** pnpm-lock.yaml: v5 ("/name/1.2.3"), v6 ("/name@1.2.3") and v9 ("name@1.2.3"), from the packages section. */
export function parsePnpmLock(body: string): ManifestPackage[] {
  const out: ManifestPackage[] = [];
  let inPackages = false;
  for (const line of body.split(/\r?\n/)) {
    if (/^packages:\s*$/.test(line)) { inPackages = true; continue; }
    if (/^\S/.test(line)) { inPackages = false; continue; }
    if (!inPackages) continue;
    const m = /^ {2}['"]?\/?((?:@[^/@\s'"]+\/)?[^/@\s'"]+)[@/](\d[^(:'"\s]*)/.exec(line);
    if (m) { out.push(pkg("npm", m[1]!, m[2]!)); continue; }
    if (/^ {4}dev:\s*true\s*$/.test(line) && out.length > 0) out[out.length - 1]!.dev = true;
  }
  return out;
}

/** bun.lock (text): each package is an array whose first entry is "name@version". */
export function parseBunLock(body: string): ManifestPackage[] {
  const out: ManifestPackage[] = [];
  for (const m of body.matchAll(/\[\s*"((?:@[^/"@]+\/)?[^@"/]+)@(\d[^"]*)"/g)) out.push(pkg("npm", m[1]!, m[2]!));
  return out;
}

// ── Python ──────────────────────────────────────────────────────────────────────────────────────────────────────────

/** requirements*.txt: only lines pinned with == (a range is not an installed version). */
export function parseRequirements(path: string, body: string): ManifestPackage[] {
  const dev = /(?:dev|test|lint|doc)/i.test(baseName(path));
  const out: ManifestPackage[] = [];
  for (const raw of body.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").replace(/\s*\\$/, "").trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*(\d[A-Za-z0-9.!+_-]*)/.exec(line);
    if (m) out.push(pkg("PyPI", m[1]!.toLowerCase(), m[2]!, dev));
  }
  return out;
}

/** poetry.lock and uv.lock: [[package]] blocks with name and version (path and editable sources are the project's own). */
export function parseTomlPackages(ecosystem: string, body: string, skipOwn = true): ManifestPackage[] {
  const out: ManifestPackage[] = [];
  for (const text of body.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(text)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(text)?.[1];
    if (!name || !version) continue;
    // A path, editable, virtual or git dependency is not a registry release OSV can tell the version of.
    if (skipOwn && (/^source\s*=\s*\{[^}]*(?:editable|virtual|directory|path|git)\s*=/m.test(text) || /^\[package\.source\][^[]*^type\s*=\s*"(?:directory|file|git|url)"/m.test(text))) continue;
    // Cargo.lock: a package with no registry source is the workspace's own crate.
    if (ecosystem === "crates.io" && !/^source\s*=\s*"registry\+/m.test(text)) continue;
    out.push(pkg(ecosystem, ecosystem === "PyPI" ? name.toLowerCase() : name, version, /^category\s*=\s*"dev"/m.test(text)));
  }
  return out;
}

/** Pipfile.lock: JSON with "default" and "develop" sections, versions like "==1.2.3". */
export function parsePipfileLock(body: string): ManifestPackage[] {
  let doc: Record<string, Record<string, { version?: string }>>;
  try { doc = JSON.parse(body); } catch { return []; }
  const out: ManifestPackage[] = [];
  for (const [section, dev] of [["default", false], ["develop", true]] as const) {
    for (const [name, p] of Object.entries(doc[section] ?? {})) {
      const v = /^===?(\d[^\s]*)$/.exec(p?.version ?? "")?.[1];
      if (v) out.push(pkg("PyPI", name.toLowerCase(), v, dev));
    }
  }
  return out;
}

// ── Go, Ruby, PHP ───────────────────────────────────────────────────────────────────────────────────────────────────

/** go.mod: require lines (single or block). OSV wants the version without the leading "v". */
export function parseGoMod(body: string): ManifestPackage[] {
  const out: ManifestPackage[] = [];
  let inBlock = false;
  for (const raw of body.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\(\s*$/.test(line)) { inBlock = true; continue; }
    if (inBlock && line === ")") { inBlock = false; continue; }
    const m = (inBlock ? /^(\S+)\s+v(\d\S*)$/ : /^require\s+(\S+)\s+v(\d\S*)$/).exec(line);
    // A pseudo-version (v0.0.0-2020...-abcdef) names a commit, not a release OSV tracks by version.
    if (m && !/^0\.0\.0-\d{14}-/.test(m[2]!)) out.push(pkg("Go", m[1]!, m[2]!));
  }
  return out;
}

/** Gemfile.lock: "    name (1.2.3)" under a GEM section's specs. */
export function parseGemfileLock(body: string): ManifestPackage[] {
  const out: ManifestPackage[] = [];
  let inGem = false;
  for (const line of body.split(/\r?\n/)) {
    if (/^[A-Z]+\s*$/.test(line)) { inGem = line.trim() === "GEM"; continue; }
    if (!inGem) continue;
    const m = /^ {4}([A-Za-z0-9_.-]+) \((\d[^)\s-]*)(?:-[^)]*)?\)\s*$/.exec(line);
    if (m) out.push(pkg("RubyGems", m[1]!, m[2]!));
  }
  return out;
}

/** composer.lock: "packages" and "packages-dev" with name and version (a leading v is dropped). */
export function parseComposerLock(body: string): ManifestPackage[] {
  let doc: { packages?: Array<{ name?: string; version?: string }>; "packages-dev"?: Array<{ name?: string; version?: string }> };
  try { doc = JSON.parse(body); } catch { return []; }
  const out: ManifestPackage[] = [];
  for (const [list, dev] of [[doc.packages, false], [doc["packages-dev"], true]] as const) {
    for (const p of list ?? []) {
      const v = (p.version ?? "").replace(/^v/, "");
      if (p.name && /^\d/.test(v) && !/^dev-/.test(p.version ?? "")) out.push(pkg("Packagist", p.name, v, dev));
    }
  }
  return out;
}

/** The packages a lockfile states, by what the file is. */
export function parseLockfile(path: string, body: string): ManifestPackage[] {
  const name = baseName(path).toLowerCase();
  if (name === "package-lock.json") return parsePackageLock(body);
  if (name === "yarn.lock") return parseYarnLock(body);
  if (name === "pnpm-lock.yaml") return parsePnpmLock(body);
  if (name === "bun.lock") return parseBunLock(body);
  if (name === "poetry.lock" || name === "uv.lock") return parseTomlPackages("PyPI", body);
  if (name === "pipfile.lock") return parsePipfileLock(body);
  if (name === "cargo.lock") return parseTomlPackages("crates.io", body);
  if (name === "gemfile.lock") return parseGemfileLock(body);
  if (name === "composer.lock") return parseComposerLock(body);
  return [];
}
