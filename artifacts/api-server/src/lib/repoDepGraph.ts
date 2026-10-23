/**
 * Which locked packages are development-only (build tools, test runners, linters), so a vulnerability in one is not
 * reported as if it shipped.
 *
 * npm's package-lock.json says so itself ("dev": true). The other lockfiles do not, but they record the dependency graph,
 * and the project's own manifest says which of its direct dependencies are development ones. A package is development-only
 * when it is reachable from the development roots and NOT reachable from the production roots.
 *
 * It is built to err toward "production": a package the graph cannot account for (a parse gap, a format variation) is left
 * as it was, never marked development. Marking a runtime package as development would hide a real vulnerability; leaving a
 * build tool as production only costs a louder finding. Names are compared without versions, which can only make a package
 * look production (a name reachable at any version counts as production), never the other way round.
 */
import type { ManifestPackage } from "./manifestSca";

interface Graph { prod: string[]; dev: string[]; edges: Map<string, string[]> }

const addEdge = (edges: Map<string, string[]>, from: string, to: string) => { const l = edges.get(from); if (l) l.push(to); else edges.set(from, [to]); };

function reach(roots: string[], edges: Map<string, string[]>): Set<string> {
  const seen = new Set<string>();
  const stack = [...roots];
  while (stack.length) {
    const n = stack.pop()!;
    if (seen.has(n)) continue;
    seen.add(n);
    for (const next of edges.get(n) ?? []) stack.push(next);
  }
  return seen;
}

/** The names that are development-only in this graph; empty when the graph has no production roots (it was not understood). */
export function devOnlyNames(g: Graph): Set<string> {
  if (g.prod.length === 0 || g.dev.length === 0) return new Set();
  const prod = reach(g.prod, g.edges);
  const dev = reach(g.dev, g.edges);
  return new Set([...dev].filter((n) => !prod.has(n)));
}

const unquote = (s: string) => s.trim().replace(/^["']|["']$/g, "");
const nameOfKey = (key: string): string | null => {
  const k = unquote(key).replace(/^\//, "");
  return /^((?:@[^/@\s]+\/)?[^/@\s]+)[@/]\d/.exec(k)?.[1] ?? null;
};

// ── bun.lock ───────────────────────────────────────────────────────────────────────────────────────────────────────

function bunGraph(body: string): Graph | null {
  let doc: { workspaces?: Record<string, Record<string, Record<string, string>>>; packages?: Record<string, unknown[]> };
  try { doc = JSON.parse(body.replace(/,(\s*[}\]])/g, "$1")); } catch { return null; }
  const prod: string[] = [];
  const dev: string[] = [];
  for (const ws of Object.values(doc.workspaces ?? {})) {
    prod.push(...Object.keys(ws["dependencies"] ?? {}), ...Object.keys(ws["optionalDependencies"] ?? {}));
    dev.push(...Object.keys(ws["devDependencies"] ?? {}));
  }
  const edges = new Map<string, string[]>();
  for (const entry of Object.values(doc.packages ?? {})) {
    const id = typeof entry[0] === "string" ? entry[0] : "";
    const at = id.indexOf("@", 1);
    if (at <= 0) continue;
    const meta = (entry[2] ?? {}) as Record<string, Record<string, string>>;
    for (const to of [...Object.keys(meta["dependencies"] ?? {}), ...Object.keys(meta["optionalDependencies"] ?? {})]) addEdge(edges, id.slice(0, at), to);
  }
  return { prod, dev, edges };
}

// ── pnpm-lock.yaml ─────────────────────────────────────────────────────────────────────────────────────────────────

function pnpmGraph(body: string): Graph | null {
  const lines = body.split(/\r?\n/);
  const prod: string[] = [];
  const dev: string[] = [];
  const edges = new Map<string, string[]>();
  let top = "";
  let section = ""; // within importers: dependencies | devDependencies | optionalDependencies
  let owner: string | null = null; // the package whose dependencies block we are in
  let block = false;
  let lockV5 = false;
  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const indent = line.length - line.trimStart().length;
    const text = line.trim();
    if (indent === 0) { top = text.replace(/:.*$/, ""); section = ""; owner = null; block = false; if (/^dependencies$|^devDependencies$|^optionalDependencies$/.test(top)) lockV5 = true; continue; }
    if (top === "importers" || lockV5 && /^(?:dependencies|devDependencies|optionalDependencies)$/.test(top)) {
      if (top === "importers") {
        if (indent === 4 && /^(?:dependencies|devDependencies|optionalDependencies):/.test(text)) { section = text.replace(/:.*$/, ""); continue; }
        if (indent === 2) { section = ""; continue; }
        if (indent === 6 && section) { const n = unquote(text.replace(/:.*$/, "")); (section === "devDependencies" ? dev : prod).push(n); }
      } else if (indent === 2) {
        // pnpm v5: the root's direct dependencies are top-level maps of name: version
        (top === "devDependencies" ? dev : prod).push(unquote(text.replace(/:.*$/, "")));
      }
      continue;
    }
    if (top === "packages" || top === "snapshots") {
      if (indent === 2) { owner = nameOfKey(text.replace(/:\s*(?:\{\})?$/, "")); block = false; continue; }
      if (indent === 4 && owner) { block = /^(?:dependencies|optionalDependencies):/.test(text); continue; }
      if (indent === 6 && owner && block) addEdge(edges, owner, unquote(text.replace(/:.*$/, "")));
    }
  }
  return { prod, dev, edges };
}

// ── yarn.lock, with the project's package.json for the roots ────────────────────────────────────────────────────────

function yarnGraph(body: string, manifest: string | undefined): Graph | null {
  if (!manifest) return null;
  let pkg: Record<string, Record<string, string> | undefined>;
  try { pkg = JSON.parse(manifest); } catch { return null; }
  const prod = [...Object.keys(pkg["dependencies"] ?? {}), ...Object.keys(pkg["optionalDependencies"] ?? {})];
  const dev = Object.keys(pkg["devDependencies"] ?? {});
  const edges = new Map<string, string[]>();
  let owner: string | null = null;
  let inDeps = false;
  for (const line of body.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      const spec = unquote(line.replace(/:\s*$/, "").split(/,\s*/)[0]!);
      const at = spec.indexOf("@", 1);
      owner = at > 0 ? spec.slice(0, at) : null;
      inDeps = false;
      continue;
    }
    const indent = line.length - line.trimStart().length;
    if (indent === 2) { inDeps = /^(?:dependencies|optionalDependencies):?\s*$/.test(line.trim()); continue; }
    if (indent === 4 && owner && inDeps) addEdge(edges, owner, unquote(line.trim().split(/[\s:]/)[0]!));
  }
  return { prod, dev, edges };
}

// ── TOML lockfiles: poetry.lock and uv.lock ─────────────────────────────────────────────────────────────────────────

function poetryDevNames(body: string): Set<string> {
  const out = new Set<string>();
  for (const text of body.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(text)?.[1];
    const groups = /^groups\s*=\s*\[([^\]]*)\]/m.exec(text)?.[1];
    // Poetry 2 lists the groups a package belongs to; one without "main" is not a runtime dependency.
    if (name && groups !== undefined && !/"main"/.test(groups)) out.add(name.toLowerCase());
  }
  return out;
}

function uvGraph(body: string): Graph | null {
  const edges = new Map<string, string[]>();
  const prod: string[] = [];
  const dev: string[] = [];
  for (const text of body.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(text)?.[1]?.toLowerCase();
    if (!name) continue;
    const own = /^source\s*=\s*\{[^}]*(?:virtual|editable)\s*=/m.test(text);
    const depsOf = (blockStart: RegExp): string[] => {
      const m = blockStart.exec(text);
      if (!m) return [];
      const rest = text.slice(m.index + m[0].length);
      const firstLine = rest.split("\n")[0]!;
      // A one-line list closes on its own line; a multi-line one closes on a line that starts with the bracket.
      const end = firstLine.includes("]") ? firstLine.indexOf("]") : rest.search(/^\]/m);
      return [...(end >= 0 ? rest.slice(0, end) : rest).matchAll(/name\s*=\s*"([^"]+)"/g)].map((x) => x[1]!.toLowerCase());
    };
    const direct = depsOf(/^dependencies\s*=\s*\[/m);
    if (own) {
      prod.push(...direct);
      // [package.dev-dependencies] has one list per group; every name in it is a development root.
      const devSection = /^\[package\.dev-dependencies\]\s*$/m.exec(text);
      if (devSection) {
        // Up to the next table: [package.metadata] after it lists every requirement, production ones included.
        const after = text.slice(devSection.index + devSection[0].length);
        const next = after.search(/^\[/m);
        dev.push(...[...(next >= 0 ? after.slice(0, next) : after).matchAll(/name\s*=\s*"([^"]+)"/g)].map((x) => x[1]!.toLowerCase()));
      }
    } else for (const d of direct) addEdge(edges, name, d);
  }
  return { prod, dev, edges };
}

// ── entry point ─────────────────────────────────────────────────────────────────────────────────────────────────────

const baseName = (p: string) => p.slice(p.lastIndexOf("/") + 1).toLowerCase();

/** The same packages with `dev: true` set on the ones that only a development tool needs. Never marks one it cannot account for. */
export function markDevOnly(path: string, body: string, packages: ManifestPackage[], siblingManifest?: string): ManifestPackage[] {
  const file = baseName(path);
  let names: Set<string> = new Set();
  try {
    if (file === "poetry.lock") names = poetryDevNames(body);
    else {
      const graph = file === "bun.lock" ? bunGraph(body) : file === "pnpm-lock.yaml" ? pnpmGraph(body) : file === "yarn.lock" ? yarnGraph(body, siblingManifest) : file === "uv.lock" ? uvGraph(body) : null;
      if (graph) names = devOnlyNames(graph);
    }
  } catch {
    return packages;
  }
  if (names.size === 0) return packages;
  const lower = file === "uv.lock" || file === "poetry.lock";
  return packages.map((p) => (names.has(lower ? p.name.toLowerCase() : p.name) && !p.dev ? { ...p, dev: true } : p));
}
