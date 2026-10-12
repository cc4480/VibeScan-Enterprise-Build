/**
 * The repository scan: walk the file tree, read a bounded, prioritised set of files, run the checks, and say exactly
 * what was and was not read. Replaces the 25-file secrets-only read in githubSourceProbe.ts for callers that want the
 * whole picture; that module still supplies the secret patterns, the candidate list and the GitHub plumbing.
 *
 * Bounds (the scan runs inside a request budget and a memory budget, and a repository is attacker-supplied input):
 *   MAX_FILES        files read per repository
 *   MAX_FILE_BYTES   per file; a larger file is listed as skipped, not truncated into a half-read
 *   MAX_TOTAL_BYTES  bytes read per repository
 * Anything over a bound is counted and reported in the coverage note. "Nothing found" only ever means something about the
 * files that were read.
 */
import { scanContent, redactContext, redactSecret } from "./jsScanner";
import { scanConfigSecrets } from "./configSecrets";
import { isCandidatePath, prioritise, MAX_FILES as SECRET_FILES } from "./githubCandidates";
import { configFinding } from "./githubFindings";
import { NOT_SCANNED, type GithubScanOutcome } from "./githubSourceProbeOutcome";
import { repoFinding, NOT_THE_PROJECTS_OWN, type RepoFile, type RepoRef } from "./repoFinding";
import { supabaseMigrationFindings, isMigrationPath } from "./repoCheckSupabase";
import { ciConfigFindings, isWorkflowPath, isDockerfilePath, isSupabaseConfigPath } from "./repoCheckCi";
import { codePatternFindings, isCodePath, isEnvFilePath } from "./repoCheckCode";
import { dependencyFindings, isManifestPath, isLockfilePath } from "./repoCheckDeps";
import type { RepoSource, TreeFile } from "./repoSource";
import type { ScanVulnerability } from "./scanner";

export const MAX_FILES = 300;
export const MAX_FILE_BYTES = 1_000_000;
export const MAX_LOCKFILE_BYTES = 5_000_000;
export const MAX_TOTAL_BYTES = 25_000_000;
const CONCURRENCY = 6;

/** Which check wants a file, lowest number first: the cap is spent in this order. */
type Why = "secrets" | "migration" | "ci" | "manifest" | "code";
const PRIORITY: Record<Why, number> = { secrets: 0, migration: 1, ci: 2, manifest: 3, code: 4 };
/** Per-class ceilings, so one kind of file cannot use the whole budget. */
const CLASS_LIMIT: Record<Why, number> = { secrets: SECRET_FILES, migration: 100, ci: 40, manifest: 12, code: 160 };

function classify(path: string): Why | null {
  if (NOT_THE_PROJECTS_OWN.test(path) && !isEnvFilePath(path)) return null;
  if (isCandidatePath(path)) return isMigrationPath(path) ? "migration" : "secrets";
  if (isMigrationPath(path)) return "migration";
  if (isWorkflowPath(path) || isDockerfilePath(path) || isSupabaseConfigPath(path)) return "ci";
  if (isManifestPath(path) || isLockfilePath(path)) return "manifest";
  if (isCodePath(path)) return "code";
  return null;
}

/** Code nearest where an app keeps its own source reads first. */
const codeRank = (p: string) => (/^(?:src|app|server|api|pages|lib|supabase\/functions|functions)\//.test(p) ? 0 : 1) * 100 + p.split("/").length;

export interface RepoCoverage {
  treeFiles: number;
  chosen: number;
  read: number;
  bytesRead: number;
  /** Chosen files that did not fit under the file or byte caps. */
  leftOutByCap: number;
  /** Files over the per-file size limit. */
  tooLarge: number;
  /** GitHub cut the file list short. */
  truncatedTree: boolean;
  /** Chosen files that could not be downloaded. */
  failedReads: number;
  byCheck: Record<Why, number>;
}

export interface RepoScanOutcome extends GithubScanOutcome {
  coverage?: RepoCoverage;
  /** What each check looked at and found, for the per-test log. */
  checks?: Array<{ name: string; files: number; findings: number; note?: string }>;
  via?: RepoSource["via"];
}

export function chooseFiles(tree: TreeFile[]): { chosen: Array<TreeFile & { why: Why }>; leftOutByCap: number; tooLarge: number } {
  const byClass = new Map<Why, Array<TreeFile & { why: Why }>>();
  let tooLarge = 0;
  for (const f of tree) {
    const why = classify(f.path);
    if (!why) continue;
    const limit = isLockfilePath(f.path) ? MAX_LOCKFILE_BYTES : MAX_FILE_BYTES;
    if (f.size > limit) { tooLarge++; continue; }
    (byClass.get(why) ?? byClass.set(why, []).get(why)!).push({ ...f, why });
  }
  const ordered: Array<TreeFile & { why: Why }> = [];
  let leftOutByCap = 0;
  for (const why of (Object.keys(PRIORITY) as Why[]).sort((a, b) => PRIORITY[a] - PRIORITY[b])) {
    let list = byClass.get(why) ?? [];
    list = why === "secrets" ? prioritise(list) : why === "code" ? [...list].sort((a, b) => codeRank(a.path) - codeRank(b.path) || a.path.localeCompare(b.path)) : [...list].sort((a, b) => a.path.localeCompare(b.path));
    leftOutByCap += Math.max(0, list.length - CLASS_LIMIT[why]);
    ordered.push(...list.slice(0, CLASS_LIMIT[why]));
  }
  const kept = ordered.slice(0, MAX_FILES);
  leftOutByCap += ordered.length - kept.length;
  return { chosen: kept, leftOutByCap, tooLarge };
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) { const i = next++; out[i] = await fn(items[i]!); }
  }));
  return out;
}

function secretFindings(files: RepoFile[], ref: RepoRef): ScanVulnerability[] {
  const out: ScanVulnerability[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    // The secret patterns were written for configuration files; they run on those (and on migrations, where a key
    // pasted into a seed script is a real leak), not on application code, where test fixtures would make them noisy.
    if (!isCandidatePath(f.path) && !isEnvFilePath(f.path) && !isMigrationPath(f.path)) continue;
    for (const hit of scanContent(f.content)) {
      const key = `${hit.pattern.name}|${f.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(repoFinding({
        ref, path: f.path, name: `${hit.pattern.name} (in source repository)`,
        severity: hit.pattern.severity, category: "Exposed Secrets / Credentials", cweId: hit.pattern.cweId, cvssScore: hit.pattern.cvssScore ?? 0, confidence: 85, wstgId: "WSTG-CONF-04",
        description: `A credential matching "${hit.pattern.name}" is committed in ${f.path}. Anyone who can read the repository can read it, and it stays in the Git history after it is deleted from the file.`,
        detail: `Match (redacted): ${redactSecret(hit.match)}\nContext: ...${redactContext(hit.context, hit.match).slice(0, 200)}...`,
        solution: `Rotate the credential now: removing it from the file does not remove it from Git history. ${hit.pattern.solution}`,
      }));
    }
    for (const hit of scanConfigSecrets(f.path, f.content)) {
      const key = `config|${f.path}|${hit.key}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(configFinding(ref, f.path, hit));
    }
  }
  return out;
}

export async function scanRepository(source: RepoSource, ref: RepoRef): Promise<RepoScanOutcome> {
  const opened = await source.open();
  if (!opened.ok) return NOT_SCANNED(opened.status);
  if (opened.tree.length === 0) return { findings: [], status: "empty", filesRead: 0, via: source.via };

  const { chosen, leftOutByCap, tooLarge } = chooseFiles(opened.tree);
  const files: RepoFile[] = [];
  let bytesRead = 0;
  let failedReads = 0;
  let overBytes = 0;
  const byCheck: Record<Why, number> = { secrets: 0, migration: 0, ci: 0, manifest: 0, code: 0 };

  await mapLimit(chosen, CONCURRENCY, async (f) => {
    if (bytesRead >= MAX_TOTAL_BYTES) { overBytes++; return; }
    const text = await source.read(f.path, opened.branch);
    if (text === null) { failedReads++; return; }
    bytesRead += text.length;
    byCheck[f.why]++;
    files.push({ path: f.path, content: text });
  });
  files.sort((a, b) => a.path.localeCompare(b.path));

  // Chosen files existed and none could be read: GitHub's raw host failing is not a clean repository.
  if (chosen.length > 0 && files.length === 0) return { ...NOT_SCANNED("unreadable"), via: source.via };

  const findings: ScanVulnerability[] = [];
  const checks: NonNullable<RepoScanOutcome["checks"]> = [];
  const run = (name: string, scope: (f: RepoFile) => boolean, produce: (fs: RepoFile[]) => ScanVulnerability[]) => {
    const scoped = files.filter(scope);
    const found = scoped.length ? produce(scoped) : [];
    findings.push(...found);
    checks.push({ name, files: scoped.length, findings: found.length, ...(scoped.length === 0 ? { note: "no matching files in the repository" } : {}) });
  };

  run("repository secrets", (f) => isCandidatePath(f.path) || isEnvFilePath(f.path) || isMigrationPath(f.path), (fs) => secretFindings(fs, ref));
  run("Supabase migrations (RLS and policies)", (f) => isMigrationPath(f.path), (fs) => supabaseMigrationFindings(fs, ref));
  run("CI and configuration", (f) => isWorkflowPath(f.path) || isDockerfilePath(f.path) || isSupabaseConfigPath(f.path), (fs) => ciConfigFindings(fs, ref));
  run("dangerous code patterns", (f) => isCodePath(f.path) || isEnvFilePath(f.path), (fs) => codePatternFindings(fs, ref));

  const deps = await dependencyFindings(files).catch(() => ({ findings: [] as ScanVulnerability[], considered: 0, looked: 0, source: null as string | null }));
  findings.push(...deps.findings);
  checks.push({
    name: "dependency vulnerabilities (OSV)", files: files.filter((f) => isManifestPath(f.path) || isLockfilePath(f.path)).length, findings: deps.findings.length,
    ...(deps.considered === 0 ? { note: "no package.json or package-lock.json with exact versions" } : deps.looked < deps.considered ? { note: `looked up ${deps.looked} of ${deps.considered} packages` } : {}),
  });

  const cap = leftOutByCap + overBytes;
  const coverage: RepoCoverage = { treeFiles: opened.tree.length, chosen: chosen.length, read: files.length, bytesRead, leftOutByCap: cap, tooLarge, truncatedTree: opened.truncated, failedReads, byCheck };
  // Files in the repository but none of a kind these checks read (a Python or Go project, say): nothing was tested.
  const nothingRead = chosen.length === 0;
  if (nothingRead || opened.truncated || cap > 0 || tooLarge > 0 || failedReads > 0 || (deps.considered > deps.looked)) {
    findings.push(repoFinding({
      ref, path: "(repository)", name: "GitHub source scan covered only part of the repository",
      severity: "info", category: "Scan Coverage", cweId: null, cvssScore: 0, confidence: 100,
      description: "The source-code scan reads a bounded, prioritised set of files and could not read all of the repository. Nothing found in the files it did read is a statement about the rest, so this result should not be read as a clean scan of the repository.",
      detail: [
        `Files read: ${files.length} of ${chosen.length} chosen (${opened.tree.length} in the repository, ${(bytesRead / 1e6).toFixed(1)} MB read)`,
        ...(nothingRead ? ["No file in the repository is of a kind these checks read (JavaScript/TypeScript source, config and env files, SQL migrations, CI workflows, npm manifests), so nothing was tested"] : []),
        ...(cap > 0 ? [`Left out by the file and size limits: ${cap}`] : []),
        ...(tooLarge > 0 ? [`Over the ${MAX_FILE_BYTES / 1000} KB per-file limit: ${tooLarge}`] : []),
        ...(failedReads > 0 ? [`Could not be downloaded: ${failedReads}`] : []),
        ...(opened.truncated ? ["GitHub truncated the repository's file list, so files beyond it were never seen"] : []),
        ...(deps.considered > deps.looked ? [`Dependencies looked up: ${deps.looked} of ${deps.considered}`] : []),
      ].join("\n"),
      solution: "Re-run the scan, or check the files it did not reach by hand.",
    }));
  }
  return { findings, status: "scanned", filesRead: files.length, skipped: cap, truncated: opened.truncated, coverage, checks, via: source.via };
}
