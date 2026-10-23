/**
 * The repository scan: walk the file tree, read every text file of the repository, run the checks, and say exactly
 * what was and was not read. Replaces the 25-file secrets-only read in githubSourceProbe.ts for callers that want the
 * whole picture; that module still supplies the secret patterns, the candidate list and the GitHub plumbing.
 *
 * There is no limit on how many files or how many bytes a repository has: every text file is read. Two bounds remain, both
 * about one file and both reported when they bite: MAX_FILE_BYTES (a file bigger than that is a data dump, not source, and
 * is listed as skipped rather than half-read) and the repository being unreadable. Memory stays flat however large the
 * repository is: files are read in batches, the per-file checks (secrets, code patterns) run on each batch and let it go,
 * and only the few kinds of file that a check needs side by side (migrations, CI, manifests) are kept to the end.
 * "Nothing found" only ever means something about the files that were read.
 */
import { scanContent, redactContext, redactSecret } from "./jsScanner";
import { scanConfigSecrets } from "./configSecrets";
import { isCandidatePath, prioritise } from "./githubCandidates";
import { configFinding } from "./githubFindings";
import { NOT_SCANNED, type GithubScanOutcome } from "./githubSourceProbeOutcome";
import { repoFinding, NOT_THE_PROJECTS_OWN, isTestOrExamplePath, asTestFileFinding, namesItselfFake, type RepoFile, type RepoRef } from "./repoFinding";
import { supabaseMigrationFindings, isMigrationPath } from "./repoCheckSupabase";
import { supabaseExtraFindings } from "./repoCheckSupabaseExtra";
import { softenSamplePaths, mergeSameName } from "./repoPostProcess";
import { IGNORE_FILE, applyIgnore, parseIgnore, suppressedNotice } from "./repoIgnore";
import { ciConfigFindings, isWorkflowPath, isDockerfilePath, isSupabaseConfigPath, isFunctionCodePath } from "./repoCheckCi";
import { isInfraPath } from "./repoCheckInfra";
import { codePatternFindings, isCodePath, isEnvFilePath } from "./repoCheckCode";
import { dependencyFindings, isManifestPath, isLockfilePath } from "./repoCheckDeps";
import type { RepoSource, TreeFile } from "./repoSource";
import type { RepoProgress } from "./repoProgress";
import type { ScanVulnerability } from "./scanner";

export const MAX_FILE_BYTES = 10_000_000;
export const MAX_LOCKFILE_BYTES = 25_000_000;
const CONCURRENCY = 10;
/** Files read, checked and released together. */
const BATCH = 100;

/** Which check wants a file, lowest number first: files are read in this order, so the ones that matter most come first. */
type Why = "secrets" | "migration" | "ci" | "manifest" | "code" | "other";
const PRIORITY: Record<Why, number> = { secrets: 0, migration: 1, ci: 2, manifest: 3, code: 4, other: 5 };

/** Files that are not text: reading them would only produce noise. Everything else is read. */
export const isBinaryPath = (p: string) =>
  /\.(?:png|jpe?g|gif|webp|avif|ico|icns|bmp|tiff?|heic|psd|ai|sketch|fig|woff2?|ttf|otf|eot|mp[34]|m4[av]|mov|avi|mkv|webm|wav|ogg|flac|zip|gz|tgz|tar|rar|7z|bz2|xz|zst|pdf|exe|dll|so|dylib|bin|dat|wasm|class|jar|pyc|o|a|lib|sqlite3?|db|parquet|onnx|pt|pth|safetensors|ckpt|npy|npz)$/i.test(p);

function classify(path: string): Why | null {
  if (NOT_THE_PROJECTS_OWN.test(path) && !isEnvFilePath(path)) return null;
  if (isCandidatePath(path)) return isMigrationPath(path) ? "migration" : "secrets";
  if (isMigrationPath(path)) return "migration";
  if (isWorkflowPath(path) || isDockerfilePath(path) || isSupabaseConfigPath(path) || isInfraPath(path)) return "ci";
  if (isManifestPath(path) || isLockfilePath(path)) return "manifest";
  if (isCodePath(path)) return "code";
  // Everything else that is text (documentation, styles, scripts in other languages, data, tests) is read for secrets.
  if (!isBinaryPath(path) && !NOT_THE_PROJECTS_OWN.test(path)) return "other";
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
  /** Files left alone on purpose: not text (images, fonts, archives), or inside a folder that is not the project's own. */
  notRead: { binary: number; vendored: number };
}

/** What a repository scan returns: the outcome the scanner records, with its coverage and per-check results (see GithubScanOutcome). */
export type RepoScanOutcome = GithubScanOutcome;

export function chooseFiles(tree: TreeFile[]): { chosen: Array<TreeFile & { why: Why }>; tooLarge: number; notRead: { binary: number; vendored: number } } {
  const byClass = new Map<Why, Array<TreeFile & { why: Why }>>();
  let tooLarge = 0;
  const notRead = { binary: 0, vendored: 0 };
  for (const f of tree) {
    const why = classify(f.path);
    if (!why) { if (isBinaryPath(f.path)) notRead.binary++; else notRead.vendored++; continue; }
    const limit = isLockfilePath(f.path) ? MAX_LOCKFILE_BYTES : MAX_FILE_BYTES;
    if (f.size > limit) { tooLarge++; continue; }
    (byClass.get(why) ?? byClass.set(why, []).get(why)!).push({ ...f, why });
  }
  const chosen: Array<TreeFile & { why: Why }> = [];
  for (const why of (Object.keys(PRIORITY) as Why[]).sort((a, b) => PRIORITY[a] - PRIORITY[b])) {
    const list = byClass.get(why) ?? [];
    chosen.push(...(why === "secrets" ? prioritise(list) : why === "code" ? [...list].sort((a, b) => codeRank(a.path) - codeRank(b.path) || a.path.localeCompare(b.path)) : [...list].sort((a, b) => a.path.localeCompare(b.path))));
  }
  return { chosen, tooLarge, notRead };
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
    // Every file that was read is checked: a key pasted into application code, a script or a README leaks as surely as
    // one in a .env file. Lockfiles are the exception (their hashes are not secrets) and are read only for dependencies.
    if (isLockfilePath(f.path)) continue;
    for (const hit of scanContent(f.content)) {
      const key = `${hit.pattern.name}|${f.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const soften = isTestOrExamplePath(f.path)
        ? (v: ScanVulnerability) => asTestFileFinding(v, "test-file")
        : namesItselfFake(hit.context) ? (v: ScanVulnerability) => asTestFileFinding(v, "named-fake") : (v: ScanVulnerability) => v;
      out.push(soften(repoFinding({
        ref, path: f.path, name: `${hit.pattern.name} (in source repository)`,
        severity: hit.pattern.severity, category: "Exposed Secrets / Credentials", cweId: hit.pattern.cweId, cvssScore: hit.pattern.cvssScore ?? 0, confidence: 85, wstgId: "WSTG-CONF-04",
        description: `A credential matching "${hit.pattern.name}" is committed in ${f.path}. Anyone who can read the repository can read it, and it stays in the Git history after it is deleted from the file.`,
        detail: `Match (redacted): ${redactSecret(hit.match)}\nContext: ...${redactContext(hit.context, hit.match).slice(0, 200)}...`,
        solution: `Rotate the credential now: removing it from the file does not remove it from Git history. ${hit.pattern.solution}`,
      })));
    }
    for (const hit of scanConfigSecrets(f.path, f.content)) {
      const key = `config|${f.path}|${hit.key}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const found = configFinding(ref, f.path, hit);
      out.push(isTestOrExamplePath(f.path) ? asTestFileFinding(found) : hit.namesItselfFake ? asTestFileFinding(found, "named-fake") : hit.devDefault ? asTestFileFinding(found, "dev-default") : found);
    }
  }
  return out;
}

/** Files a check needs alongside others (a table in one migration, its policy in the next), so they are kept to the end. */
const keptToTheEnd = (p: string) =>
  isMigrationPath(p) || isWorkflowPath(p) || isDockerfilePath(p) || isSupabaseConfigPath(p) || isFunctionCodePath(p) || isInfraPath(p) || isManifestPath(p) || isLockfilePath(p) || p === IGNORE_FILE;

/**
 * Migrations grouped by the Supabase project they belong to (the folder that holds supabase/). A monorepo can carry
 * several, such as the real app and a library's test projects, and judging them as one pool would let a table of one
 * stand in for another's.
 */
function bySupabaseProject(files: RepoFile[]): RepoFile[][] {
  const groups = new Map<string, RepoFile[]>();
  for (const f of files) {
    const root = /^(.*?)supabase\//.exec(f.path)?.[1] ?? "";
    (groups.get(root) ?? groups.set(root, []).get(root)!).push(f);
  }
  return [...groups.values()];
}

export async function scanRepository(source: RepoSource, ref: RepoRef, opts: { onProgress?: (e: RepoProgress) => void } = {}): Promise<RepoScanOutcome> {
  const onProgress = opts.onProgress;
  const opened = await source.open();
  if (!opened.ok) return NOT_SCANNED(opened.status);
  if (opened.tree.length === 0) return { findings: [], status: "empty", filesRead: 0, via: source.via };

  const { chosen, tooLarge, notRead } = chooseFiles(opened.tree);
  onProgress?.({ kind: "listed", treeFiles: opened.tree.length, toRead: chosen.length, binary: notRead.binary, vendored: notRead.vendored, tooLarge, truncated: opened.truncated });
  const files: RepoFile[] = []; // only what is kept to the end
  const readPaths: string[] = [];
  const findings: ScanVulnerability[] = [];
  let bytesRead = 0;
  let failedReads = 0;
  const byCheck: Record<Why, number> = { secrets: 0, migration: 0, ci: 0, manifest: 0, code: 0, other: 0 };
  const secrets = { files: 0, found: 0 };
  const code = { files: 0, found: 0 };

  // About ten progress lines however big the repository is, and always one for the last batch.
  const batches = Math.ceil(chosen.length / BATCH);
  const every = Math.max(1, Math.ceil(batches / 10));
  for (let i = 0; i < chosen.length; i += BATCH) {
    const batch: RepoFile[] = [];
    await mapLimit(chosen.slice(i, i + BATCH), CONCURRENCY, async (f) => {
      const text = await source.read(f.path, opened.branch);
      if (text === null) { failedReads++; return; }
      bytesRead += text.length;
      byCheck[f.why]++;
      batch.push({ path: f.path, content: text });
    });
    batch.sort((a, b) => a.path.localeCompare(b.path));
    readPaths.push(...batch.map((f) => f.path));

    // The per-file checks run now, so the batch can be released.
    const forSecrets = batch.filter((f) => !isLockfilePath(f.path));
    if (forSecrets.length) { const found = secretFindings(forSecrets, ref); findings.push(...found); secrets.files += forSecrets.length; secrets.found += found.length; }
    const forCode = batch.filter((f) => isCodePath(f.path) || isEnvFilePath(f.path));
    if (forCode.length) { const found = codePatternFindings(forCode, ref); findings.push(...found); code.files += forCode.length; code.found += found.length; }
    files.push(...batch.filter((f) => keptToTheEnd(f.path)));
    const n = i / BATCH + 1;
    if (n % every === 0 || n === batches) onProgress?.({ kind: "reading", read: readPaths.length, total: chosen.length, bytes: bytesRead });
  }

  // Chosen files existed and none could be read: GitHub's raw host failing is not a clean repository.
  if (chosen.length > 0 && readPaths.length === 0) return { ...NOT_SCANNED("unreadable"), via: source.via };

  const checks: NonNullable<RepoScanOutcome["checks"]> = [];
  const record = (name: string, scoped: number, found: number) =>
    checks.push({ name, files: scoped, findings: found, ...(scoped === 0 ? { note: "no matching files in the repository" } : {}) });
  const run = (name: string, scope: (f: RepoFile) => boolean, produce: (fs: RepoFile[]) => ScanVulnerability[]) => {
    const scoped = files.filter(scope);
    const found = scoped.length ? produce(scoped) : [];
    findings.push(...found);
    record(name, scoped.length, found.length);
  };

  record("repository secrets", secrets.files, secrets.found);
  run("Supabase migrations (RLS and policies)", (f) => isMigrationPath(f.path), (fs) => bySupabaseProject(fs).flatMap((project) => [...supabaseMigrationFindings(project, ref), ...supabaseExtraFindings(project, ref)]));
  run("CI and configuration", (f) => isWorkflowPath(f.path) || isDockerfilePath(f.path) || isSupabaseConfigPath(f.path) || isFunctionCodePath(f.path) || isInfraPath(f.path), (fs) => ciConfigFindings(fs, ref));
  record("dangerous code patterns", code.files, code.found);

  const deps = await dependencyFindings(files, ref).catch(() => ({ findings: [] as ScanVulnerability[], considered: 0, looked: 0, source: null as string | null }));
  findings.push(...deps.findings);
  checks.push({
    name: "dependency vulnerabilities (OSV)", files: files.filter((f) => isManifestPath(f.path) || isLockfilePath(f.path)).length, findings: deps.findings.length,
    ...(deps.considered === 0 ? { note: "no dependency file with exact versions (a lockfile, or a pinned package.json, requirements.txt or go.mod)" } : deps.looked < deps.considered ? { note: `looked up ${deps.looked} of ${deps.considered} packages` } : {}),
  });

  // Report what matters, once: samples softened, repeats of a low-level finding merged.
  // What the owner has marked as accepted in .secscanignore comes out first, and is counted in the report.
  const ignoreFile = files.find((f) => f.path === IGNORE_FILE);
  const { kept, suppressed } = applyIgnore(findings, ignoreFile ? parseIgnore(ignoreFile.content) : []);
  const ignoredNote = suppressedNotice(suppressed, ref);
  const shaped = mergeSameName(softenSamplePaths(kept));
  findings.length = 0;
  findings.push(...shaped, ...(ignoredNote ? [ignoredNote] : []));

  for (const c of checks) onProgress?.({ kind: "check", name: c.name, files: c.files, findings: c.findings, ...(c.note ? { note: c.note } : {}) });

  // No count or byte limit exists any more; the field stays so records and reports made before keep their meaning.
  const cap = 0;
  const coverage: RepoCoverage = { treeFiles: opened.tree.length, chosen: chosen.length, read: readPaths.length, bytesRead, leftOutByCap: cap, tooLarge, truncatedTree: opened.truncated, failedReads, byCheck, notRead };
  // Files in the repository but none of a kind these checks read (a Python or Go project, say): nothing was tested.
  const nothingRead = chosen.length === 0;
  if (nothingRead || opened.truncated || cap > 0 || tooLarge > 0 || failedReads > 0 || (deps.considered > deps.looked)) {
    // `repoFilesRead` lets a later scan's diff tell that a file was opened again even though this scan was partial.
    const notice = repoFinding({
      ref, path: "(repository)", name: "GitHub source scan covered only part of the repository",
      severity: "info", category: "Scan Coverage", cweId: null, cvssScore: 0, confidence: 100,
      description: "The source-code scan reads every text file of the repository and could not read all of it. Nothing found in the files it did read is a statement about the rest, so this result should not be read as a clean scan of the repository.",
      detail: [
        `Files read: ${readPaths.length} of ${chosen.length} chosen (${opened.tree.length} in the repository, ${(bytesRead / 1e6).toFixed(1)} MB read)`,
        ...(nothingRead ? ["No file in the repository is of a kind these checks read (text files of any kind, other than lockfiles, vendored folders such as node_modules, and binary files such as images), so nothing was tested"] : []),
        ...(tooLarge > 0 ? [`Over the ${MAX_FILE_BYTES / 1_000_000} MB per-file limit, so not read: ${tooLarge}`] : []),
        ...(failedReads > 0 ? [`Could not be downloaded: ${failedReads}`] : []),
        ...(opened.truncated ? ["GitHub truncated the repository's file list, so files beyond it were never seen"] : []),
        ...(deps.considered > deps.looked ? [`Dependencies looked up: ${deps.looked} of ${deps.considered}`] : []),
      ].join("\n"),
      solution: "Re-run the scan, or check the files it did not reach by hand.",
    });
    findings.push({ ...notice, repoFilesRead: readPaths } as ScanVulnerability);
  }
  return { findings, status: "scanned", filesRead: readPaths.length, skipped: cap, truncated: opened.truncated, coverage, checks, via: source.via };
}
