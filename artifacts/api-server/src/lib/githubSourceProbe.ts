/**
 * Optional source-code scan of a PUBLIC GitHub repository, alongside the
 * live-URL scan. Runs only when the user supplies a repo URL for the scan —
 * it is never guessed or crawled for.
 *
 * Why this is a different question from the live-URL scan: a hardcoded key or
 * a wrong RLS migration can sit in a repo for months before it ever reaches a
 * deployed URL (or after it's removed from one) — a live-only scan structurally
 * cannot see either case. See jsScanner.ts for the equivalent check against
 * what the browser actually downloads.
 *
 * Deliberately narrow for a first version:
 *   - Public repositories only. No token is ever sent, so a private repo (or
 *     one that requires auth for any reason) simply produces no findings —
 *     never an attempt, a prompt, or a stored credential.
 *   - No cloning. Two calls to GitHub's own REST API (repo metadata, then the
 *     recursive tree listing) plus a bounded number of raw-file fetches.
 *   - A small, fixed candidate-path list, read most-valuable-first (see
 *     githubCandidates.ts) — the same discipline the signature-probe checks
 *     elsewhere in this codebase use for a fixed list of sensitive live paths.
 *   - Reuses the exact same secret patterns as the live JavaScript scan
 *     (scanContent in jsScanner.ts) rather than a second, divergent list, and
 *     adds a reader for the syntaxes config files use (configSecrets.ts), which
 *     those JS-shaped patterns cannot read.
 *   - Supabase migrations are read, but only the secret patterns run on them:
 *     nothing here inspects a migration for a missing or wrong RLS policy, which
 *     is the second example above and is not implemented.
 *
 * What it will NOT do is let a partial or empty read pass for a clean one. The
 * outcome names why a repository was not looked at, and a scan that read nothing
 * or only part says so: "scanned" with filesRead 0 used to be recorded as a clean
 * run, and a truncated file list or the 25-file cap left no trace at all.
 * Every request — the body as well as the headers — runs under one timeout.
 */

import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanContent, redactContext, redactSecret } from "./jsScanner";
import { scanConfigSecrets } from "./configSecrets";
import { isCandidatePath, prioritise, MAX_FILES } from "./githubCandidates";
import { configFinding, partialNote } from "./githubFindings";
import { type GithubRepoRef } from "./githubSourceProbeRef";
import { type GithubScanOutcome, NOT_SCANNED } from "./githubSourceProbeOutcome";
import { githubApi, githubRaw } from "./githubEndpoints";
export { parseGithubRepoRef } from "./githubSourceProbeRef";
export { githubNotScannedReason, githubProbeOutcome } from "./githubSourceProbeOutcome";
export type { GithubRepoRef } from "./githubSourceProbeRef";
export type { GithubScanOutcome } from "./githubSourceProbeOutcome";

export { isCandidatePath } from "./githubCandidates";

const GITHUB_FETCH_TIMEOUT_MS = 10_000;
const MAX_FILE_SIZE_BYTES = 200_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

/** A GitHub answer, fully read: the body is part of the request and runs under the same timeout. */
export interface GithubReply {
  ok: boolean;
  status: number;
  rateLimitRemaining: string | null;
  retryAfter: string | null;
  data: unknown;
}

export async function githubGet(url: string, as: "json" | "text", timeoutMs: number, extraHeaders: Record<string, string> = {}): Promise<GithubReply | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  // The abort rejects a real body read, but not every Response implementation, so it is raced explicitly.
  const deadline = new Promise<never>((_, reject) => controller.signal.addEventListener("abort", () => reject(new Error("timed out"))));
  deadline.catch(() => {});
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "SecScan", ...extraHeaders },
      signal: controller.signal,
    });
    const data = await Promise.race([as === "json" ? res.json() : res.text(), deadline]).catch((err: unknown) => {
      if (controller.signal.aborted) throw err;
      return null;
    });
    return {
      ok: res.ok,
      status: res.status,
      rateLimitRemaining: res.headers?.get?.("x-ratelimit-remaining") ?? null,
      retryAfter: res.headers?.get?.("retry-after") ?? null,
      data,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

interface RepoMeta {
  private: boolean;
  default_branch: string;
}

interface TreeEntry {
  path: string;
  type: string;
  size?: number;
}

/**
 * Why a non-OK answer was not a repository to scan. A 403 is a rate limit only on evidence: an
 * exhausted quota header, a Retry-After, or a message that says so. A blocked repository also
 * answers 403 (and 451, 401), and calling that "rate limited" is a false statement about it. A 403
 * with no evidence either way keeps the old reading, since a limit is by far its commonest cause.
 */
export function whyNotOk(res: GithubReply, missing: GithubScanOutcome["status"]): GithubScanOutcome["status"] {
  if (res.status === 404) return missing;
  if (res.status === 429) return "rate_limited";
  if (res.status === 403) {
    const message = String((res.data as { message?: unknown } | null)?.message ?? "");
    if (res.rateLimitRemaining === "0" || res.retryAfter !== null || /rate limit/i.test(message)) return "rate_limited";
    return /block|dmca|legal|access/i.test(message) ? "blocked" : "rate_limited";
  }
  if (res.status === 401 || res.status === 451) return "blocked";
  if (res.status >= 500) return "unreachable";
  return "unreadable";
}

/** The same scan as a list of findings alone. Never throws: an unscannable repo gives []. */
export async function scanGithubRepoForSecrets(ref: GithubRepoRef): Promise<ScanVulnerability[]> {
  return (await scanGithubRepo(ref)).findings;
}

/**
 * Fetch a bounded set of sensitive-looking files from a public repo's chosen branch and scan each
 * for a hardcoded secret. Never throws; a repo that could not be read comes back with a status
 * saying why, so it is not mistaken for a clean one.
 */
export async function scanGithubRepo(ref: GithubRepoRef, opts: { timeoutMs?: number } = {}): Promise<GithubScanOutcome> {
  const timeoutMs = opts.timeoutMs ?? GITHUB_FETCH_TIMEOUT_MS;

  const metaRes = await githubGet(`${githubApi()}/repos/${ref.owner}/${ref.repo}`, "json", timeoutMs);
  if (!metaRes) return NOT_SCANNED("unreachable");
  if (!metaRes.ok) return NOT_SCANNED(whyNotOk(metaRes, "not_public_or_missing"));
  const meta = metaRes.data as RepoMeta | null;
  if (!meta || meta.private) return NOT_SCANNED("not_public_or_missing");

  const branch = ref.branch || meta.default_branch || "main";
  const treeRes = await githubGet(
    `${githubApi()}/repos/${ref.owner}/${ref.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    "json",
    timeoutMs,
  );
  if (!treeRes) return NOT_SCANNED("unreachable");
  // GitHub answers 409 for a repository with no commits.
  if (treeRes.status === 409) return { findings: [], status: "empty", filesRead: 0 };
  if (!treeRes.ok) return NOT_SCANNED(whyNotOk(treeRes, "unreadable"));
  const tree = treeRes.data as { tree?: TreeEntry[]; truncated?: boolean } | null;
  if (!tree?.tree) return NOT_SCANNED("unreadable");

  const eligible = prioritise(
    tree.tree
      .filter((e) => e.type === "blob" && isCandidatePath(e.path))
      .filter((e) => (e.size ?? 0) <= MAX_FILE_SIZE_BYTES),
  );
  const candidates = eligible.slice(0, MAX_FILES);
  const skipped = eligible.length - candidates.length;

  const findings: ScanVulnerability[] = [];
  const seen = new Set<string>();
  let filesRead = 0;

  for (const entry of candidates) {
    const rawRes = await githubGet(
      `${githubRaw()}/${ref.owner}/${ref.repo}/${encodeURIComponent(branch)}/${entry.path.split("/").map(encodeURIComponent).join("/")}`,
      "text",
      timeoutMs,
    );
    if (!rawRes || !rawRes.ok || typeof rawRes.data !== "string") continue;
    const content = rawRes.data.slice(0, MAX_FILE_SIZE_BYTES);
    if (!content) continue;
    filesRead++;

    for (const f of scanContent(content)) {
      const key = `${f.pattern.name}|${entry.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(
        vuln({
          name: `${f.pattern.name} (in source repository)`,
          severity: f.pattern.severity,
          category: "Exposed Secrets / Credentials",
          // Not f.pattern.description: those are written for a secret shipped to a browser ("anyone who
          // views your page"), which is the wrong story for a file in a repository.
          description:
            `A credential matching "${f.pattern.name}" is committed in ${entry.path} of ${ref.owner}/${ref.repo}. ` +
            `Anyone who can read the repository can read it, and it stays in the Git history after it is deleted from the file. ` +
            `This is a source-code finding, not something read from the live site, so it applies whether or ` +
            `not the current deployment happens to carry the same secret.`,
          evidence: `Repository: ${ref.owner}/${ref.repo}\nFile: ${entry.path}\nMatch (redacted): ${redactSecret(f.match)}\nContext: ...${redactContext(f.context, f.match).slice(0, 200)}...`,
          solution: `Rotate the credential now: removing it from the file does not remove it from Git history. ${f.pattern.solution}`,
          cweId: f.pattern.cweId,
          cvssScore: f.pattern.cvssScore,
          wstgId: "WSTG-CONF-04",
        }),
      );
    }

    for (const hit of scanConfigSecrets(entry.path, content)) {
      const key = `config|${entry.path}|${hit.key}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(configFinding(ref, entry.path, hit));
    }
  }

  // Reading nothing is not scanning. Candidates existed and every one failed to download, which is
  // GitHub's raw host rate-limiting or failing, not a clean repository.
  if (candidates.length > 0 && filesRead === 0) return { ...NOT_SCANNED("unreadable"), skipped };

  const truncated = tree.truncated === true;
  if (truncated || skipped > 0 || filesRead < candidates.length) {
    findings.push(partialNote(ref, { filesRead, attempted: candidates.length, skipped, truncated }));
  }
  return { findings, status: "scanned", filesRead, skipped, truncated };
}