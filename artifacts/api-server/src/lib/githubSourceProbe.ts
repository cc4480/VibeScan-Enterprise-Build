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
 *   - A small, fixed candidate-path allowlist — the same discipline the
 *     signature-probe checks elsewhere in this codebase use for a fixed list
 *     of sensitive live paths, applied here to a fixed list of sensitive
 *     *repo* paths instead.
 *   - Reuses the exact same secret patterns as the live JavaScript scan
 *     (scanContent in jsScanner.ts) rather than a second, divergent list.
 */
import { randomUUID } from "node:crypto";
import type { ScanVulnerability } from "./scanner";
import { scanContent, redactContext, redactSecret } from "./jsScanner";

const GITHUB_FETCH_TIMEOUT_MS = 10_000;
const MAX_FILES = 25;
const MAX_FILE_SIZE_BYTES = 200_000;

function vuln(partial: Omit<ScanVulnerability, "id">): ScanVulnerability {
  return { id: randomUUID(), ...partial };
}

/** A path worth reading in full: config, environment and migration files most
 *  likely to carry a real secret or a database access-control statement. */
const CANDIDATE_PATH_RE =
  /(^|\/)\.env(\.[\w-]+)?$|(^|\/)\.env\.example$|(^|\/)config\/[\w.-]+\.(json|ya?ml|js|ts)$|(^|\/)docker-compose\.ya?ml$|(^|\/)\.aws\/credentials$|(^|\/)wp-config\.php$|(^|\/)settings\.py$|(^|\/)appsettings(\.[\w-]+)?\.json$|supabase\/migrations\/.*\.sql$|(^|\/)serviceAccountKey\.json$/i;

export interface GithubRepoRef {
  owner: string;
  repo: string;
}

/** Accepts a bare "owner/repo" or a full https://github.com/owner/repo(.git) URL. */
export function parseGithubRepoRef(input: string): GithubRepoRef | null {
  const trimmed = input.trim();
  const bare = /^([\w.-]+)\/([\w.-]+)$/.exec(trimmed);
  if (bare) return { owner: bare[1]!, repo: bare[2]!.replace(/\.git$/, "") };

  try {
    const url = new URL(trimmed);
    if (url.hostname !== "github.com" && url.hostname !== "www.github.com") return null;
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    return { owner: parts[0]!, repo: parts[1]!.replace(/\.git$/, "") };
  } catch {
    return null;
  }
}

async function githubFetch(url: string): Promise<Response | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), GITHUB_FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "SecScan" },
      signal: controller.signal,
    });
    return res;
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
 * What a scan of one repository actually did. "Nothing found" only means something when
 * `status` is "scanned" (or "empty", a repo with no files at all); every other status is a
 * repository that was not looked at.
 */
export interface GithubScanOutcome {
  findings: ScanVulnerability[];
  status: "scanned" | "empty" | "unreachable" | "rate_limited" | "not_public_or_missing";
  /** Files that matched the candidate list and were read. */
  filesRead: number;
}

/** Why a repository was not looked at, or null when it was. */
export function githubNotScannedReason(status: GithubScanOutcome["status"]): string | null {
  switch (status) {
    case "unreachable": return "GitHub could not be reached";
    case "rate_limited": return "GitHub's public API rate limit was reached";
    case "not_public_or_missing": return "the repository is private or does not exist";
    default: return null;
  }
}

const NOT_SCANNED = (status: GithubScanOutcome["status"]): GithubScanOutcome => ({ findings: [], status, filesRead: 0 });

/** The same scan as a list of findings alone. Never throws: an unscannable repo gives []. */
export async function scanGithubRepoForSecrets(ref: GithubRepoRef): Promise<ScanVulnerability[]> {
  return (await scanGithubRepo(ref)).findings;
}

/**
 * Fetch a bounded set of sensitive-looking files from a public repo's default
 * branch and scan each for a hardcoded secret. Never throws; a repo that could not be
 * read comes back with a status saying why, so it is not mistaken for a clean one.
 */
export async function scanGithubRepo(ref: GithubRepoRef): Promise<GithubScanOutcome> {
  const metaRes = await githubFetch(`https://api.github.com/repos/${ref.owner}/${ref.repo}`);
  if (!metaRes) return NOT_SCANNED("unreachable");
  if (metaRes.status === 403 || metaRes.status === 429) return NOT_SCANNED("rate_limited");
  if (!metaRes.ok) return NOT_SCANNED("not_public_or_missing");
  const meta = (await metaRes.json().catch(() => null)) as RepoMeta | null;
  if (!meta || meta.private) return NOT_SCANNED("not_public_or_missing");

  const branch = meta.default_branch || "main";
  const treeRes = await githubFetch(
    `https://api.github.com/repos/${ref.owner}/${ref.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
  );
  if (!treeRes) return NOT_SCANNED("unreachable");
  // GitHub answers 409 for a repository with no commits.
  if (treeRes.status === 409) return { findings: [], status: "empty", filesRead: 0 };
  if (treeRes.status === 403 || treeRes.status === 429) return NOT_SCANNED("rate_limited");
  if (!treeRes.ok) return NOT_SCANNED("unreachable");
  const tree = (await treeRes.json().catch(() => null)) as { tree?: TreeEntry[] } | null;
  if (!tree?.tree) return NOT_SCANNED("unreachable");

  const candidates = tree.tree
    .filter((e) => e.type === "blob" && CANDIDATE_PATH_RE.test(e.path))
    .filter((e) => (e.size ?? 0) <= MAX_FILE_SIZE_BYTES)
    .slice(0, MAX_FILES);

  const findings: ScanVulnerability[] = [];
  const seen = new Set<string>();
  let filesRead = 0;

  for (const entry of candidates) {
    const rawRes = await githubFetch(
      `https://raw.githubusercontent.com/${ref.owner}/${ref.repo}/${encodeURIComponent(branch)}/${entry.path}`,
    );
    if (!rawRes || !rawRes.ok) continue;
    const content = (await rawRes.text().catch(() => "")).slice(0, MAX_FILE_SIZE_BYTES);
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
          description:
            `${f.pattern.description} Found in the repository ${ref.owner}/${ref.repo}, at ${entry.path} — ` +
            `this is a source-code finding, not something read from the live site, so it applies whether or ` +
            `not the current deployment happens to carry the same secret.`,
          evidence: `Repository: ${ref.owner}/${ref.repo}\nFile: ${entry.path}\nMatch (redacted): ${redactSecret(f.match)}\nContext: ...${redactContext(f.context, f.match).slice(0, 200)}...`,
          solution: f.pattern.solution,
          cweId: f.pattern.cweId,
          cvssScore: f.pattern.cvssScore,
          wstgId: "WSTG-CONF-04",
        }),
      );
    }
  }

  return { findings, status: "scanned", filesRead };
}
