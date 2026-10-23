/**
 * Where a repository's files come from. The scan itself (repoScan.ts) only needs a file list and a way to read one file,
 * so how access was obtained is kept out of it:
 *
 *   publicGithubSource      GitHub's unauthenticated API and raw host. Public repositories only; no credential exists.
 *   githubInstallationSource  A GitHub App installation token (githubApp.ts), so a private repository the owner chose to
 *                           share can be read. The token is read-only (Contents: read, Metadata: read), lives for
 *                           an hour, and is held in memory for one scan.
 */
import { githubGet, whyNotOk } from "./githubSourceProbe";
import type { GithubScanOutcome } from "./githubSourceProbeOutcome";
import type { RepoRef } from "./repoFinding";
import { githubApi, githubRaw } from "./githubEndpoints";

export interface TreeFile { path: string; size: number }

export type OpenResult =
  | { ok: true; branch: string; tree: TreeFile[]; truncated: boolean }
  | { ok: false; status: GithubScanOutcome["status"] };

export interface RepoSource {
  /** How access was obtained, for the report. */
  readonly via: "public" | "github-app";
  open(): Promise<OpenResult>;
  /** The file's text, or null when it could not be read. */
  read(path: string, branch: string): Promise<string | null>;
}

interface RepoMeta { private: boolean; default_branch: string }
interface TreeEntry { path: string; type: string; size?: number; sha?: string }

/**
 * GitHub cuts the one-request file list off at 100,000 entries. A repository that large is read folder by folder instead,
 * so its size does not decide which files are seen. Reports truncated only if a folder could not be listed after all.
 */
async function walkTree(ref: RepoRef, rootSha: string, timeoutMs: number, headers: Record<string, string>): Promise<{ tree: TreeFile[]; truncated: boolean }> {
  const tree: TreeFile[] = [];
  let truncated = false;
  let inFlight = 0;
  const queue: Array<{ sha: string; prefix: string }> = [{ sha: rootSha, prefix: "" }];
  const workers = Array.from({ length: 6 }, async () => {
    for (;;) {
      const next = queue.pop();
      if (!next) { if (inFlight === 0) return; await new Promise((r) => setTimeout(r, 20)); continue; }
      inFlight++;
      try {
        const res = await githubGet(`${githubApi()}/repos/${ref.owner}/${ref.repo}/git/trees/${next.sha}`, "json", timeoutMs, headers);
        const body = res && res.ok ? (res.data as { tree?: TreeEntry[]; truncated?: boolean } | null) : null;
        if (!body?.tree) { truncated = true; continue; }
        if (body.truncated === true) truncated = true;
        for (const e of body.tree) {
          if (e.type === "blob") tree.push({ path: next.prefix + e.path, size: e.size ?? 0 });
          else if (e.type === "tree" && e.sha) queue.push({ sha: e.sha, prefix: `${next.prefix}${e.path}/` });
        }
      } finally { inFlight--; }
    }
  });
  await Promise.all(workers);
  return { tree, truncated };
}

async function openRepo(ref: RepoRef, timeoutMs: number, headers: Record<string, string>, allowPrivate: boolean): Promise<OpenResult> {
  const metaRes = await githubGet(`${githubApi()}/repos/${ref.owner}/${ref.repo}`, "json", timeoutMs, headers);
  if (!metaRes) return { ok: false, status: "unreachable" };
  if (!metaRes.ok) return { ok: false, status: whyNotOk(metaRes, "not_public_or_missing") };
  const meta = metaRes.data as RepoMeta | null;
  if (!meta || (meta.private && !allowPrivate)) return { ok: false, status: "not_public_or_missing" };
  const branch = ref.branch || meta.default_branch || "main";
  const treeRes = await githubGet(`${githubApi()}/repos/${ref.owner}/${ref.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`, "json", timeoutMs, headers);
  if (!treeRes) return { ok: false, status: "unreachable" };
  if (treeRes.status === 409) return { ok: true, branch, tree: [], truncated: false }; // no commits
  if (!treeRes.ok) return { ok: false, status: whyNotOk(treeRes, "unreadable") };
  const tree = treeRes.data as { sha?: string; tree?: TreeEntry[]; truncated?: boolean } | null;
  if (!tree?.tree) return { ok: false, status: "unreadable" };
  if (tree.truncated === true && tree.sha) {
    const walked = await walkTree(ref, tree.sha, timeoutMs, headers);
    // Use the walk only if it saw at least as much as the cut-off list did; otherwise keep the list and say it is partial.
    if (walked.tree.length >= tree.tree.filter((e) => e.type === "blob").length) return { ok: true, branch, tree: walked.tree, truncated: walked.truncated };
  }
  return {
    ok: true, branch, truncated: tree.truncated === true,
    tree: tree.tree.filter((e) => e.type === "blob").map((e) => ({ path: e.path, size: e.size ?? 0 })),
  };
}

const encodePath = (p: string) => p.split("/").map(encodeURIComponent).join("/");

/**
 * GITHUB_PUBLIC_API_TOKEN (optional): a read-only token used for api.github.com when reading a PUBLIC repository.
 * Without one, every user's public-repository scan shares GitHub's unauthenticated limit of 60 API calls an hour for the
 * server's address, so about thirty scans an hour would start failing. With one the limit is 5,000. Create it as a
 * fine-grained token with "Public repositories (read-only)" and no other access. It is never sent to the file host,
 * and a repository that turns out to be private is refused whatever the token could see (openRepo's allowPrivate).
 */
export function publicApiHeaders(env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const token = env["GITHUB_PUBLIC_API_TOKEN"]?.trim();
  return token ? { Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" } : {};
}

export function publicGithubSource(ref: RepoRef, timeoutMs = 10_000): RepoSource {
  return {
    via: "public",
    open: () => openRepo(ref, timeoutMs, publicApiHeaders(), false),
    async read(path, branch) {
      const r = await githubGet(`${githubRaw()}/${ref.owner}/${ref.repo}/${encodeURIComponent(branch)}/${encodePath(path)}`, "text", timeoutMs);
      return r && r.ok && typeof r.data === "string" ? r.data : null;
    },
  };
}

/** `token` is an installation access token. It is sent only to api.github.com and never written anywhere. */
export function githubInstallationSource(ref: RepoRef, token: string, timeoutMs = 10_000): RepoSource {
  const auth = { Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" };
  return {
    via: "github-app",
    open: () => openRepo(ref, timeoutMs, auth, true),
    async read(path, branch) {
      const r = await githubGet(
        `${githubApi()}/repos/${ref.owner}/${ref.repo}/contents/${encodePath(path)}?ref=${encodeURIComponent(branch)}`,
        "text", timeoutMs, { ...auth, Accept: "application/vnd.github.raw+json" },
      );
      return r && r.ok && typeof r.data === "string" ? r.data : null;
    },
  };
}
