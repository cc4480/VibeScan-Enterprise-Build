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
interface TreeEntry { path: string; type: string; size?: number }

async function openRepo(ref: RepoRef, timeoutMs: number, headers: Record<string, string>, allowPrivate: boolean): Promise<OpenResult> {
  const metaRes = await githubGet(`https://api.github.com/repos/${ref.owner}/${ref.repo}`, "json", timeoutMs, headers);
  if (!metaRes) return { ok: false, status: "unreachable" };
  if (!metaRes.ok) return { ok: false, status: whyNotOk(metaRes, "not_public_or_missing") };
  const meta = metaRes.data as RepoMeta | null;
  if (!meta || (meta.private && !allowPrivate)) return { ok: false, status: "not_public_or_missing" };
  const branch = ref.branch || meta.default_branch || "main";
  const treeRes = await githubGet(`https://api.github.com/repos/${ref.owner}/${ref.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`, "json", timeoutMs, headers);
  if (!treeRes) return { ok: false, status: "unreachable" };
  if (treeRes.status === 409) return { ok: true, branch, tree: [], truncated: false }; // no commits
  if (!treeRes.ok) return { ok: false, status: whyNotOk(treeRes, "unreadable") };
  const tree = treeRes.data as { tree?: TreeEntry[]; truncated?: boolean } | null;
  if (!tree?.tree) return { ok: false, status: "unreadable" };
  return {
    ok: true, branch, truncated: tree.truncated === true,
    tree: tree.tree.filter((e) => e.type === "blob").map((e) => ({ path: e.path, size: e.size ?? 0 })),
  };
}

const encodePath = (p: string) => p.split("/").map(encodeURIComponent).join("/");

export function publicGithubSource(ref: RepoRef, timeoutMs = 10_000): RepoSource {
  return {
    via: "public",
    open: () => openRepo(ref, timeoutMs, {}, false),
    async read(path, branch) {
      const r = await githubGet(`https://raw.githubusercontent.com/${ref.owner}/${ref.repo}/${encodeURIComponent(branch)}/${encodePath(path)}`, "text", timeoutMs);
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
        `https://api.github.com/repos/${ref.owner}/${ref.repo}/contents/${encodePath(path)}?ref=${encodeURIComponent(branch)}`,
        "text", timeoutMs, { ...auth, Accept: "application/vnd.github.raw+json" },
      );
      return r && r.ok && typeof r.data === "string" ? r.data : null;
    },
  };
}
