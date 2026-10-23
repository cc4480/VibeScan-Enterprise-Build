/**
 * Connect GitHub: how a person proves which GitHub App installations they may use, and which repositories those
 * installations let SecScan read.
 *
 * The proof is GitHub's own. During installation the App asks the person to authorise it, GitHub hands back a
 * one-time code, and the code is exchanged (with the App's client secret) for a short-lived user token. That token
 * is used for exactly one call, GET /user/installations, which lists the installations THIS GitHub user can access.
 * Only installations of our App are kept, and the token is dropped. Nothing a request says about an installation id
 * is ever trusted on its own: an id is not a secret.
 *
 *   Environment: GITHUB_APP_CLIENT_ID, GITHUB_APP_CLIENT_SECRET (with GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY and
 *   GITHUB_APP_SLUG from githubApp.ts).
 */
import { githubAppConfig, signAppJwt, type GithubAppConfig } from "./githubApp";
import { githubApi, githubWeb } from "./githubEndpoints";

export interface GithubClientConfig { clientId: string; clientSecret: string }

export function githubClientConfig(env: NodeJS.ProcessEnv = process.env): GithubClientConfig | null {
  const clientId = env["GITHUB_APP_CLIENT_ID"]?.trim();
  const clientSecret = env["GITHUB_APP_CLIENT_SECRET"]?.trim();
  return clientId && clientSecret ? { clientId, clientSecret } : null;
}

/** Everything Connect GitHub needs is set: the App itself (to mint tokens) and its OAuth client (to prove the user). */
export function connectConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  const app = githubAppConfig(env);
  return Boolean(app?.slug) && githubClientConfig(env) !== null;
}

/**
 * Where to send someone to prove which GitHub account they are, so the installations they can use can be listed. This is
 * the first step of connecting, before any install page: a person who already installed the App is recognised at once and
 * comes straight back, instead of being left on GitHub's settings page with no way back to SecScan.
 * `redirectUri` must be one of the App's Callback URLs; when given, GitHub returns exactly there.
 */
export function authorizeUrl(client: GithubClientConfig, state: string, redirectUri?: string): string {
  return (
    `${githubWeb()}/login/oauth/authorize?client_id=${encodeURIComponent(client.clientId)}&state=${encodeURIComponent(state)}` +
    (redirectUri ? `&redirect_uri=${encodeURIComponent(redirectUri)}` : "")
  );
}

/** Why the GitHub side of connecting failed. The message never contains a credential. */
export class GithubConnectError extends Error {
  constructor(readonly reason: "code_rejected" | "github_unavailable", message: string) { super(message); }
}

const PAGE_SIZE = 100;
/** Pages read from any GitHub list: a ceiling, so an odd answer cannot loop. */
const MAX_PAGES = 10;

const GITHUB_HEADERS = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SecScan" };

/** The one-time code from GitHub's redirect, exchanged for a user token that is used once and dropped by the caller. */
export async function exchangeCode(code: string, client: GithubClientConfig, fetchFn: typeof fetch = fetch): Promise<string> {
  let res: Response;
  try {
    res = await fetchFn(`${githubWeb()}/login/oauth/access_token`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json", "User-Agent": "SecScan" },
      body: JSON.stringify({ client_id: client.clientId, client_secret: client.clientSecret, code }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new GithubConnectError("github_unavailable", "GitHub could not be reached to finish connecting");
  }
  const body = (await res.json().catch(() => null)) as { access_token?: unknown; error?: unknown } | null;
  // GitHub answers 200 with an "error" field for a bad, used or expired code.
  if (!res.ok || typeof body?.access_token !== "string" || !body.access_token) {
    throw new GithubConnectError(res.ok ? "code_rejected" : "github_unavailable", "GitHub did not accept the authorisation code");
  }
  return body.access_token;
}

export interface UserInstallation { installationId: number; accountLogin: string | null }

/**
 * The installations of OUR App that this GitHub user can access, as GitHub reports them for the user's own token.
 * An installation of any other App is ignored.
 */
export async function userInstallations(userToken: string, appId: string, fetchFn: typeof fetch = fetch): Promise<UserInstallation[]> {
  // A person who can reach more than 100 installations (of every App, not just this one) has them on later pages.
  const list: Array<Record<string, unknown>> = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    let res: Response;
    try {
      res = await fetchFn(`${githubApi()}/user/installations?per_page=${PAGE_SIZE}&page=${page}`, {
        headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${userToken}` },
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      throw new GithubConnectError("github_unavailable", "GitHub could not be reached to list installations");
    }
    if (!res.ok) throw new GithubConnectError("github_unavailable", `GitHub refused to list installations (HTTP ${res.status})`);
    const body = (await res.json().catch(() => null)) as { installations?: unknown } | null;
    const got = Array.isArray(body?.installations) ? (body!.installations as Array<Record<string, unknown>>) : [];
    list.push(...got);
    if (got.length < PAGE_SIZE) break;
  }
  return list
    .filter((i) => String(i["app_id"]) === String(appId) && typeof i["id"] === "number")
    .map((i) => {
      const account = i["account"] as { login?: unknown } | null | undefined;
      return { installationId: i["id"] as number, accountLogin: typeof account?.login === "string" ? account.login : null };
    });
}

export interface ConnectedRepository { fullName: string; private: boolean; url: string; installationId: number }

/**
 * How one connection stands: "ok" (listed, possibly with no repositories shared), "gone" (GitHub says the installation no
 * longer exists, so the App was uninstalled), or "unavailable" (GitHub could not be asked, or refused: say nothing is wrong
 * with the connection, only that it could not be read now).
 */
export type ConnectionStatus = "ok" | "gone" | "unavailable";

/**
 * The repositories one installation lets SecScan read. A token is minted for the whole installation, metadata only,
 * used for this listing and dropped. All pages are read (up to a ceiling), so an owner with more than 100 repositories
 * sees them all. The status says why the list is empty when it is.
 */
export async function installationRepositoryList(
  installationId: number,
  cfg: GithubAppConfig | null = githubAppConfig(),
  fetchFn: typeof fetch = fetch,
): Promise<{ status: ConnectionStatus; repositories: ConnectedRepository[] }> {
  if (!cfg) return { status: "unavailable", repositories: [] };
  try {
    const tokenRes = await fetchFn(`${githubApi()}/app/installations/${installationId}/access_tokens`, {
      method: "POST",
      headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${signAppJwt(cfg)}`, "Content-Type": "application/json" },
      body: JSON.stringify({ permissions: { metadata: "read" } }),
      signal: AbortSignal.timeout(10_000),
    });
    if (tokenRes.status === 404) return { status: "gone", repositories: [] };
    if (!tokenRes.ok) return { status: "unavailable", repositories: [] };
    const token = ((await tokenRes.json().catch(() => null)) as { token?: unknown } | null)?.token;
    if (typeof token !== "string" || !token) return { status: "unavailable", repositories: [] };

    const repositories: ConnectedRepository[] = [];
    for (let page = 1; page <= MAX_PAGES; page++) {
      const res = await fetchFn(`${githubApi()}/installation/repositories?per_page=${PAGE_SIZE}&page=${page}`, {
        headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) return { status: repositories.length > 0 ? "ok" : "unavailable", repositories };
      const body = (await res.json().catch(() => null)) as { repositories?: unknown } | null;
      const repos = Array.isArray(body?.repositories) ? (body!.repositories as Array<Record<string, unknown>>) : [];
      for (const r of repos) {
        if (typeof r["full_name"] === "string" && typeof r["html_url"] === "string") {
          repositories.push({ fullName: r["full_name"], private: r["private"] === true, url: r["html_url"], installationId });
        }
      }
      if (repos.length < PAGE_SIZE) break;
    }
    return { status: "ok", repositories };
  } catch {
    return { status: "unavailable", repositories: [] };
  }
}

/** Just the repositories; empty (not an error) when the installation is gone or cannot be read. */
export async function installationRepositories(
  installationId: number,
  cfg: GithubAppConfig | null = githubAppConfig(),
  fetchFn: typeof fetch = fetch,
): Promise<ConnectedRepository[]> {
  return (await installationRepositoryList(installationId, cfg, fetchFn)).repositories;
}
