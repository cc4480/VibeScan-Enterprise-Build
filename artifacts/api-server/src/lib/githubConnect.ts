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

/** Where to send someone to authorise the App without installing it again (they already have it installed). */
export function authorizeUrl(client: GithubClientConfig, state: string): string {
  return `https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(client.clientId)}&state=${encodeURIComponent(state)}`;
}

/** Why the GitHub side of connecting failed. The message never contains a credential. */
export class GithubConnectError extends Error {
  constructor(readonly reason: "code_rejected" | "github_unavailable", message: string) { super(message); }
}

const GITHUB_HEADERS = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SecScan" };

/** The one-time code from GitHub's redirect, exchanged for a user token that is used once and dropped by the caller. */
export async function exchangeCode(code: string, client: GithubClientConfig, fetchFn: typeof fetch = fetch): Promise<string> {
  let res: Response;
  try {
    res = await fetchFn("https://github.com/login/oauth/access_token", {
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
  let res: Response;
  try {
    res = await fetchFn("https://api.github.com/user/installations?per_page=100", {
      headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${userToken}` },
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new GithubConnectError("github_unavailable", "GitHub could not be reached to list installations");
  }
  if (!res.ok) throw new GithubConnectError("github_unavailable", `GitHub refused to list installations (HTTP ${res.status})`);
  const body = (await res.json().catch(() => null)) as { installations?: unknown } | null;
  const list = Array.isArray(body?.installations) ? (body!.installations as Array<Record<string, unknown>>) : [];
  return list
    .filter((i) => String(i["app_id"]) === String(appId) && typeof i["id"] === "number")
    .map((i) => {
      const account = i["account"] as { login?: unknown } | null | undefined;
      return { installationId: i["id"] as number, accountLogin: typeof account?.login === "string" ? account.login : null };
    });
}

export interface ConnectedRepository { fullName: string; private: boolean; url: string; installationId: number }

/**
 * The repositories one installation lets SecScan read. A token is minted for the whole installation, metadata only,
 * used for this one listing and dropped. Missing or failing installations yield an empty list, not an error: the
 * person may have uninstalled the App on GitHub since connecting.
 */
export async function installationRepositories(
  installationId: number,
  cfg: GithubAppConfig | null = githubAppConfig(),
  fetchFn: typeof fetch = fetch,
): Promise<ConnectedRepository[]> {
  if (!cfg) return [];
  try {
    const tokenRes = await fetchFn(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
      method: "POST",
      headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${signAppJwt(cfg)}`, "Content-Type": "application/json" },
      body: JSON.stringify({ permissions: { metadata: "read" } }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!tokenRes.ok) return [];
    const token = ((await tokenRes.json().catch(() => null)) as { token?: unknown } | null)?.token;
    if (typeof token !== "string" || !token) return [];
    const res = await fetchFn("https://api.github.com/installation/repositories?per_page=100", {
      headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return [];
    const body = (await res.json().catch(() => null)) as { repositories?: unknown } | null;
    const repos = Array.isArray(body?.repositories) ? (body!.repositories as Array<Record<string, unknown>>) : [];
    return repos
      .filter((r) => typeof r["full_name"] === "string" && typeof r["html_url"] === "string")
      .map((r) => ({ fullName: r["full_name"] as string, private: r["private"] === true, url: r["html_url"] as string, installationId }));
  } catch {
    return [];
  }
}
