/**
 * GitHub App authentication, so a private repository its owner chose to share can be read.
 *
 * Why an App and not a pasted personal access token: an installation is limited to the repositories the owner picks,
 * the permissions are fixed on the App (read-only Contents and Metadata), the owner can revoke it from GitHub at any time,
 * and what SecScan holds is never a long-lived user credential. This module holds none at all: it signs a short JWT with
 * the App's private key (an environment secret) and exchanges it for an installation access token that lives an hour,
 * scoped, for this one scan, to one repository and to read-only contents. The token is returned to the caller, used
 * in memory, and not logged, stored or put in a job payload (the job carries the installation id, which is not a secret).
 *
 * Setup (done once, by the owner of SecScan, in GitHub: Settings, Developer settings, GitHub Apps):
 *   Permissions: Repository contents: Read-only; Metadata: Read-only. Nothing else. No webhooks needed.
 *   Environment: GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY (the PEM, with newlines or \n escapes), GITHUB_APP_SLUG.
 */
import { createSign } from "node:crypto";
import { githubApi, githubWeb } from "./githubEndpoints";

export interface GithubAppConfig { appId: string; privateKey: string; slug: string | null }

/**
 * A PEM as it arrives from an environment variable, which hosting dashboards mangle in predictable ways: quotes pasted
 * along with the value, line breaks written as the two characters \n, or line breaks flattened into spaces. The base64
 * body is rebuilt on 64-character lines inside the BEGIN/END markers, which is the form Node expects.
 */
export function normalisePem(raw: string): string {
  let key = raw.trim();
  if (key.length >= 2 && ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'")))) key = key.slice(1, -1).trim();
  if (key.includes("\\n")) key = key.replace(/\\n/g, "\n");
  const m = key.match(/^(-----BEGIN [A-Z ]+-----)([\s\S]*?)(-----END [A-Z ]+-----)$/);
  if (!m) return key;
  const body = (m[2] ?? "").replace(/\s+/g, "");
  if (!body) return key;
  return `${m[1]}\n${body.match(/.{1,64}/g)!.join("\n")}\n${m[3]}\n`;
}

export function githubAppConfig(env: NodeJS.ProcessEnv = process.env): GithubAppConfig | null {
  const appId = env["GITHUB_APP_ID"]?.trim();
  const key = env["GITHUB_APP_PRIVATE_KEY"]?.trim();
  if (!appId || !key) return null;
  return { appId, privateKey: normalisePem(key), slug: env["GITHUB_APP_SLUG"]?.trim() || null };
}

const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64url");

/** The App's own JWT: RS256, valid ten minutes at most, issued a minute in the past to allow for clock skew. */
export function signAppJwt(cfg: GithubAppConfig, nowSeconds = Math.floor(Date.now() / 1000)): string {
  const head = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = b64url(JSON.stringify({ iat: nowSeconds - 60, exp: nowSeconds + 9 * 60, iss: cfg.appId }));
  const sig = createSign("RSA-SHA256").update(`${head}.${body}`).sign(cfg.privateKey);
  return `${head}.${body}.${b64url(sig)}`;
}

export interface InstallationToken { token: string; expiresAt: string }

/** Why a token could not be had. The message never contains a credential. */
export class GithubAppError extends Error {
  constructor(readonly reason: "not_configured" | "installation_missing" | "repository_not_shared" | "github_unavailable", message: string) { super(message); }
}

/**
 * An installation token limited to one repository and read-only contents. GitHub answers 404 for an installation that was
 * removed and 422 when the repository is not among those the owner shared; both mean "the owner has not given access".
 */
export async function installationToken(
  installationId: number,
  repo: string,
  cfg: GithubAppConfig | null = githubAppConfig(),
  fetchFn: typeof fetch = fetch,
): Promise<InstallationToken> {
  if (!cfg) throw new GithubAppError("not_configured", "the GitHub App is not configured on this server");
  if (!Number.isInteger(installationId) || installationId <= 0) throw new GithubAppError("installation_missing", "no GitHub installation is connected");
  let res: Response;
  try {
    res = await fetchFn(`${githubApi()}/app/installations/${installationId}/access_tokens`, {
      method: "POST",
      headers: { Authorization: `Bearer ${signAppJwt(cfg)}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SecScan", "Content-Type": "application/json" },
      body: JSON.stringify({ repositories: [repo], permissions: { contents: "read", metadata: "read" } }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new GithubAppError("github_unavailable", "GitHub could not be reached to authorise the repository read");
  }
  if (res.status === 404) throw new GithubAppError("installation_missing", "the GitHub installation no longer exists (the app was uninstalled)");
  if (res.status === 422) throw new GithubAppError("repository_not_shared", "the repository is not one the owner shared with the app");
  if (!res.ok) throw new GithubAppError("github_unavailable", `GitHub refused to issue an access token (HTTP ${res.status})`);
  const j = (await res.json().catch(() => null)) as { token?: unknown; expires_at?: unknown } | null;
  if (typeof j?.token !== "string" || !j.token) throw new GithubAppError("github_unavailable", "GitHub's answer carried no access token");
  return { token: j.token, expiresAt: typeof j.expires_at === "string" ? j.expires_at : "" };
}

/** The page where an owner installs the App and picks repositories. */
export function installUrl(cfg: GithubAppConfig | null = githubAppConfig(), state = ""): string | null {
  return cfg?.slug ? `${githubWeb()}/apps/${cfg.slug}/installations/new${state ? `?state=${encodeURIComponent(state)}` : ""}` : null;
}
