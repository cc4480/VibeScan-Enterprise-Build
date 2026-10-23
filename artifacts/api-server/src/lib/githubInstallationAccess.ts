/**
 * Who may read a private repository through the GitHub App.
 *
 * Installing the App proves that someone with access to a GitHub account shared repositories with SecScan. It says
 * nothing about WHICH SecScan account that person is. An installation id is not a secret, so if the scan form accepted
 * one from the request, any signed-in user could name another owner's installation and have SecScan read that owner's
 * private code for them. So an installation id is never taken from a request. A scan may use one only when:
 *
 *   1. the signed-in account's email is listed as an owner of that installation, in GITHUB_INSTALLATION_OWNERS, and
 *   2. GitHub itself says the installation covers this repository (the answer is the App's own, asked with its JWT).
 *
 * Until installations can be linked by proving ownership on GitHub (user authorisation during installation, which needs
 * the App's client credentials), this explicit list is the whole mechanism. It fails closed: anything missing, malformed,
 * unreachable or mismatched yields null, and the scan then reads only what is public, as it always did.
 *
 *   GITHUB_INSTALLATION_OWNERS="170782825=owner@example.com;98765=a@example.com,b@example.com"
 */
import { GithubAppError, githubAppConfig, installationToken, signAppJwt, type GithubAppConfig } from "./githubApp";
import { githubApi } from "./githubEndpoints";

/** installation id -> lower-cased emails allowed to use it. Malformed entries are dropped, not guessed at. */
export function parseInstallationOwners(raw: string | undefined): Map<number, Set<string>> {
  const owners = new Map<number, Set<string>>();
  // Dashboards sometimes keep the quotes a value was pasted with; they are never part of it.
  const text = (raw ?? "").trim().replace(/^(["'])([\s\S]*)\1$/, "$2");
  for (const entry of text.split(";")) {
    const [idPart, emailsPart, ...extra] = entry.split("=");
    if (extra.length > 0 || idPart === undefined || emailsPart === undefined) continue;
    const idText = idPart.trim();
    if (!/^[1-9]\d{0,15}$/.test(idText)) continue;
    const emails = emailsPart.split(",").map((e) => e.trim().toLowerCase()).filter((e) => /^[^@\s]+@[^@\s]+$/.test(e));
    if (emails.length === 0) continue;
    const id = Number(idText);
    const set = owners.get(id) ?? new Set<string>();
    for (const e of emails) set.add(e);
    owners.set(id, set);
  }
  return owners;
}

/** The installation ids this account is listed as an owner of. */
export function installationsOwnedBy(email: string | null | undefined, owners: Map<number, Set<string>>): number[] {
  const who = (email ?? "").trim().toLowerCase();
  if (!who) return [];
  return [...owners].filter(([, emails]) => emails.has(who)).map(([id]) => id);
}

export interface RepoCoordinates { owner: string; repo: string }

/**
 * The installation to read `repo` through for this account, or null. Null is the safe answer to every doubt, and it
 * never throws: a failure here must not stop a scan, only leave it with public access.
 */
export async function installationForRepo(input: {
  email: string | null | undefined;
  repo: RepoCoordinates;
  /** Installations this account connected through Connect GitHub (proven by GitHub at the time, see githubConnect.ts). */
  linked?: readonly number[];
  env?: NodeJS.ProcessEnv;
  cfg?: GithubAppConfig | null;
  fetchFn?: typeof fetch;
}): Promise<number | null> {
  const env = input.env ?? process.env;
  const candidates = [...new Set([
    ...installationsOwnedBy(input.email, parseInstallationOwners(env["GITHUB_INSTALLATION_OWNERS"])),
    ...(input.linked ?? []),
  ])];
  if (candidates.length === 0) return null;
  const cfg = input.cfg === undefined ? githubAppConfig(env) : input.cfg;
  if (!cfg) return null;
  const fetchFn = input.fetchFn ?? fetch;
  try {
    // Asks GitHub which installation (if any) covers this repository. 404: the App is not installed on it.
    const res = await fetchFn(
      `${githubApi()}/repos/${encodeURIComponent(input.repo.owner)}/${encodeURIComponent(input.repo.repo)}/installation`,
      {
        headers: { Authorization: `Bearer ${signAppJwt(cfg)}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SecScan" },
        signal: AbortSignal.timeout(8_000),
      },
    );
    if (!res.ok) return null;
    const body = (await res.json().catch(() => null)) as { id?: unknown } | null;
    const id = typeof body?.id === "number" ? body.id : null;
    return id !== null && candidates.includes(id) ? id : null;
  } catch {
    return null;
  }
}

/** What each step of getting private-repository access did, with nothing secret in it. */
export interface AccessDiagnosis {
  /** The account the server sees. Echoed back to the person who is signed in as it. */
  signedInAs: string | null;
  /** GITHUB_INSTALLATION_OWNERS holds at least one usable entry. */
  ownersConfigured: boolean;
  /** Why not, when it does not: the variable is absent from this server, or present but not in the installation=email form. */
  ownersVariable?: "missing" | "unreadable";
  /** Names of the GITHUB_* variables the server can see, when the owners variable is not usable. Never values. */
  githubVariableNamesSeen?: string[];
  /** This account is listed as an owner of some installation. Everything below runs only when it is. */
  listed: boolean;
  /** GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY are both set. */
  appConfigured?: boolean;
  /** The private key could sign the App's JWT. False means the key was pasted in a form it cannot read. */
  keySigns?: boolean;
  /** GitHub's answer to "which installation covers this repository?". */
  lookup?: { status: number | "unreachable" | "skipped"; installationId: number | null; coveredByOwnedInstallation: boolean };
  /** Whether a read-only token for just this repository could be minted, or why not. Never the token. */
  token?: "minted" | GithubAppError["reason"] | "skipped";
}

/**
 * Walks the same steps a scan does and says where it stops. Reaches GitHub only for an account that is listed as an
 * owner, so it cannot be used by anyone else to probe installations. Never returns, or logs, the key or a token.
 */
export async function diagnoseAccess(input: {
  email: string | null | undefined;
  repo: RepoCoordinates;
  /** Installations this account connected through Connect GitHub. */
  linked?: readonly number[];
  env?: NodeJS.ProcessEnv;
  fetchFn?: typeof fetch;
}): Promise<AccessDiagnosis> {
  const env = input.env ?? process.env;
  const fetchFn = input.fetchFn ?? fetch;
  const owners = parseInstallationOwners(env["GITHUB_INSTALLATION_OWNERS"]);
  const mine = [...new Set([...installationsOwnedBy(input.email, owners), ...(input.linked ?? [])])];
  const out: AccessDiagnosis = { signedInAs: input.email ?? null, ownersConfigured: owners.size > 0, listed: mine.length > 0 };
  if (!out.ownersConfigured) {
    out.ownersVariable = (env["GITHUB_INSTALLATION_OWNERS"] ?? "").trim() === "" ? "missing" : "unreadable";
    // Names only, never values: shows whether the server sees the variable under the exact name we expect.
    out.githubVariableNamesSeen = Object.keys(env).filter((k) => k.startsWith("GITHUB_")).sort();
  }
  if (!out.listed) return out;

  const cfg = githubAppConfig(env);
  out.appConfigured = cfg !== null;
  if (!cfg) return out;
  try { signAppJwt(cfg); out.keySigns = true; } catch { out.keySigns = false; return out; }

  let installationId: number | null = null;
  try {
    const res = await fetchFn(
      `${githubApi()}/repos/${encodeURIComponent(input.repo.owner)}/${encodeURIComponent(input.repo.repo)}/installation`,
      {
        headers: { Authorization: `Bearer ${signAppJwt(cfg)}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SecScan" },
        signal: AbortSignal.timeout(8_000),
      },
    );
    const body = res.ok ? ((await res.json().catch(() => null)) as { id?: unknown } | null) : null;
    installationId = typeof body?.id === "number" ? body.id : null;
    out.lookup = { status: res.status, installationId, coveredByOwnedInstallation: installationId !== null && mine.includes(installationId) };
  } catch {
    out.lookup = { status: "unreachable", installationId: null, coveredByOwnedInstallation: false };
    return out;
  }
  if (!out.lookup.coveredByOwnedInstallation || installationId === null) { out.token = "skipped"; return out; }
  try {
    await installationToken(installationId, input.repo.repo, cfg, fetchFn);
    out.token = "minted";
  } catch (err) {
    out.token = err instanceof GithubAppError ? err.reason : "github_unavailable";
  }
  return out;
}
