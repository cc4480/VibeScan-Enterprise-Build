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
import { githubAppConfig, signAppJwt, type GithubAppConfig } from "./githubApp";

/** installation id -> lower-cased emails allowed to use it. Malformed entries are dropped, not guessed at. */
export function parseInstallationOwners(raw: string | undefined): Map<number, Set<string>> {
  const owners = new Map<number, Set<string>>();
  for (const entry of (raw ?? "").split(";")) {
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
  env?: NodeJS.ProcessEnv;
  cfg?: GithubAppConfig | null;
  fetchFn?: typeof fetch;
}): Promise<number | null> {
  const env = input.env ?? process.env;
  const candidates = installationsOwnedBy(input.email, parseInstallationOwners(env["GITHUB_INSTALLATION_OWNERS"]));
  if (candidates.length === 0) return null;
  const cfg = input.cfg === undefined ? githubAppConfig(env) : input.cfg;
  if (!cfg) return null;
  const fetchFn = input.fetchFn ?? fetch;
  try {
    // Asks GitHub which installation (if any) covers this repository. 404: the App is not installed on it.
    const res = await fetchFn(
      `https://api.github.com/repos/${encodeURIComponent(input.repo.owner)}/${encodeURIComponent(input.repo.repo)}/installation`,
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
