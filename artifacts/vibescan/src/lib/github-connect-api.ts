/**
 * Connect GitHub, from the scan form. Connecting is a full-page trip to GitHub and back through the server
 * (GET /api/github/connect, which returns to /scan?github=<outcome>); this file only words the outcome and reads or
 * forgets the connections.
 */
import { customFetch } from "@workspace/api-client-react";

/** How a connection stands: readable, uninstalled on GitHub's side, or GitHub could not be asked just now. */
export type ConnectionStatus = "ok" | "gone" | "unavailable";
export interface GithubConnection {
  installationId: number;
  accountLogin: string | null;
  /** Absent from an older server. */
  status?: ConnectionStatus;
  repositoryCount?: number;
}
export interface ConnectedRepository { fullName: string; private: boolean; url: string; installationId: number }
export interface GithubRepos { available: boolean; connections: GithubConnection[]; repositories: ConnectedRepository[] }

/** The server route that starts the trip to GitHub. A plain link, not a fetch: it is a page navigation. */
export const CONNECT_HREF = "/api/github/connect";

/** Straight to GitHub's page for choosing which repositories SecScan may read, for someone already connected. */
export const MANAGE_HREF = "/api/github/connect?manage=1";

export const getGithubRepos = () => customFetch<GithubRepos>("/api/github/repos");

export const disconnectGithub = (installationId: number) =>
  customFetch<{ removed: boolean }>(`/api/github/installations/${installationId}`, { method: "DELETE" });

export type ConnectOutcome = "connected" | "none" | "expired" | "unavailable" | "error";

/** What to tell the person after GitHub sends them back, or null for a URL that carries no outcome. */
export function connectOutcomeMessage(search: string): { tone: "good" | "warn"; text: string } | null {
  const outcome = new URLSearchParams(search).get("github");
  switch (outcome as ConnectOutcome | null) {
    case "connected":
      return { tone: "good", text: "GitHub is connected. Pick a repository below to read it with this scan." };
    case "none":
      return { tone: "warn", text: "GitHub did not show SecScan as installed. Connect again, and on GitHub choose the repositories to share and finish the install." };
    case "expired":
      return { tone: "warn", text: "That GitHub connection could not be confirmed, so nothing was saved. Start it again from this page." };
    case "unavailable":
      return { tone: "warn", text: "Connecting GitHub is not available right now. You can still check any public repository by its address." };
    case "error":
      return { tone: "warn", text: "GitHub did not finish connecting, so nothing was saved. Please try again." };
    default:
      return null;
  }
}

/** The value the repository field takes for a repository picked from the list. */
export const repoFieldValue = (r: ConnectedRepository) => `https://github.com/${r.fullName}`;

/**
 * What to tell the person about one connection that is not simply working, or null when there is nothing to say.
 * An uninstalled App and a GitHub that could not be reached are different problems with different fixes, and
 * "no repositories" is neither: it means the App is installed but nothing was shared.
 */
export function connectionNote(c: GithubConnection): string | null {
  const who = c.accountLogin ?? `installation ${c.installationId}`;
  if (c.status === "gone") return `SecScan was uninstalled from ${who} on GitHub. Disconnect it, then connect again to share repositories.`;
  if (c.status === "unavailable") return `GitHub could not be reached to list ${who}'s repositories just now. Try again in a moment.`;
  if (c.status === "ok" && c.repositoryCount === 0) return `SecScan is installed on ${who} but no repository is shared with it. Choose repositories on GitHub.`;
  return null;
}
