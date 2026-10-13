/**
 * The GitHub App installations each account has connected. Rows are written only by the Connect GitHub callback
 * (routes/githubConnect.ts) after GitHub listed the installation for the person's own authorisation.
 */
import { db, githubInstallationsTable } from "@workspace/db";
import { and, eq } from "drizzle-orm";
import type { UserInstallation } from "./githubConnect";

export interface GithubLink { installationId: number; accountLogin: string | null }

export async function linkedInstallations(userId: string): Promise<GithubLink[]> {
  const rows = await db
    .select({ installationId: githubInstallationsTable.installationId, accountLogin: githubInstallationsTable.accountLogin })
    .from(githubInstallationsTable)
    .where(eq(githubInstallationsTable.userId, userId));
  return rows
    .map((r) => ({ installationId: Number(r.installationId), accountLogin: r.accountLogin }))
    .filter((r) => Number.isInteger(r.installationId) && r.installationId > 0);
}

export async function linkedInstallationIds(userId: string): Promise<number[]> {
  return (await linkedInstallations(userId)).map((l) => l.installationId);
}

/** Records installations GitHub vouched for. Re-connecting the same one updates its account name, nothing else. */
export async function saveLinks(userId: string, installs: readonly UserInstallation[]): Promise<void> {
  for (const i of installs) {
    await db
      .insert(githubInstallationsTable)
      .values({ userId, installationId: String(i.installationId), accountLogin: i.accountLogin })
      .onConflictDoUpdate({
        target: [githubInstallationsTable.userId, githubInstallationsTable.installationId],
        set: { accountLogin: i.accountLogin },
      });
  }
}

/** Forgets one installation for this account. True when there was one to forget. */
export async function removeLink(userId: string, installationId: number): Promise<boolean> {
  const deleted = await db
    .delete(githubInstallationsTable)
    .where(and(eq(githubInstallationsTable.userId, userId), eq(githubInstallationsTable.installationId, String(installationId))))
    .returning({ id: githubInstallationsTable.id });
  return deleted.length > 0;
}
