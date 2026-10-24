/**
 * File Linear and Jira tickets by itself when monitoring finds a new problem.
 *
 * The same rules as GitHub's (githubIssuesAuto.ts): opt-in per provider, only regressions, nothing below the chosen severity,
 * at most MAX_PER_SCAN a scan per provider, and through fileTicket so the one-ticket-per-problem rule, the secret redaction
 * and the daily cap hold exactly as for a click. Never throws: a failure here must not fail the scan.
 */
import { eq } from "drizzle-orm";
import { db, reportsTable } from "@workspace/db";
import { findingFingerprint } from "./fingerprint";
import { selectForFiling } from "./githubIssuesAuto";
import { fileTicket, getDestinations } from "./tickets";
import type { Log } from "./workerTypes";

export async function autoFileTickets(input: {
  userId: string;
  reportId: string;
  regressions: ReadonlyArray<{ category: string; name: string; evidence?: string | null; severity: string }>;
  log: Log;
}): Promise<void> {
  const { userId, reportId, regressions, log } = input;
  try {
    const dests = (await getDestinations(userId)).filter((d) => d.autoFile);
    if (dests.length === 0 || regressions.length === 0) return;

    // Ids come from the stored report, the same place a click on the finding reads them.
    const [report] = await db.select({ data: reportsTable.data }).from(reportsTable).where(eq(reportsTable.id, reportId));
    const vulns = (report?.data as { vulnerabilities?: Array<{ id?: string; category: string; name: string; evidence?: string | null }> } | undefined)?.vulnerabilities ?? [];
    const idByFingerprint = new Map(vulns.filter((v) => v.id).map((v) => [findingFingerprint(v.category, v.name, v.evidence), v.id!]));

    for (const dest of dests) {
      for (const r of selectForFiling(regressions, dest.autoMinSeverity)) {
        const findingId = idByFingerprint.get(findingFingerprint(r.category, r.name, r.evidence));
        if (!findingId) continue;
        const result = await fileTicket({ userId, provider: dest.provider, reportId, findingId });
        if (result.ok) {
          log.info({ reportId, provider: dest.provider, ticket: result.ticketKey, created: result.created }, "Ticket filed automatically");
        } else {
          log.warn({ reportId, provider: dest.provider, code: result.code }, "Automatic ticket not filed");
          // A rejected credential, a missing permission or the daily cap will not clear within this scan: stop asking this provider.
          break;
        }
      }
    }
  } catch (err) {
    log.warn({ err }, "Automatic ticket filing failed (non-fatal)");
  }
}
