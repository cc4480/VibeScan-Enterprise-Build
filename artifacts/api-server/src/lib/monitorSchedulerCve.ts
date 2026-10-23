/** The CVE watch: new matches against each subscription's technologies. */
import { db, monitorSubscriptionsTable, cveAlertsTable, reportsTable } from "@workspace/db";
import { eq, and, desc, inArray } from "drizzle-orm";
import { sameSite } from "./urlKey";
import { logger } from "./logger";
import { fetchChangedCves, matchCvesToTechnologies, describeAffected } from "./cveMonitor";
import { sendMonitorCveAlertEmail } from "./mailer";
import { fireWebhook } from "./webhook";
import { APP_ORIGIN } from "./appOrigin";
import { highestSeverity } from "./notificationPrefs";
import { activeEntitledSubscriptions, enqueueMonitorScan } from "./monitorSchedulerSweep";

export const CVE_QUEUE        = "monitor-cve-check";

// ─── EPSS enrichment ──────────────────────────────────────────────────────────

export interface EpssEntry { cve: string; epss: string; percentile: string }

export async function fetchEpssScores(
  cveIds: string[],
): Promise<Map<string, { score: number; percentile: number }>> {
  if (cveIds.length === 0) return new Map();
  const log = logger.child({ job: "epss-fetch" });

  try {
    const url = `https://api.first.org/data/json?cve=${cveIds.join(",")}`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(15_000),
      headers: { Accept: "application/json" },
    });
    if (!res.ok) throw new Error(`EPSS API ${res.status}`);

    const json = (await res.json()) as { data?: EpssEntry[] };
    const map = new Map<string, { score: number; percentile: number }>();
    for (const entry of json.data ?? []) {
      map.set(entry.cve, {
        score: parseFloat(entry.epss),
        percentile: parseFloat(entry.percentile),
      });
    }
    log.info({ fetched: map.size }, "EPSS scores fetched");
    return map;
  } catch (err) {
    log.warn({ err }, "EPSS fetch failed (non-fatal)");
    return new Map();
  }
}

// ─── 3. CVE check job ─────────────────────────────────────────────────────────

/**
 * How far back the hourly CVE check looks.
 *
 * Longer than the hour between runs, deliberately. NVD populates a CVE's
 * published timestamp before it appears in the feed, so a window that exactly
 * matched the schedule would drop anything that landed in the seam. The overlap
 * is only safe because alerts are deduplicated per (subscription, CVE) — see
 * below.
 */
export const CVE_LOOKBACK_MS = 3 * 60 * 60 * 1000;

/**
 * Which of this run's CVE matches are genuinely new for one subscription.
 *
 * This is the only thing making an hourly CVE check possible. The lookback
 * window deliberately overlaps the schedule, so the same CVE matches on several
 * consecutive runs; without this the user gets the same alert every hour and a
 * full rescan with it.
 *
 * It also collapses duplicates WITHIN a single run. One CVE can match two
 * technologies on the same site — "nginx" and "nginx 1.24", say — and the
 * already-alerted set is read from the database before any of this run's rows
 * are written, so a repeat inside one batch would slip past a database check
 * entirely and be inserted twice. The first match wins, because
 * matchCvesToTechnologies returns the most specific technology first.
 *
 * Pure and exported for tests: an off-by-one here is not a crash, it is a
 * customer receiving twenty-four identical emails a day.
 */
export function selectNewCveMatches<T extends { cve: { id: string } }>(
  matches: T[],
  alreadyAlerted: Iterable<string>,
): T[] {
  const seen = new Set(alreadyAlerted);
  const fresh: T[] = [];

  for (const match of matches) {
    if (seen.has(match.cve.id)) continue;
    seen.add(match.cve.id);
    fresh.push(match);
  }

  return fresh;
}

export async function runCveCheck(): Promise<void> {
  const log = logger.child({ job: CVE_QUEUE });
  log.info("Running CVE check");

  const now = new Date();
  const since = new Date(now.getTime() - CVE_LOOKBACK_MS);

  const { cves, ok } = await fetchChangedCves(since, now);
  const analysed = cves.filter((c) => c.products.length > 0).length;
  log.info(
    { cveCount: cves.length, withProductData: analysed, complete: ok, lookbackHours: CVE_LOOKBACK_MS / 3_600_000 },
    "Fetched changed CVEs from NVD",
  );
  // A partial fetch still gets matched: what did arrive is real, and the overlapping
  // window re-reads the rest next hour. fetchChangedCves has already logged the failure.
  if (cves.length === 0) return;

  const { subs: validSubs, total, skippedUnentitled } = await activeEntitledSubscriptions(now);
  log.info(
    { total, subscriptions: validSubs.length, skippedUnentitled },
    "Checking active subscriptions against CVEs",
  );

  const appOrigin = APP_ORIGIN;

  for (const sub of validSubs) {
    try {
      const [latestReport] = await db
        .select({ id: reportsTable.id, data: reportsTable.data })
        .from(reportsTable)
        .where(
          and(
            eq(reportsTable.userId, sub.userId),
            sameSite(reportsTable.targetUrl, sub.targetUrl),
          ),
        )
        .orderBy(desc(reportsTable.createdAt))
        .limit(1);

      if (!latestReport) continue;

      const reportData = latestReport.data as { technologies?: string[] };
      const technologies = reportData.technologies ?? [];
      if (technologies.length === 0) continue;

      const allMatches = matchCvesToTechnologies(technologies, cves);
      if (allMatches.length === 0) continue;

      // Drop anything this subscription has already been told about.
      //
      // This is what makes an hourly cadence possible at all. The lookback
      // window overlaps the schedule by design, so the same CVE matches on
      // several consecutive runs; without this the user would get the same
      // alert every hour and a rescan every hour with it. Keyed on the
      // subscription, not the user, because two monitored sites can genuinely
      // both be affected by one CVE.
      const seen = await db
        .select({ cveId: cveAlertsTable.cveId })
        .from(cveAlertsTable)
        .where(
          and(
            eq(cveAlertsTable.subscriptionId, sub.id),
            inArray(cveAlertsTable.cveId, allMatches.map(({ cve }) => cve.id)),
          ),
        );

      const matches = selectNewCveMatches(allMatches, seen.map((row) => row.cveId));

      if (matches.length === 0) {
        log.debug(
          { subscriptionId: sub.id, alreadyAlerted: seen.length },
          "CVE matches all previously alerted — nothing to do",
        );
        continue;
      }

      log.info(
        {
          subscriptionId: sub.id,
          targetUrl: sub.targetUrl,
          matches: matches.length,
          suppressedAsDuplicate: allMatches.length - matches.length,
        },
        "New CVE matches found — enriching with EPSS and triggering rescan",
      );

      // Fetch EPSS scores for all matched CVEs
      const cveIds = matches.map(({ cve }) => cve.id);
      const epssMap = await fetchEpssScores(cveIds);

      // Enqueue immediate rescan
      const scanId = await enqueueMonitorScan(sub, "cve");

      // Schedule a 24h follow-up rescan: set nextScanAt = now + 24h so the adaptive
      // sweep will pick it up again 24 hours after the CVE-triggered scan.
      await db
        .update(monitorSubscriptionsTable)
        .set({ nextScanAt: new Date(Date.now() + 24 * 60 * 60 * 1000) })
        .where(eq(monitorSubscriptionsTable.id, sub.id));

      // Insert CVE alerts sorted by EPSS × severity_weight descending
      const SEVERITY_WEIGHT: Record<string, number> = {
        CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1,
      };
      const combinedScore = (cveId: string, severity: string) =>
        (epssMap.get(cveId)?.score ?? 0) * (SEVERITY_WEIGHT[severity?.toUpperCase()] ?? 1);

      const sortedMatches = [...matches].sort((a, b) =>
        combinedScore(b.cve.id, b.cve.severity) - combinedScore(a.cve.id, a.cve.severity),
      );

      for (const match of sortedMatches) {
        const { cve } = match;
        const epss = epssMap.get(cve.id);
        await db.insert(cveAlertsTable).values({
          subscriptionId: sub.id,
          cveId: cve.id,
          cveSummary: cve.description.slice(0, 500),
          // Says whether the detected version is in the affected range or no
          // version was detected, so the alert is never read as more than it is.
          affectedTech: describeAffected(match),
          severity: cve.severity,
          epssScore: epss?.score ?? null,
          epssPercentile: epss?.percentile ?? null,
          triggerScanId: scanId ?? undefined,
        });
      }

      // Email
      if (sub.userEmail) {
        await sendMonitorCveAlertEmail({
          toEmail: sub.userEmail,
          userId: sub.userId,
          targetUrl: sub.targetUrl,
          cveMatches: sortedMatches.map((match) => ({
            cveId: match.cve.id,
            summary: match.cve.description.slice(0, 200),
            severity: match.cve.severity,
            affectedTech: describeAffected(match),
          })),
          scanId: scanId ?? "",
          dashboardUrl: `${appOrigin}/monitor`,
        });
      }

      // Webhook
      if (sub.webhookUrl) {
        await fireWebhook(sub.webhookUrl, "cve_alert", sub.targetUrl, sub.id, {
          cves: sortedMatches.map((match) => {
            const { cve } = match;
            const epss = epssMap.get(cve.id);
            return {
              cveId: cve.id,
              severity: cve.severity,
              affectedTech: match.matchedTech,
              // "affected": detected version is in the vulnerable range;
              // "unconfirmed": no version was detected, product only.
              basis: match.basis,
              epssScore: epss?.score,
              epssPercentile: epss?.percentile,
            };
          }),
          scanId,
        }, {
          userId: sub.userId,
          // The worst CVE in the batch. Judging by the first would drop a mail
          // containing a critical because it happened to lead with a low.
          severity: highestSeverity(sortedMatches.map(({ cve }) => ({ severity: cve.severity }))),
        });
      }
    } catch (err) {
      log.error({ err, subscriptionId: sub.id }, "CVE check failed for subscription");
    }
  }
}
