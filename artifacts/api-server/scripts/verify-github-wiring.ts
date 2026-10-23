/**
 * End to end for the GitHub repository option: a scan row carrying githubRepoUrl goes through the
 * real worker (processScanJob), and the saved report must show the "GitHub source code secrets"
 * test having run against that repository. Local fixture as the target, a public repo you own as
 * the source; only GitHub's public API is contacted for the repo.
 *
 *   DATABASE_URL=postgres://... ALLOW_PRIVATE_SCAN_TARGETS=true \
 *     npx tsx scripts/verify-github-wiring.ts https://github.com/owner/repo
 */
import { db, pool, scansTable, reportsTable, migrateToLatest } from "@workspace/db";
import { eq } from "drizzle-orm";
import { processScanJob } from "../src/lib/worker.js";
import { normaliseGithubRepoInput } from "../src/lib/githubRepoInput.js";
import { initBrowser, closeBrowser } from "../src/lib/browser.js";

const TARGET = process.env["SCAN_TARGET"] ?? "http://127.0.0.1:4100";
const input = process.argv[2] ?? "";

async function main(): Promise<void> {
  await migrateToLatest(process.env["DATABASE_URL"]!);
  const repo = normaliseGithubRepoInput(input);
  if (!repo.ok) throw new Error(repo.error);
  const [scan] = await db
    .insert(scansTable)
    .values({ userId: "wire-check", userEmail: "wire@example.test", targetUrl: TARGET, tier: "deep", status: "queued", paidWith: "free", githubRepoUrl: repo.url })
    .returning();
  console.log(`scan ${scan!.id} stored with githubRepoUrl=${scan!.githubRepoUrl}`);

  await initBrowser();
  await processScanJob({ data: { scanId: scan!.id, userId: "wire-check", targetUrl: TARGET, tier: "deep" } } as never);
  await closeBrowser();

  const [report] = await db.select().from(reportsTable).where(eq(reportsTable.scanId, scan!.id));
  if (!report) throw new Error("no report was saved");
  const json = JSON.stringify(report.data);
  const ran = /GitHub source code secrets/.test(json);
  console.log(`report saved; mentions the GitHub test: ${ran}`);
  const tests = (report.data as { tests?: { name: string; status: string; findings: number; reason?: string }[] }).tests ?? [];
  for (const t of tests.filter((x) => /GitHub/.test(x.name))) console.log(`  [${t.status}] ${t.name} — ${t.findings} finding(s)${t.reason ? ` (${t.reason})` : ""}`);
  const [after] = await db.select({ repo: scansTable.githubRepoUrl, status: scansTable.status }).from(scansTable).where(eq(scansTable.id, scan!.id));
  console.log(`row after the scan: status=${after!.status} githubRepoUrl=${after!.repo}`);
  await pool.end();
  process.exit(ran ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
