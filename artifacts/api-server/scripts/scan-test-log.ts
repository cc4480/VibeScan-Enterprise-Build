/**
 * Prints every test a scan records (name, outcome, findings, reason), so "did
 * every test show up?" can be answered by reading a list instead of inferring.
 * Local fixture only: the target defaults to the vuln-fixture on 127.0.0.1:4100.
 *
 *   DATABASE_URL=postgres://localhost/whatever \
 *     npx tsx artifacts/api-server/scripts/scan-test-log.ts [plain|full] [githubRepo]
 *
 *   plain  active probing on, one signed-in account, no extras
 *   full   active probing on, two accounts, race-condition test opted in, and the
 *          optional GitHub repo (if given)
 */
import { runScan, type RunScanExtras } from "../src/lib/scanner.js";
import { initBrowser, closeBrowser } from "../src/lib/browser.js";

const TARGET = process.env.SCAN_TARGET ?? "http://127.0.0.1:4100";
const mode = process.argv[2] === "full" ? "full" : "plain";
const repo = process.argv[3];

async function main(): Promise<void> {
  const primary = { cookie: "session=alice-session-token" };
  const secondary = { cookie: "session=bob-session-token" };
  const extra: RunScanExtras | undefined =
    mode === "full" ? { raceConditionTesting: true, ...(repo ? { githubRepoUrl: repo } : {}) } : undefined;

  console.log(`[scan-test-log] ${mode} scan of ${TARGET}`);
  const seen: string[] = [];
  await initBrowser();
  const result = await runScan(
    TARGET,
    "deep",
    true,
    mode === "full" ? { credentials: primary, secondary } : { credentials: primary },
    null,
    (r) => {
      seen.push(r.name);
      const found = r.found?.length ? `  found: ${r.found.join("; ")}` : "";
      const why = r.reason ? `  (${r.reason})` : "";
      console.log(`  [${r.status.toUpperCase().padEnd(7)}] ${r.group.padEnd(8)} ${r.name} — ${r.findings} finding(s)${why}${found}`);
    },
    extra,
  );
  await closeBrowser();

  const counts = { ran: 0, skipped: 0, failed: 0 } as Record<string, number>;
  console.log(`\n[scan-test-log] ${result.vulnerabilities.length} findings; ${seen.length} tests recorded`);
  const expected = [
    "GitHub source code secrets",
    "LLM prompt injection (system prompt extraction)",
    "race condition (one-time action)",
    "cross-account access control (IDOR)",
  ];
  for (const name of expected) {
    const present = seen.some((s) => s === name || s.startsWith(`${name} (`));
    console.log(`  ${present ? "PRESENT" : "MISSING"}  ${name}`);
  }
  void counts;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
