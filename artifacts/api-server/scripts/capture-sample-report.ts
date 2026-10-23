/**
 * Captures the public sample report shown at secscan.info/sample-report.
 *
 * Runs the REAL scanner and the REAL AI analysis — the same runScan and
 * callDeepSeek the worker uses — against artifacts/vuln-fixture, a deliberately
 * vulnerable app we own, and writes the result as JSON. Nothing in the sample
 * is written by hand: re-run this whenever the scanner or the report changes,
 * and copy the output into the secscan-info repo.
 *
 * Usage:
 *   1. pnpm --filter @workspace/vuln-fixture run start
 *   2. DEEPSEEK_API_KEY=... npx tsx artifacts/api-server/scripts/capture-sample-report.ts \
 *        ../secscan-info/src/data/sample-report.json
 *
 * Env must be set on the command line, not inside this file: ESM imports are
 * hoisted, and lib/db reads DATABASE_URL on import. The dummy value is fine —
 * a scan with no scanId never touches the database.
 *   DATABASE_URL=postgres://localhost/x ALLOW_PRIVATE_SCAN_TARGETS=true ...
 *
 * Credentialed with two accounts, like verify-vuln-fixture.ts, so the sample
 * shows the access-control findings a verified-domain scan can produce.
 */
process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
process.env["DATABASE_URL"] ??= "postgres://localhost/capture-sample-report";

import { writeFileSync } from "node:fs";
import { runScan, computeRiskScore, computeGrade } from "../src/lib/scanner.js";
import { callDeepSeek } from "../src/lib/deepseek.js";
import { controlsForFinding, summariseCompliance, COMPLIANCE_DISCLAIMER } from "../src/lib/compliance.js";

const TARGET = "http://127.0.0.1:4100";
const out = process.argv[2];
if (!out) {
  console.error("Usage: capture-sample-report.ts <out.json>");
  process.exit(1);
}

async function main(): Promise<void> {
  const started = Date.now();
  const result = await runScan(
    TARGET,
    "deep",
    true,
    { credentials: { cookie: "session=alice-session-token" }, secondary: { cookie: "session=bob-session-token" } },
    null,
  );
  const durationMs = Date.now() - started;

  // The worker's own confidence gate (worker.ts, AI_CONFIDENCE_GATE).
  const forAi = result.vulnerabilities.filter((v) => (v.confidence ?? 100) >= 65);
  const ai = await callDeepSeek(TARGET, forAi, result.technologies, "deep");
  // The page hides the AI section when this is null, rather than showing a
  // report that looks complete without it. Refuse unless that was intended.
  if (!ai && !process.argv.includes("--allow-no-ai")) {
    throw new Error("AI analysis failed (is DEEPSEEK_API_KEY set?). Pass --allow-no-ai to write the scanner output alone.");
  }

  const riskScore = computeRiskScore(result.vulnerabilities);
  const sample = {
    capturedAt: new Date().toISOString(),
    target: TARGET,
    tier: "deep",
    durationMs,
    pagesScanned: result.pagesScanned.length,
    technologies: result.technologies,
    riskScore,
    grade: computeGrade(riskScore),
    findings: result.vulnerabilities.map((v) => ({
      name: v.name,
      severity: v.severity,
      category: v.category,
      description: v.description,
      evidence: v.evidence ?? null,
      solution: v.solution,
      cweId: v.cweId ?? null,
      controls: controlsForFinding(v),
    })),
    compliance: summariseCompliance(result.vulnerabilities),
    complianceDisclaimer: COMPLIANCE_DISCLAIMER,
    ai,
  };
  writeFileSync(out, JSON.stringify(sample, null, 2) + "\n");
  console.log(`Wrote ${out}: ${sample.findings.length} findings, grade ${sample.grade}, ${Math.round(durationMs / 1000)} s`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => process.exit());
