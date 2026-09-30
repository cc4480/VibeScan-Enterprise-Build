/**
 * Cross-scanner benchmark against artifacts/vuln-fixture.
 *
 * Runs OWASP ZAP, Nuclei and SecScan against the same target, normalises what
 * each one reported, and scores all three against the same ground truth in
 * ground-truth.ts. Read that file first: it explains the matching rule and the
 * bias this benchmark cannot remove.
 *
 * USAGE
 *   1. Start the fixture:
 *        pnpm --filter @workspace/vuln-fixture run start
 *   2. Run the benchmark:
 *        npx tsx artifacts/api-server/scripts/benchmark/run-benchmark.ts
 *
 * FLAGS
 *   --tools zap,nuclei,secscan   which to run (default: all three)
 *   --score-only                 skip the scans, score whatever raw output exists
 *   --out <dir>                  where raw output lands (default: ./benchmark-out)
 *   --zap-mode baseline|full     ZAP passive-only or passive+active (default: full)
 *
 * Every tool's raw output is written to --out unchanged, so the scoring can be
 * re-run, disputed, or redone by somebody else with a different mapping.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { GROUND_TRUTH, CATEGORIES, type GroundTruthItem } from "./ground-truth";
import { OUT_DIR, TOOLS, ZAP_MODE, SCORE_ONLY, HOST_TARGET, DOCKER_TARGET, REPO_ROOT } from "./run-benchmark-config";
import { type Normalised, parseZap, parseNuclei, parseSecscan } from "./run-benchmark-parse";

if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

function sh(cmd: string, args: string[], timeoutMs: number): string {
  return execFileSync(cmd, args, {
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function toolVersion(image: string, args: string[]): string {
  try {
    return sh("docker", ["run", "--rm", "--add-host=host.docker.internal:host-gateway", image, ...args], 120_000).trim().split("\n").slice(-3).join(" ");
  } catch {
    return "(version unavailable)";
  }
}

// ── Runners ───────────────────────────────────────────────────────────────────

function runZap(): void {
  const script = ZAP_MODE === "baseline" ? "zap-baseline.py" : "zap-full-scan.py";
  console.log(`[zap] ${script} against ${DOCKER_TARGET} — this takes a while`);
  try {
    // -I: report findings but do not exit non-zero on them. -j: include the
    // AJAX spider, so a JS-rendered route is reachable the way it is for the
    // other two. The report lands in the mounted directory.
    sh("docker", [
      "run", "--rm", "--add-host=host.docker.internal:host-gateway",
      "-v", `${OUT_DIR}:/zap/wrk/:rw`,
      "-t", "ghcr.io/zaproxy/zaproxy:stable",
      script, "-t", DOCKER_TARGET, "-J", "zap.json", "-I", "-j",
    ], 45 * 60_000);
  } catch (err) {
    // zap-*-scan.py exits non-zero when it has findings even with -I in some
    // versions; the report is what matters, not the exit code.
    const e = err as { stdout?: string };
    if (e.stdout) console.log(String(e.stdout).slice(-600));
  }
  if (!existsSync(join(OUT_DIR, "zap.json"))) {
    throw new Error("ZAP produced no report — check that the fixture is reachable at " + DOCKER_TARGET);
  }
}

function runNuclei(): void {
  console.log(`[nuclei] scanning ${DOCKER_TARGET}`);
  const out = sh("docker", [
    "run", "--rm", "--add-host=host.docker.internal:host-gateway", "projectdiscovery/nuclei:latest",
    "-u", DOCKER_TARGET, "-jsonl", "-silent", "-no-color",
    // Everything except the network/ssl families, which do not apply to a
    // plain-HTTP fixture on a loopback port.
    "-severity", "info,low,medium,high,critical",
  ], 30 * 60_000);
  writeFileSync(join(OUT_DIR, "nuclei.jsonl"), out, "utf8");
}

function runSecscan(): void {
  console.log(`[secscan] active scan against ${HOST_TARGET}`);
  const out = sh("npx", [
    "tsx",
    join(REPO_ROOT, "artifacts", "api-server", "scripts", "live-scan.ts"),
    "--active", HOST_TARGET,
    "--json", join(OUT_DIR, "secscan.json"),
  ], 20 * 60_000);
  console.log(out.split("\n").slice(-6).join("\n"));
}

// ── Scoring ───────────────────────────────────────────────────────────────────

type ToolName = "secscan" | "zap" | "nuclei";
const TOOL_LABEL: Record<ToolName, string> = {
  secscan: "SecScan", zap: "OWASP ZAP", nuclei: "Nuclei",
};

interface Hit { item: GroundTruthItem; matchedBy: string | null; }

function score(findings: Normalised[], tool: ToolName): { hits: Hit[]; usedIndexes: Set<number> } {
  const hits: Hit[] = [];
  const used = new Set<number>();
  for (const item of GROUND_TRUTH) {
    const rx = item[tool];
    let matchedBy: string | null = null;
    if (rx) {
      for (let i = 0; i < findings.length; i++) {
        if (!rx.test(findings[i]!.haystack)) continue;
        // EVERY finding that matches this item is "accounted for", not just
        // the first. Marking only the first credited one left the other
        // duplicates in notInGroundTruth, which made a tool look like it had
        // found things we never planted when it had simply reported the same
        // planted fault at five different paths. That inflated the one list
        // whose whole job is to be the honest counterweight to the score.
        used.add(i);
        if (!matchedBy) matchedBy = findings[i]!.name;
      }
    }
    hits.push({ item, matchedBy });
  }
  return { hits, usedIndexes: used };
}

// ── Main ──────────────────────────────────────────────────────────────────────

function reachable(url: string): boolean {
  try {
    sh("curl", ["-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8", url], 15_000);
    return true;
  } catch { return false; }
}

async function main(): Promise<void> {
  if (!SCORE_ONLY) {
    if (!reachable(HOST_TARGET)) {
      console.error(`The fixture is not answering at ${HOST_TARGET}.`);
      console.error(`Start it first:  pnpm --filter @workspace/vuln-fixture run start`);
      process.exit(2);
    }
    if (TOOLS.includes("zap")) runZap();
    if (TOOLS.includes("nuclei")) runNuclei();
    if (TOOLS.includes("secscan")) runSecscan();
  }

  const parsed: Record<ToolName, Normalised[]> = {
    secscan: parseSecscan(),
    zap: parseZap(),
    nuclei: parseNuclei(),
  };

  const report = {
    generatedAt: new Date().toISOString(),
    target: HOST_TARGET,
    zapMode: ZAP_MODE,
    versions: SCORE_ONLY ? {} : {
      zap: TOOLS.includes("zap") ? toolVersion("ghcr.io/zaproxy/zaproxy:stable", ["zap.sh", "-version"]) : "(not run)",
      nuclei: TOOLS.includes("nuclei") ? toolVersion("projectdiscovery/nuclei:latest", ["-version"]) : "(not run)",
    },
    groundTruthCount: GROUND_TRUTH.length,
    tools: {} as Record<string, unknown>,
  };

  console.log("\n" + "=".repeat(74));
  console.log("  DETECTION AGAINST GROUND TRUTH — " + GROUND_TRUTH.length + " planted faults");
  console.log("=".repeat(74) + "\n");

  for (const tool of ["secscan", "zap", "nuclei"] as ToolName[]) {
    const findings = parsed[tool];
    const { hits, usedIndexes } = score(findings, tool);
    const found = hits.filter((h) => h.matchedBy);
    const missed = hits.filter((h) => !h.matchedBy);
    const extra = findings.filter((_, i) => !usedIndexes.has(i));

    const byCategory: Record<string, { found: number; total: number }> = {};
    for (const cat of CATEGORIES) byCategory[cat] = { found: 0, total: 0 };
    for (const h of hits) {
      const c = byCategory[h.item.category]!;
      c.total++;
      if (h.matchedBy) c.found++;
    }

    const pct = ((found.length / GROUND_TRUTH.length) * 100).toFixed(1);
    console.log(`${TOOL_LABEL[tool].padEnd(12)} ${String(found.length).padStart(3)}/${GROUND_TRUTH.length}  (${pct}%)`
      + `   raw findings reported: ${findings.length}`
      + `   not in ground truth: ${extra.length}`);

    report.tools[tool] = {
      label: TOOL_LABEL[tool],
      rawFindingCount: findings.length,
      detected: found.length,
      total: GROUND_TRUTH.length,
      byCategory,
      detectedItems: found.map((h) => ({ id: h.item.id, label: h.item.label, matchedBy: h.matchedBy })),
      missedItems: missed.map((h) => ({
        id: h.item.id, label: h.item.label, category: h.item.category,
        hadMatcher: Boolean(h.item[tool]), needs: h.item.needs ?? null,
      })),
      notInGroundTruth: extra.map((f) => ({ name: f.name, severity: f.severity })),
    };
  }

  console.log("");
  for (const cat of CATEGORIES) {
    const row = (["secscan", "zap", "nuclei"] as ToolName[]).map((t) => {
      const c = (report.tools[t] as { byCategory: Record<string, { found: number; total: number }> })
        .byCategory[cat]!;
      return `${String(c.found).padStart(2)}/${String(c.total).padEnd(2)}`;
    });
    console.log(`  ${cat.padEnd(28)} SecScan ${row[0]}   ZAP ${row[1]}   Nuclei ${row[2]}`);
  }

  const jsonPath = join(OUT_DIR, "benchmark-report.json");
  writeFileSync(jsonPath, JSON.stringify(report, null, 2), "utf8");
  console.log(`\nFull report: ${jsonPath}`);
  console.log(`Raw tool output kept in ${OUT_DIR} so the scoring can be redone or disputed.\n`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});