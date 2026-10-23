/**
 * Combine three blind adjudicators' verdicts into a score, then unblind.
 *
 * Reports three things, in order of how much they should be trusted:
 *
 *   1. Agreement. If three adjudicators looking at identical data disagree on
 *      a large share of their decisions, this benchmark is measuring the
 *      adjudicator rather than the scanners, and no percentage from it is
 *      publishable — regardless of which tool comes out ahead. This is why
 *      it is reported FIRST, before any score.
 *   2. The unanimous score (3/3 credited yes).
 *   3. The majority score (2/3).
 *
 * The gap between 2 and 3 is the benchmark's own margin of error and should
 * be published alongside the headline number, not dropped.
 *
 * USAGE
 *   npx tsx artifacts/api-server/scripts/benchmark/score-consensus.ts \
 *     [--out benchmark-out]
 *
 * Expects, in --out: judge-packet.json, judge-key.json, and
 * verdict-1.json / verdict-2.json / verdict-3.json (from three independent
 * runs of ADJUDICATOR-PROMPT.md against judge-packet.json).
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { GROUND_TRUTH, CATEGORIES } from "./ground-truth";

const argv = process.argv.slice(2);
const flag = (name: string, fallback: string): string => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1]! : fallback;
};
const OUT_DIR = resolve(flag("out", "benchmark-out"));

type Verdict = "yes" | "no" | "unclear";
interface Row {
  id: string;
  A: Verdict; B: Verdict; C: Verdict;
  A_match?: string | null; B_match?: string | null; C_match?: string | null;
  equipped?: boolean;
  reason?: string;
}

function loadVerdicts(n: number): Map<string, Row> {
  const p = join(OUT_DIR, `verdict-${n}.json`);
  if (!existsSync(p)) {
    console.error(`Missing ${p} — judge ${n} has not finished. Run all three before scoring.`);
    process.exit(2);
  }
  const doc = JSON.parse(readFileSync(p, "utf8")) as { verdicts: Row[] } | Row[];
  const rows = Array.isArray(doc) ? doc : doc.verdicts;
  const map = new Map<string, Row>();
  for (const r of rows) map.set(r.id, r);
  const missing = GROUND_TRUTH.filter((f) => !map.has(f.id));
  if (missing.length > 0) {
    console.error(`verdict-${n}.json is missing ${missing.length} fault(s): ${missing.map((f) => f.id).join(", ")}`);
    process.exit(2);
  }
  return map;
}

const verdicts = [loadVerdicts(1), loadVerdicts(2), loadVerdicts(3)];

const keyPath = join(OUT_DIR, "judge-key.json");
if (!existsSync(keyPath)) {
  console.error(`Missing ${keyPath} — run build-judge-packet.ts first.`);
  process.exit(2);
}
const key = JSON.parse(readFileSync(keyPath, "utf8")) as Record<"secscan" | "zap" | "nuclei", string>;
const letterToReal: Record<string, keyof typeof key> = {};
for (const [real, letter] of Object.entries(key)) letterToReal[letter] = real as keyof typeof key;

const REAL_LABEL: Record<string, string> = { secscan: "SecScan", zap: "OWASP ZAP", nuclei: "Nuclei" };
const TOOLS = ["A", "B", "C"] as const;

// ── 1. Agreement ──────────────────────────────────────────────────────────────
let totalCells = 0;
let unanimousCells = 0;
const disagreements: Array<{ id: string; tool: string; values: string[] }> = [];

for (const fault of GROUND_TRUTH) {
  for (const t of TOOLS) {
    totalCells++;
    const values = verdicts.map((v) => v.get(fault.id)?.[t] ?? "missing");
    if (new Set(values).size === 1) unanimousCells++;
    else disagreements.push({ id: fault.id, tool: t, values });
  }
}

console.log("=".repeat(78));
console.log("  JUDGE AGREEMENT  (three independent blind adjudicators)");
console.log("=".repeat(78));
console.log(`  decisions:          ${totalCells}  (${GROUND_TRUTH.length} faults x 3 tools)`);
console.log(`  all three agreed:   ${unanimousCells}  (${((100 * unanimousCells) / totalCells).toFixed(1)}%)`);
console.log(`  judges disagreed:   ${disagreements.length}  (${((100 * disagreements.length) / totalCells).toFixed(1)}%)`);
console.log();

if (unanimousCells / totalCells < 0.85) {
  console.log("  ⚠ Agreement below 85%. These numbers should NOT be published as a");
  console.log("    detection rate without resolving the disagreements first — see below.");
  console.log();
}

// ── 2 & 3. Scores ─────────────────────────────────────────────────────────────
function tally(letter: string, mode: "unanimous" | "majority"): number {
  let n = 0;
  for (const fault of GROUND_TRUTH) {
    const yes = verdicts.filter((v) => v.get(fault.id)?.[letter as "A"] === "yes").length;
    if (mode === "unanimous" && yes === 3) n++;
    else if (mode === "majority" && yes >= 2) n++;
  }
  return n;
}

console.log("=".repeat(78));
console.log(`  DETECTION RATE  (${GROUND_TRUTH.length} planted faults)`);
console.log("=".repeat(78));

const scored = TOOLS.map((letter) => {
  const real = letterToReal[letter]!;
  return {
    label: REAL_LABEL[real]!,
    unanimous: tally(letter, "unanimous"),
    majority: tally(letter, "majority"),
  };
}).sort((a, b) => b.majority - a.majority);

for (const row of scored) {
  const uPct = ((100 * row.unanimous) / GROUND_TRUTH.length).toFixed(1);
  const mPct = ((100 * row.majority) / GROUND_TRUTH.length).toFixed(1);
  console.log(
    `  ${row.label.padEnd(12)} ${String(row.unanimous).padStart(2)}/${GROUND_TRUTH.length} (${uPct.padStart(5)}%)   ` +
      `${String(row.majority).padStart(2)}/${GROUND_TRUTH.length} (${mPct.padStart(5)}%)   spread=${row.majority - row.unanimous}`,
  );
}
console.log();

// ── By category ────────────────────────────────────────────────────────────
console.log("  By category (majority verdict, 2/3)");
for (const cat of CATEGORIES) {
  const ids = GROUND_TRUTH.filter((f) => f.category === cat).map((f) => f.id);
  const parts = TOOLS.map((letter) => {
    const real = letterToReal[letter]!;
    const n = ids.filter(
      (id) => verdicts.filter((v) => v.get(id)?.[letter as "A"] === "yes").length >= 2,
    ).length;
    return `${REAL_LABEL[real]} ${String(n).padStart(2)}/${ids.length}`;
  });
  console.log(`    ${cat.padEnd(28)} ${parts.join("   ")}`);
}
console.log();

// ── Disagreements ─────────────────────────────────────────────────────────
if (disagreements.length > 0) {
  console.log(`  Faults the judges did not fully agree on (${disagreements.length}):`);
  const byFault = new Map<string, typeof disagreements>();
  for (const d of disagreements) {
    if (!byFault.has(d.id)) byFault.set(d.id, []);
    byFault.get(d.id)!.push(d);
  }
  for (const [id, entries] of byFault) {
    const label = GROUND_TRUTH.find((f) => f.id === id)?.label ?? id;
    const parts = entries.map((e) => `${REAL_LABEL[letterToReal[e.tool]!]}=${e.values.join("/")}`);
    console.log(`    ${label.slice(0, 40).padEnd(40)} ${parts.join("; ")}`);
  }
  console.log();
}

const out = {
  generatedAt: new Date().toISOString(),
  totalFaults: GROUND_TRUTH.length,
  agreementPct: Math.round((1000 * unanimousCells) / totalCells) / 10,
  disagreementCount: disagreements.length,
  scores: Object.fromEntries(
    scored.map((r) => [r.label, { unanimous: r.unanimous, majority: r.majority, total: GROUND_TRUTH.length }]),
  ),
};
writeFileSync(join(OUT_DIR, "consensus.json"), JSON.stringify(out, null, 1), "utf8");
console.log(`Wrote ${join(OUT_DIR, "consensus.json")}`);
