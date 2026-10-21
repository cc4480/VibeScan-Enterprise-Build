/**
 * Score a multi-model panel run (run-panel.ts), then unblind.
 *
 * Reports, in order of how much each should be trusted:
 *
 *   1. Round-0 agreement: unanimity and Fleiss' kappa across the blind,
 *      independent verdicts. This is the measurement. If it is low, the
 *      benchmark is measuring the judges, not the scanners.
 *   2. The detection rate per tool, from the round-0 majority and from the
 *      final majority after discussion. The gap is the panel's own margin.
 *   3. The discussion, the way a human panel's minutes would read: each judge's
 *      first vote against its last, who moved toward the majority, who held
 *      out, whose argument other judges named as the one that changed their
 *      mind, and the decisions where the panel as a whole changed its answer.
 *      Agreement after discussion is reported but is high by construction.
 *   4. A human check, if one has been done: a blind random sample graded by a
 *      person, against which every judge and both majorities are scored. Without
 *      it, nothing here says the judges are right, only that they agree.
 *
 * USAGE
 *   npx tsx artifacts/api-server/scripts/benchmark/score-panel.ts \
 *     [--out benchmark-out] [--sample 40] [--seed 20261021]
 *
 * Expects benchmark-out/judge-key.json (build-judge-packet.ts) and
 * benchmark-out/panel/{transcript.json,key.json} (run-panel.ts). Writes
 * panel/report.json, and panel/human-check.json the first time it runs.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  cellKey,
  fleissKappa,
  majorityYes,
  mulberry32,
  shuffle,
  TOOLS,
  VERDICTS,
  verdictCounts,
  type Cell,
  type Packet,
  type Row,
  type Verdict,
} from "./panel-core";
import type { PanelResult } from "./panel-run";

const argv = process.argv.slice(2);
const flag = (name: string, fallback: string): string => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1]! : fallback;
};
const OUT_DIR = resolve(flag("out", "benchmark-out"));
const PANEL_DIR = join(OUT_DIR, "panel");
const SAMPLE = parseInt(flag("sample", "40"), 10);
const SEED = parseInt(flag("seed", "20261021"), 10);

function readJson<T>(path: string, hint: string): T {
  if (!existsSync(path)) {
    console.error(`Missing ${path}. ${hint}`);
    process.exit(2);
  }
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

const packet = readJson<Packet>(join(OUT_DIR, "judge-packet.json"), "Run build-judge-packet.ts first.");
const toolKey = readJson<Record<string, string>>(join(OUT_DIR, "judge-key.json"), "Run build-judge-packet.ts first.");
const run = readJson<PanelResult>(join(PANEL_DIR, "transcript.json"), "Run run-panel.ts first.");
const judgeKey = readJson<Record<string, string>>(join(PANEL_DIR, "key.json"), "Run run-panel.ts first.");

const REAL_LABEL: Record<string, string> = { secscan: "SecScan", zap: "OWASP ZAP", nuclei: "Nuclei" };
const letterToReal: Record<string, string> = {};
for (const [real, letter] of Object.entries(toolKey)) letterToReal[letter] = REAL_LABEL[real] ?? real;

const faultIds = packet.faults.map((f) => f.id);
const faultLabel = new Map(packet.faults.map((f) => [f.id, f.label]));
const labels = run.judges.map((j) => j.label);
const asMaps = (byJudge: Record<string, Record<string, Row>>): Array<Map<string, Row>> =>
  labels.map((l) => new Map(Object.entries(byJudge[l]!)));
const round0 = asMaps(run.round0);
const final = asMaps(run.final);
const totalCells = faultIds.length * TOOLS.length;

const pct = (n: number, d: number): string => (d === 0 ? "  n/a" : `${((100 * n) / d).toFixed(1).padStart(5)}%`);
const rule = (title: string): void => {
  console.log("=".repeat(78));
  console.log(`  ${title}`);
  console.log("=".repeat(78));
};

// Landis & Koch's bands: the usual reading of a kappa, quoted so a reader can check it.
const kappaBand = (k: number): string =>
  Number.isNaN(k) ? "undefined" : k < 0 ? "worse than chance" : k <= 0.2 ? "slight" : k <= 0.4 ? "fair" : k <= 0.6 ? "moderate" : k <= 0.8 ? "substantial" : "almost perfect";

function votesFor(maps: Array<Map<string, Row>>, c: Cell): Verdict[] {
  return maps.map((m) => m.get(c.id)![c.tool]);
}

/** The most common verdict, or null on a tie for first place. */
function plurality(votes: Verdict[]): Verdict | null {
  const counts = VERDICTS.map((v) => ({ v, n: votes.filter((x) => x === v).length })).sort((a, b) => b.n - a.n);
  return counts[0]!.n === counts[1]!.n ? null : counts[0]!.v;
}

function unanimousShare(maps: Array<Map<string, Row>>): number {
  let n = 0;
  for (const id of faultIds) for (const tool of TOOLS) if (new Set(votesFor(maps, { id, tool })).size === 1) n++;
  return n;
}

// ── 1. Panel and blind agreement ──────────────────────────────────────────────
rule(`PANEL  (${labels.length} judges)`);
for (const j of run.judges) console.log(`  ${j.label.padEnd(9)} ${j.model}`);
if (run.failed.length > 0) {
  console.log();
  for (const f of run.failed) console.log(`  ! ${f.label} (${f.model}) failed in ${f.phase}: ${f.error}`);
}
const cost = Object.values(run.usage).reduce((s, u) => s + u.costUsd, 0);
console.log(`\n  cost reported by the provider: $${cost.toFixed(2)}`);
console.log();

const k0 = fleissKappa(verdictCounts(round0, faultIds));
const kF = fleissKappa(verdictCounts(final, faultIds));
const u0 = unanimousShare(round0);
const uF = unanimousShare(final);

rule("AGREEMENT  (round 0 is the blind, independent measurement)");
console.log(`  decisions:                ${totalCells}  (${faultIds.length} faults x ${TOOLS.length} tools)`);
console.log(`  round 0  unanimous:       ${String(u0).padStart(4)}  ${pct(u0, totalCells)}   Fleiss kappa ${k0.toFixed(3)} (${kappaBand(k0)})`);
console.log(`  final    unanimous:       ${String(uF).padStart(4)}  ${pct(uF, totalCells)}   Fleiss kappa ${kF.toFixed(3)} (${kappaBand(kF)})`);
console.log("  (final agreement rises by design: judges saw each other's votes. Quote round 0.)");
if (k0 < 0.6) {
  console.log("\n  ! Round-0 kappa is below 0.6. Do not publish a detection rate from this run until");
  console.log("    the disputed decisions below are understood.");
}
console.log();

// ── 2. Detection rates ────────────────────────────────────────────────────────
rule(`DETECTION RATE  (${faultIds.length} planted faults; "yes" needs more than half the panel)`);
const scores = TOOLS.map((t) => {
  const count = (maps: Array<Map<string, Row>>, mode: "majority" | "unanimous"): number =>
    faultIds.filter((id) => {
      const votes = votesFor(maps, { id, tool: t });
      return mode === "majority" ? majorityYes(votes) : votes.every((v) => v === "yes");
    }).length;
  return {
    tool: letterToReal[t] ?? `Tool ${t}`,
    round0Majority: count(round0, "majority"),
    round0Unanimous: count(round0, "unanimous"),
    finalMajority: count(final, "majority"),
    finalUnanimous: count(final, "unanimous"),
  };
}).sort((a, b) => b.round0Majority - a.round0Majority);
console.log(`  ${"".padEnd(12)} ${"round 0 majority".padEnd(20)} ${"unanimous".padEnd(14)} ${"after discussion".padEnd(18)}`);
for (const s of scores) {
  const n = faultIds.length;
  console.log(
    `  ${s.tool.padEnd(12)} ${`${s.round0Majority}/${n} ${pct(s.round0Majority, n)}`.padEnd(20)} ` +
      `${`${s.round0Unanimous}/${n}`.padEnd(14)} ${s.finalMajority}/${n} ${pct(s.finalMajority, n)}`,
  );
}
console.log();

// ── 3. The discussion ─────────────────────────────────────────────────────────
const discussed: Cell[] = run.discussion[0]?.disputed ?? [];
const lastRound = run.discussion.length;
const citedBy = new Map<string, number>(labels.map((l) => [l, 0]));
for (const r of run.discussion) {
  for (const byCell of Object.values(r.positions)) {
    for (const p of Object.values(byCell)) if (p.changed_by) citedBy.set(p.changed_by, (citedBy.get(p.changed_by) ?? 0) + 1);
  }
}

const perJudge = labels.map((label, i) => {
  let agreeOthers = 0;
  let comparable = 0;
  let changed = 0;
  let towardMajority = 0;
  let awayFromMajority = 0;
  let heldOut = 0;
  let carried = 0;
  for (const id of faultIds) {
    for (const tool of TOOLS) {
      const c = { id, tool };
      const mine0 = round0[i]!.get(id)![tool];
      const others0 = plurality(votesFor(round0.filter((_, j) => j !== i), c));
      if (others0) {
        comparable++;
        if (mine0 === others0) agreeOthers++;
      }
      const mineF = final[i]!.get(id)![tool];
      const maj0 = plurality(votesFor(round0, c));
      const majF = plurality(votesFor(final, c));
      if (mine0 !== mineF) {
        changed++;
        if (mineF === majF) towardMajority++;
        else awayFromMajority++;
      }
      if (majF && mineF !== majF) heldOut++;
      // The panel changed its answer, and landed where this judge started.
      if (maj0 !== majF && majF && mine0 === majF && mineF === majF) carried++;
    }
  }
  return {
    label,
    model: judgeKey[label] ?? run.judges[i]!.model,
    agreesWithOthersRound0: comparable ? agreeOthers / comparable : Number.NaN,
    changed,
    towardMajority,
    awayFromMajority,
    heldOut,
    citedAsPersuasive: citedBy.get(label) ?? 0,
    carried,
  };
});

rule(`THE DISCUSSION  (${discussed.length} disputed decisions, ${lastRound} round(s))`);
console.log("  agrees = round-0 vote matched the other judges' most common vote (leave-one-out)");
console.log("  changed = votes changed in discussion; held out = final vote differs from the final majority");
console.log("  cited = times another judge named this one as the argument that changed its vote");
console.log("  carried = decisions where the panel's answer moved to where this judge started\n");
console.log(`  ${"judge".padEnd(9)} ${"model".padEnd(36)} agrees  changed (to/away)  held out  cited  carried`);
for (const j of perJudge) {
  console.log(
    `  ${j.label.padEnd(9)} ${j.model.slice(0, 36).padEnd(36)} ${pct(Math.round(j.agreesWithOthersRound0 * 1000), 1000)}  ` +
      `${String(j.changed).padStart(4)} (${j.towardMajority}/${j.awayFromMajority})`.padEnd(19) +
      `${String(j.heldOut).padStart(8)}  ${String(j.citedAsPersuasive).padStart(5)}  ${String(j.carried).padStart(7)}`,
  );
}
console.log();

const panelChangedMind = faultIds.flatMap((id) =>
  TOOLS.flatMap((tool) => {
    const c = { id, tool };
    const before = plurality(votesFor(round0, c));
    const after = plurality(votesFor(final, c));
    return before !== after ? [{ c, before, after }] : [];
  }),
);
if (panelChangedMind.length > 0) {
  console.log(`  Decisions where the panel changed its answer (${panelChangedMind.length}):`);
  for (const { c, before, after } of panelChangedMind) {
    const name = `${(faultLabel.get(c.id) ?? c.id).slice(0, 38)} / ${letterToReal[c.tool]}`;
    console.log(`    ${name.padEnd(54)} ${String(before ?? "tie")} -> ${String(after ?? "tie")}`);
  }
  console.log();
}

// Closest splits first. A 9-1 split is usually one judge holding out (see "held out"
// above); a 5-5 or 6-4 split is a call the standard does not settle.
const margin = (c: Cell): number => {
  const counts = VERDICTS.map((v) => votesFor(final, c).filter((x) => x === v).length).sort((a, b) => b - a);
  return counts[0]! - counts[1]!;
};
const stillSplit = discussed.filter((c) => new Set(votesFor(final, c)).size > 1).sort((a, b) => margin(a) - margin(b));
if (stillSplit.length > 0) {
  console.log(`  Still split after discussion (${stillSplit.length}), closest first:`);
  for (const c of stillSplit) {
    const votes = votesFor(final, c);
    const tally = VERDICTS.map((v) => `${v} ${votes.filter((x) => x === v).length}`).join(", ");
    console.log(`    ${`${(faultLabel.get(c.id) ?? c.id).slice(0, 38)} / ${letterToReal[c.tool]}`.padEnd(54)} ${tally}`);
  }
  console.log();
}

// ── 4. Human check ────────────────────────────────────────────────────────────
interface HumanItem {
  id: string;
  fault: string;
  tool: string;
  human: Verdict | null;
}
const humanPath = join(PANEL_DIR, "human-check.json");
if (!existsSync(humanPath)) {
  // Half from the disputed decisions, where a referee matters most, half at random.
  const rng = mulberry32(SEED);
  const all = faultIds.flatMap((id) => TOOLS.map((tool) => ({ id, tool })));
  const disputedKeys = new Set(discussed.map(cellKey));
  const fromDisputed = shuffle(discussed, rng).slice(0, Math.floor(SAMPLE / 2));
  const taken = new Set(fromDisputed.map(cellKey));
  const fromRest = shuffle(all.filter((c) => !taken.has(cellKey(c)) && !disputedKeys.has(cellKey(c))), rng).slice(0, SAMPLE - fromDisputed.length);
  const items: HumanItem[] = shuffle([...fromDisputed, ...fromRest], rng).map((c) => ({
    id: c.id,
    fault: faultLabel.get(c.id) ?? c.id,
    tool: `Tool ${c.tool}`,
    human: null,
  }));
  writeFileSync(
    humanPath,
    JSON.stringify(
      {
        instructions:
          'Grade each item as "yes", "no" or "unclear" by the standard in ADJUDICATOR-PROMPT.md, using only the ' +
          "tool's distinct_findings in judge-packet.json. Do not look at any judge's verdicts first. Then rerun score-panel.ts.",
        items,
      },
      null,
      1,
    ),
    "utf8",
  );
  console.log(`  Wrote a blind sample of ${items.length} decisions for a person to grade: ${humanPath}`);
  console.log("  Until that is filled in, this run shows the judges agree, not that they are right.\n");
}

let human: Record<string, unknown> | null = null;
const graded = (JSON.parse(readFileSync(humanPath, "utf8")) as { items: HumanItem[] }).items.filter(
  (it) => it.human && (VERDICTS as string[]).includes(it.human),
);
if (graded.length > 0) {
  rule(`HUMAN CHECK  (${graded.length} decisions graded by a person)`);
  const cellOf = (it: HumanItem): Cell => ({ id: it.id, tool: it.tool.replace("Tool ", "") as Cell["tool"] });
  const accuracy = (pick: (c: Cell) => Verdict | null): number =>
    graded.filter((it) => pick(cellOf(it)) === it.human).length / graded.length;
  const rows = [
    { name: "round-0 majority", acc: accuracy((c) => plurality(votesFor(round0, c))) },
    { name: "final majority", acc: accuracy((c) => plurality(votesFor(final, c))) },
    ...labels.map((l, i) => ({ name: `${l} round 0`, acc: accuracy((c) => round0[i]!.get(c.id)![c.tool]) })),
  ];
  for (const r of rows) console.log(`  ${r.name.padEnd(20)} matches the person on ${pct(Math.round(r.acc * 1000), 1000)}`);
  console.log();
  human = Object.fromEntries(rows.map((r) => [r.name, Math.round(r.acc * 1000) / 1000]));
}

const report = {
  generatedAt: new Date().toISOString(),
  judges: run.judges,
  failed: run.failed,
  totalFaults: faultIds.length,
  agreement: {
    round0: { unanimousPct: Math.round((1000 * u0) / totalCells) / 10, fleissKappa: Math.round(k0 * 1000) / 1000 },
    final: { unanimousPct: Math.round((1000 * uF) / totalCells) / 10, fleissKappa: Math.round(kF * 1000) / 1000 },
  },
  scores,
  discussion: {
    rounds: lastRound,
    disputed: discussed.length,
    stillSplit: stillSplit.length,
    panelChangedAnswer: panelChangedMind.map(({ c, before, after }) => ({ id: c.id, tool: letterToReal[c.tool], before, after })),
    perJudge,
  },
  humanCheck: human,
  costUsd: Math.round(cost * 100) / 100,
};
writeFileSync(join(PANEL_DIR, "report.json"), JSON.stringify(report, null, 1), "utf8");
console.log(`Wrote ${join(PANEL_DIR, "report.json")}`);
