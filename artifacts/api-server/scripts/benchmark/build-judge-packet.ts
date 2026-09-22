/**
 * Build a BLINDED adjudication packet for independent judges.
 *
 * WHY THIS EXISTS AS A SEPARATE STEP FROM run-benchmark.ts
 *
 * run-benchmark.ts's own regex matchers are fast and useful for iterating on
 * ground-truth.ts, but they are not trustworthy enough to publish from. Three
 * successive rounds of "fix a regex, re-score" moved ZAP's number from 59.5%
 * to 47.3% to 31.1% on mapping choices alone, with the raw scan data never
 * changing — a benchmark author scoring their own product's competitors with
 * hand-written patterns is exactly the setup that makes a result impossible
 * to trust, ours included.
 *
 * So the number that gets published comes from semantic judgment instead:
 * three independently-run adjudicators, each shown the SAME packet this
 * script produces, deciding per fault whether each tool's reported findings
 * demonstrate detection. They are blind to which tool is which product — the
 * three tools are shuffled to Tool A / Tool B / Tool C, and the assignment is
 * written to a key file this script also produces, which the scorer reads
 * only after every verdict is in.
 *
 * WHAT BLINDING DOES NOT BUY
 *
 * Three judges from the same model are not three independent experts — they
 * share weights and priors, and can fail identically. Blinding removes
 * motivated reasoning (a judge steering credit toward "our" tool), not
 * correlated error. High agreement between them is evidence the SCORING is
 * stable, not evidence the scoring is CORRECT. Report both.
 *
 * The blinding is also imperfect on its face: the tool with dramatically more
 * raw findings than the other two is a legible hint. That is disclosed, not
 * hidden, in whatever publishes these numbers.
 *
 * USAGE
 *   npx tsx artifacts/api-server/scripts/benchmark/build-judge-packet.ts \
 *     [--out benchmark-out] [--seed 20260922]
 *
 * Then hand judge-packet.json (ONLY that file) to each adjudicator with the
 * standing instructions in ADJUDICATOR-PROMPT.md, collect verdict-1/2/3.json,
 * and run score-consensus.ts.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { GROUND_TRUTH } from "./ground-truth";

const argv = process.argv.slice(2);
const flag = (name: string, fallback: string): string => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1]! : fallback;
};

const OUT_DIR = resolve(flag("out", "benchmark-out"));
const SEED = parseInt(flag("seed", "20260922"), 10);

if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });

// Deterministic PRNG (mulberry32) so a given --seed always produces the same
// A/B/C assignment — reruns of the same seed are reproducible without a key
// file surviving between them, though one is still written for convenience.
function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffle<T>(arr: T[], rng: () => number): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [a[i], a[j]] = [a[j]!, a[i]!];
  }
  return a;
}

function distinct(names: Array<string | undefined | null>): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of names) {
    const n = (raw ?? "").trim();
    if (n && !seen.has(n.toLowerCase())) {
      seen.add(n.toLowerCase());
      out.push(n);
    }
  }
  return out.sort();
}

function loadSecscan(): string[] {
  const p = join(OUT_DIR, "secscan.json");
  if (!existsSync(p)) return [];
  const doc = JSON.parse(readFileSync(p, "utf8")) as {
    results?: Array<{ findings?: Array<{ name?: string }> }>;
  };
  return (doc.results ?? []).flatMap((s) => (s.findings ?? []).map((f) => f.name ?? ""));
}

function loadZap(): string[] {
  const p = join(OUT_DIR, "zap.json");
  if (!existsSync(p)) return [];
  const doc = JSON.parse(readFileSync(p, "utf8")) as {
    site?: Array<{ alerts?: Array<{ alert?: string; name?: string }> }>;
  };
  return (doc.site ?? []).flatMap((s) => (s.alerts ?? []).map((a) => a.alert ?? a.name ?? ""));
}

function loadNuclei(): string[] {
  const p = join(OUT_DIR, "nuclei.jsonl");
  if (!existsSync(p)) return [];
  const out: string[] = [];
  for (const line of readFileSync(p, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line) as { "template-id"?: string; info?: { name?: string } };
      const name = r.info?.name ?? r["template-id"] ?? "";
      const id = r["template-id"] ?? "";
      out.push(id ? `${name} [${id}]` : name);
    } catch {
      /* skip a malformed line rather than fail the whole build */
    }
  }
  return out;
}

const real: Record<"secscan" | "zap" | "nuclei", string[]> = {
  secscan: distinct(loadSecscan()),
  zap: distinct(loadZap()),
  nuclei: distinct(loadNuclei()),
};

for (const [name, findings] of Object.entries(real)) {
  if (findings.length === 0) {
    console.error(
      `No findings loaded for "${name}" — run the scanners first ` +
        `(run-benchmark.ts without --score-only), or check --out points at the right directory.`,
    );
    process.exit(2);
  }
}

const rng = mulberry32(SEED);
const letters = shuffle(["A", "B", "C"], rng);
const assignment: Record<"secscan" | "zap" | "nuclei", string> = {
  secscan: letters[0]!,
  zap: letters[1]!,
  nuclei: letters[2]!,
};

const faults = GROUND_TRUTH.map((item) => ({
  id: item.id,
  label: item.label,
  category: item.category,
  ...(item.needs ? { note: `Reaching this may require: ${item.needs}` } : {}),
}));

const packet = {
  instructions_summary:
    "For each fault, decide which of Tool A / Tool B / Tool C reported findings that demonstrate detection of it. See ADJUDICATOR-PROMPT.md for the full standard.",
  seed: SEED,
  faults,
  tools: {
    "Tool A": { distinct_findings: real[Object.keys(assignment).find((k) => assignment[k as keyof typeof assignment] === "A") as keyof typeof real] },
    "Tool B": { distinct_findings: real[Object.keys(assignment).find((k) => assignment[k as keyof typeof assignment] === "B") as keyof typeof real] },
    "Tool C": { distinct_findings: real[Object.keys(assignment).find((k) => assignment[k as keyof typeof assignment] === "C") as keyof typeof real] },
  },
};

writeFileSync(join(OUT_DIR, "judge-packet.json"), JSON.stringify(packet, null, 1), "utf8");
writeFileSync(join(OUT_DIR, "judge-key.json"), JSON.stringify(assignment, null, 1), "utf8");

console.log(`faults: ${faults.length}`);
for (const [toolName, letter] of Object.entries(assignment)) {
  console.log(`  ${toolName.padEnd(8)} -> Tool ${letter}   (${real[toolName as keyof typeof real].length} distinct findings)`);
}
console.log(`\nWrote ${join(OUT_DIR, "judge-packet.json")}`);
console.log(`Key (do not show to judges): ${join(OUT_DIR, "judge-key.json")}`);
console.log(`\nHand judge-packet.json to three independent adjudicators (see ADJUDICATOR-PROMPT.md),`);
console.log(`collect their output as verdict-1.json, verdict-2.json, verdict-3.json in ${OUT_DIR},`);
console.log(`then run: npx tsx artifacts/api-server/scripts/benchmark/score-consensus.ts`);
