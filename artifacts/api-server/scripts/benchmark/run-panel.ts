/**
 * Run the multi-model adjudication panel over OpenRouter.
 *
 * Each judge on panel-models.json gets judge-packet.json and the standing
 * prompt from ADJUDICATOR-PROMPT.md, alone and blind (round 0). Then, for the
 * decisions the panel split on, every judge sees the others' votes and
 * reasoning under anonymous labels and argues its position (discussion rounds).
 * score-panel.ts reports the result. See panel-core.ts for why it works this way.
 *
 * USAGE
 *   # Check every model id against OpenRouter and estimate the cost. No key, no spend.
 *   npx tsx artifacts/api-server/scripts/benchmark/run-panel.ts --dry-run
 *
 *   OPENROUTER_API_KEY=... npx tsx artifacts/api-server/scripts/benchmark/run-panel.ts \
 *     [--out benchmark-out] [--rounds 2] [--concurrency 4] [--seed 20261021] \
 *     [--models artifacts/api-server/scripts/benchmark/panel-models.json]
 *
 * Writes benchmark-out/panel/: key.json (which judge is which model: never shown
 * to a judge), round-0/, discussion-N/, final/, raw/ and transcript.json. A rerun
 * reuses every saved verdict, so an interrupted run resumes without paying twice.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { extractStandingPrompt, mulberry32, round0Messages, shuffle, type Packet } from "./panel-core";
import { runPanel, type Complete, type Judge, type Store } from "./panel-run";

const HERE = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const flag = (name: string, fallback: string): string => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1]! : fallback;
};
const OUT_DIR = resolve(flag("out", "benchmark-out"));
const PANEL_DIR = join(OUT_DIR, "panel");
const MODELS_PATH = resolve(flag("models", join(HERE, "panel-models.json")));
const ROUNDS = parseInt(flag("rounds", "2"), 10);
const CONCURRENCY = parseInt(flag("concurrency", "4"), 10);
const SEED = parseInt(flag("seed", "20261021"), 10);
const DRY_RUN = argv.includes("--dry-run");
const OPENROUTER = "https://openrouter.ai/api/v1";
const CALL_TIMEOUT_MS = 10 * 60_000; // a reasoning model on 74 faults can take minutes

const packetPath = join(OUT_DIR, "judge-packet.json");
if (!existsSync(packetPath)) {
  console.error(`Missing ${packetPath}. Run the scanners (run-benchmark.ts) and build-judge-packet.ts first.`);
  process.exit(2);
}
const packet = JSON.parse(readFileSync(packetPath, "utf8")) as Packet;
const standingPrompt = extractStandingPrompt(readFileSync(join(HERE, "ADJUDICATOR-PROMPT.md"), "utf8"));
const models = (JSON.parse(readFileSync(MODELS_PATH, "utf8")) as { models: Array<{ id: string; vendor: string }> }).models;
if (models.length < 3) {
  console.error(`${MODELS_PATH} lists ${models.length} model(s); a panel needs at least 3.`);
  process.exit(2);
}

// Judges get labels in a seeded random order, so "Judge 1" says nothing about the
// vendor, and the same seed gives the same seating on a rerun.
const seating = shuffle(models, mulberry32(SEED));
const judges: Judge[] = seating.map((m, i) => ({ label: `Judge-${i + 1}`, model: m.id }));

interface ModelInfo {
  id: string;
  pricing?: { prompt?: string; completion?: string };
  supported_parameters?: string[];
}

async function dryRun(): Promise<void> {
  const res = await fetch(`${OPENROUTER}/models`, { signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`OpenRouter model list: HTTP ${res.status}`);
  const live = new Map(((await res.json()) as { data: ModelInfo[] }).data.map((m) => [m.id, m]));

  const messages = round0Messages(standingPrompt, packet);
  // About four characters a token for English and JSON. An estimate, labelled as one.
  const promptTokens = Math.ceil(messages.reduce((s, m) => s + m.content.length, 0) / 4);
  const outputTokens = packet.faults.length * 90;
  let total = 0;
  let problems = 0;
  console.log(`Panel of ${judges.length}, ${packet.faults.length} faults, round-0 prompt about ${promptTokens.toLocaleString()} tokens each\n`);
  for (const j of judges) {
    const info = live.get(j.model);
    if (!info) {
      problems++;
      console.log(`  ${j.label.padEnd(9)} ${j.model.padEnd(36)} NOT FOUND on OpenRouter`);
      continue;
    }
    const pin = Number(info.pricing?.prompt ?? 0);
    const pout = Number(info.pricing?.completion ?? 0);
    const est = promptTokens * pin + outputTokens * pout;
    total += est;
    const json = (info.supported_parameters ?? []).includes("response_format");
    if (!json) problems++;
    console.log(
      `  ${j.label.padEnd(9)} ${j.model.padEnd(36)} round 0 ~$${est.toFixed(3)}${json ? "" : "   no JSON mode: replies may need the retry"}`,
    );
  }
  // Discussion rounds resend the packet plus the disputed decisions, to every judge, per round.
  const withDiscussion = total * (1 + ROUNDS * 1.3);
  console.log(`\n  estimated round 0:            ~$${total.toFixed(2)}`);
  console.log(`  estimated with ${ROUNDS} discussion round(s): ~$${withDiscussion.toFixed(2)}  (depends on how many decisions are disputed)`);
  if (problems > 0) console.log(`\n  ${problems} problem(s) above. Fix panel-models.json before a real run.`);
  mkdirSync(join(PANEL_DIR, "dry-run"), { recursive: true });
  writeFileSync(join(PANEL_DIR, "dry-run", "round-0-messages.json"), JSON.stringify(messages, null, 1), "utf8");
  console.log(`\n  The exact round-0 prompt every judge receives: ${join(PANEL_DIR, "dry-run", "round-0-messages.json")}`);
}

function openRouter(apiKey: string): Complete {
  return async (model, messages) => {
    let lastError = "";
    for (let attempt = 1; attempt <= 3; attempt++) {
      const res = await fetch(`${OPENROUTER}/chat/completions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          "X-Title": "SecScan benchmark panel",
        },
        body: JSON.stringify({
          model,
          messages,
          temperature: 0,
          // Credit is reserved for the output ceiling up front, so an unbounded ceiling
          // makes the provider refuse the call (HTTP 402) even when the balance is ample.
          // 74 faults x 3 tools of compact JSON fits well inside this.
          max_tokens: 12000,
          response_format: { type: "json_object" },
          usage: { include: true },
        }),
        signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
      });
      if (res.status === 429 || res.status >= 500) {
        lastError = `HTTP ${res.status}`;
        await new Promise((r) => setTimeout(r, attempt * 15_000));
        continue;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
      const body = (await res.json()) as {
        choices?: Array<{ message?: { content?: string | null } }>;
        usage?: { prompt_tokens?: number; completion_tokens?: number; cost?: number };
        error?: { message?: string };
      };
      if (body.error) throw new Error(body.error.message ?? "provider error");
      const text = body.choices?.[0]?.message?.content ?? "";
      if (!text.trim()) throw new Error("empty reply");
      return {
        text,
        usage: {
          promptTokens: body.usage?.prompt_tokens ?? 0,
          completionTokens: body.usage?.completion_tokens ?? 0,
          costUsd: body.usage?.cost ?? 0,
        },
      };
    }
    throw new Error(`gave up after 3 attempts (${lastError})`);
  };
}

const fileStore: Store = {
  read(path) {
    const p = join(PANEL_DIR, path);
    return existsSync(p) ? readFileSync(p, "utf8") : null;
  },
  write(path, data) {
    const p = join(PANEL_DIR, path);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, data, "utf8");
  },
};

async function main(): Promise<void> {
  if (DRY_RUN) return dryRun();

  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) {
    console.error("Set OPENROUTER_API_KEY. Run with --dry-run first to check the models and the cost.");
    process.exit(2);
  }
  mkdirSync(PANEL_DIR, { recursive: true });
  // Written before any call, so a crashed run can still be unblinded.
  writeFileSync(join(PANEL_DIR, "key.json"), JSON.stringify(Object.fromEntries(judges.map((j) => [j.label, j.model])), null, 1), "utf8");

  console.log(`Panel of ${judges.length}, ${packet.faults.length} faults, up to ${ROUNDS} discussion round(s)`);
  const result = await runPanel({
    packet,
    standingPrompt,
    judges,
    rounds: ROUNDS,
    complete: openRouter(apiKey),
    store: fileStore,
    concurrency: CONCURRENCY,
    log: (line) => console.log(line),
  });
  const cost = Object.values(result.usage).reduce((s, u) => s + u.costUsd, 0);
  console.log(`\nDone: ${result.judges.length} judges seated, ${result.failed.length} failure(s), cost $${cost.toFixed(2)}`);
  console.log("Next: npx tsx artifacts/api-server/scripts/benchmark/score-panel.ts");
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
