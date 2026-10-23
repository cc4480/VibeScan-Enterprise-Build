/**
 * Runs the adjudication panel: one blind round, then discussion rounds on the
 * decisions the panel split on. See panel-core.ts for why it is built this way.
 *
 * The model call and the file store are passed in, so a test can drive a whole
 * panel with scripted judges and no network. run-panel.ts wires in OpenRouter
 * and the filesystem.
 *
 * Every reply is stored raw, before parsing, in the same spirit as the scanners'
 * raw output in benchmark-out/: anyone disputing a verdict can read exactly what
 * the judge said.
 */
import {
  cellKey,
  disputedCells,
  discussionMessages,
  parsePositions,
  parseVerdicts,
  round0Messages,
  TOOLS,
  type Cell,
  type ChatMessage,
  type DiscussionEntry,
  type Packet,
  type Position,
  type Row,
} from "./panel-core";

export interface Judge {
  label: string;
  model: string;
}

export interface Usage {
  promptTokens: number;
  completionTokens: number;
  costUsd: number;
}

export type Complete = (
  model: string,
  messages: Array<ChatMessage | { role: "assistant"; content: string }>,
) => Promise<{ text: string; usage?: Partial<Usage> }>;

export interface Store {
  read(path: string): string | null;
  write(path: string, data: string): void;
}

export interface DiscussionRound {
  round: number;
  disputed: Cell[];
  /** judge label -> cell key -> position */
  positions: Record<string, Record<string, Position>>;
}

export interface PanelResult {
  judges: Judge[];
  failed: Array<{ label: string; model: string; phase: string; error: string }>;
  round0: Record<string, Record<string, Row>>;
  discussion: DiscussionRound[];
  final: Record<string, Record<string, Row>>;
  usage: Record<string, Usage>;
}

async function pool<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const item = items[next++]!;
      await fn(item);
    }
  });
  await Promise.all(workers);
}

const errMsg = (e: unknown): string => (e instanceof Error ? e.message : String(e));

export async function runPanel(opts: {
  packet: Packet;
  standingPrompt: string;
  judges: Judge[];
  rounds: number;
  complete: Complete;
  store: Store;
  concurrency?: number;
  log?: (line: string) => void;
}): Promise<PanelResult> {
  const { packet, standingPrompt, complete, store } = opts;
  const log = opts.log ?? (() => undefined);
  const concurrency = opts.concurrency ?? 4;
  const faultIds = packet.faults.map((f) => f.id);
  const usage: Record<string, Usage> = {};
  const failed: PanelResult["failed"] = [];

  const addUsage = (label: string, u?: Partial<Usage>): void => {
    const acc = (usage[label] ??= { promptTokens: 0, completionTokens: 0, costUsd: 0 });
    acc.promptTokens += u?.promptTokens ?? 0;
    acc.completionTokens += u?.completionTokens ?? 0;
    acc.costUsd += u?.costUsd ?? 0;
  };

  /**
   * One call, checked by `parse`. An unusable reply gets one more chance, with the
   * reason sent back, which is what a human panel chair would do with an
   * incomplete form. A second unusable reply drops the judge from that phase.
   */
  async function ask<T>(judge: Judge, phase: string, messages: ChatMessage[], parse: (text: string) => T): Promise<T> {
    const first = await complete(judge.model, messages);
    addUsage(judge.label, first.usage);
    store.write(`raw/${phase}/${judge.label}.txt`, first.text);
    try {
      return parse(first.text);
    } catch (e) {
      log(`  ${judge.label} (${judge.model}) ${phase}: unusable reply (${errMsg(e)}), asking once more`);
      const retry = await complete(judge.model, [
        ...messages,
        { role: "assistant", content: first.text },
        { role: "user", content: `That reply could not be used: ${errMsg(e)}. Send the complete JSON object again, covering every item.` },
      ]);
      addUsage(judge.label, retry.usage);
      store.write(`raw/${phase}/${judge.label}.retry.txt`, retry.text);
      return parse(retry.text);
    }
  }

  // ── Round 0: blind and independent ──────────────────────────────────────────
  const round0 = new Map<string, Map<string, Row>>();
  await pool(opts.judges, concurrency, async (judge) => {
    const saved = store.read(`round-0/${judge.label}.json`);
    if (saved) {
      try {
        round0.set(judge.label, parseVerdicts(saved, faultIds));
        log(`  ${judge.label} round 0: reused saved verdicts`);
        return;
      } catch {
        /* a damaged saved file is redone, not trusted */
      }
    }
    try {
      const rows = await ask(judge, "round-0", round0Messages(standingPrompt, packet), (t) => parseVerdicts(t, faultIds));
      store.write(`round-0/${judge.label}.json`, JSON.stringify({ verdicts: [...rows.values()] }, null, 1));
      round0.set(judge.label, rows);
      log(`  ${judge.label} round 0: ${rows.size} verdicts`);
    } catch (e) {
      failed.push({ label: judge.label, model: judge.model, phase: "round-0", error: errMsg(e) });
      log(`  ${judge.label} (${judge.model}) round 0 FAILED: ${errMsg(e)}`);
    }
  });

  // Keep the panel in label order so every later step is deterministic.
  const seated = opts.judges.filter((j) => round0.has(j.label));
  if (seated.length < 3) {
    throw new Error(`only ${seated.length} judge(s) returned usable verdicts; a panel needs at least 3`);
  }
  const ordered = new Map(seated.map((j) => [j.label, round0.get(j.label)!]));

  // ── Discussion rounds: only on what the panel split on ──────────────────────
  // Each judge's current vote and reasoning per disputed decision, starting from round 0.
  const current = new Map<string, Map<string, DiscussionEntry>>();
  let disputed = disputedCells(ordered, faultIds);
  for (const cell of disputed) {
    const k = cellKey(cell);
    const m = new Map<string, DiscussionEntry>();
    for (const [label, rows] of ordered) {
      const row = rows.get(cell.id)!;
      m.set(label, {
        judge: label,
        vote: row[cell.tool],
        match: row[`${cell.tool}_match` as "A_match"] ?? null,
        reason: row.reason ?? null,
      });
    }
    current.set(k, m);
  }
  log(`  round 0: ${disputed.length} of ${faultIds.length * TOOLS.length} decisions disputed`);

  const discussion: DiscussionRound[] = [];
  const labels = seated.map((j) => j.label);
  for (let round = 1; round <= opts.rounds && disputed.length > 0; round++) {
    const roundCells = disputed;
    const positions: DiscussionRound["positions"] = {};
    await pool(seated, concurrency, async (judge) => {
      const phase = `discussion-${round}`;
      const saved = store.read(`${phase}/${judge.label}.json`);
      if (saved) {
        try {
          positions[judge.label] = Object.fromEntries(parsePositions(saved, roundCells, labels));
          return;
        } catch {
          /* redo */
        }
      }
      const messages = discussionMessages({
        standingPrompt,
        packet,
        self: judge.label,
        panelSize: seated.length,
        round,
        disputed: roundCells.map((c) => ({ ...c, entries: labels.map((l) => current.get(cellKey(c))!.get(l)!) })),
      });
      try {
        const got = await ask(judge, phase, messages, (t) => parsePositions(t, roundCells, labels));
        store.write(`${phase}/${judge.label}.json`, JSON.stringify({ positions: [...got.values()] }, null, 1));
        positions[judge.label] = Object.fromEntries(got);
      } catch (e) {
        // A judge that cannot answer keeps its last vote: silence is not a change of mind.
        failed.push({ label: judge.label, model: judge.model, phase, error: errMsg(e) });
        log(`  ${judge.label} (${judge.model}) ${phase} FAILED, keeping its previous votes: ${errMsg(e)}`);
      }
    });

    for (const cell of roundCells) {
      const k = cellKey(cell);
      for (const label of labels) {
        const p = positions[label]?.[k];
        if (p) current.get(k)!.set(label, { judge: label, vote: p.vote, reason: p.argument });
      }
    }
    discussion.push({ round, disputed: roundCells, positions });
    disputed = roundCells.filter((c) => new Set(labels.map((l) => current.get(cellKey(c))!.get(l)!.vote)).size > 1);
    log(`  discussion ${round}: ${roundCells.length - disputed.length} of ${roundCells.length} settled, ${disputed.length} still split`);
  }

  // ── Final verdicts: round 0, with each discussed decision's last vote ───────
  const final: PanelResult["final"] = {};
  for (const [label, rows] of ordered) {
    const out: Record<string, Row> = {};
    for (const [id, row] of rows) {
      const copy: Row = { ...row };
      for (const t of TOOLS) {
        const entry = current.get(cellKey({ id, tool: t }))?.get(label);
        if (entry) copy[t] = entry.vote;
      }
      out[id] = copy;
    }
    final[label] = out;
    store.write(`final/${label}.json`, JSON.stringify({ verdicts: Object.values(out) }, null, 1));
  }

  const result: PanelResult = {
    judges: seated,
    failed,
    round0: Object.fromEntries([...ordered].map(([l, rows]) => [l, Object.fromEntries(rows)])),
    discussion,
    final,
    usage,
  };
  store.write("transcript.json", JSON.stringify(result, null, 1));
  return result;
}
