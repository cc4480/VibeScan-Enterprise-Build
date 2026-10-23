/**
 * Pure logic for the multi-model adjudication panel (run-panel.ts, score-panel.ts).
 *
 * WHY A PANEL OF DIFFERENT MODELS
 *
 * ADJUDICATOR-PROMPT.md's three judges were instances of one model: they share
 * weights and priors, so their agreement shows the scoring is stable, not that it
 * is correct. Judges from different vendors make different mistakes, so where
 * they still agree it means more, and where they disagree the decision is
 * genuinely contested.
 *
 * WHY TWO PHASES
 *
 * Round 0 is blind and independent, exactly as ADJUDICATOR-PROMPT.md requires.
 * That is the measurement: it is the only phase whose agreement is evidence of
 * anything. The discussion rounds that follow work like a human panel: every
 * judge sees the others' votes and reasons on the decisions the panel split
 * on, under anonymous labels, and may hold or change its vote. Discussion makes
 * agreement go up by construction, so the scorer reports round-0 agreement as
 * the headline and the discussion as what it is: who moved, who held out, and
 * whose argument carried.
 *
 * None of this makes the result independently verified. Every judge is still a
 * model, and the fixture is still SecScan's own checklist (see README.md).
 */

export type Verdict = "yes" | "no" | "unclear";
export const VERDICTS: readonly Verdict[] = ["yes", "no", "unclear"];
export const TOOLS = ["A", "B", "C"] as const;
export type ToolLetter = (typeof TOOLS)[number];

export interface Fault {
  id: string;
  label: string;
  category: string;
  note?: string;
}

export interface Packet {
  faults: Fault[];
  tools: Record<string, { distinct_findings: string[] }>;
  [key: string]: unknown;
}

export interface Row {
  id: string;
  A: Verdict;
  B: Verdict;
  C: Verdict;
  A_match?: string | null;
  B_match?: string | null;
  C_match?: string | null;
  equipped?: boolean;
  reason?: string | null;
}

/** One judge's stance on one disputed decision during discussion. */
export interface Position {
  id: string;
  tool: ToolLetter;
  vote: Verdict;
  argument: string;
  /** The judge whose argument changed this judge's vote, if any. */
  changed_by: string | null;
}

export interface ChatMessage {
  role: "system" | "user";
  content: string;
}

export interface Cell {
  id: string;
  tool: ToolLetter;
}

export const cellKey = (c: Cell): string => `${c.id}|${c.tool}`;

/**
 * The standing prompt from ADJUDICATOR-PROMPT.md: the quoted block under
 * "## The prompt", without the "> " quote markers. Reading it from the file
 * keeps one copy of the standard, so a model judge and a human judge are held
 * to the same words.
 */
export function extractStandingPrompt(markdown: string): string {
  const start = markdown.indexOf("## The prompt");
  if (start < 0) throw new Error('ADJUDICATOR-PROMPT.md has no "## The prompt" section');
  const end = markdown.indexOf("\n---", start);
  const block = markdown.slice(start, end < 0 ? undefined : end);
  const lines = block
    .split("\n")
    .slice(1)
    .filter((l) => l.startsWith(">"))
    .map((l) => l.replace(/^> ?/, ""));
  const text = lines.join("\n").trim();
  if (!text) throw new Error("ADJUDICATOR-PROMPT.md's prompt section is empty");
  return text;
}

// The standing prompt is written for an agent that reads and writes files. Over an
// API there are no files, so this says where the packet is and what to send back.
const API_ADAPTER =
  "The packet is given to you in the user message instead of as a file. " +
  "Reply with ONLY the JSON object described above, with no prose and no code fence.";

export function round0Messages(standingPrompt: string, packet: Packet): ChatMessage[] {
  return [
    { role: "system", content: `${standingPrompt}\n\n${API_ADAPTER}` },
    {
      role: "user",
      content:
        `judge-packet.json (${packet.faults.length} faults, every one needs a verdict):\n` +
        JSON.stringify(packet),
    },
  ];
}

/** Strips a code fence a model added despite being told not to, then parses. */
function parseJsonObject(text: string): unknown {
  let s = text.trim();
  const fence = /^```(?:json)?\s*([\s\S]*?)\s*```$/i.exec(s);
  if (fence) s = fence[1]!;
  const first = s.indexOf("{");
  const last = s.lastIndexOf("}");
  if (first < 0 || last < first) throw new Error("reply contains no JSON object");
  return JSON.parse(s.slice(first, last + 1));
}

const isVerdict = (v: unknown): v is Verdict => typeof v === "string" && (VERDICTS as string[]).includes(v);

/**
 * Parses and checks a round-0 reply. Throws with a message a model can act on
 * when the reply is unusable, so the caller can send that message back once.
 */
export function parseVerdicts(text: string, faultIds: string[]): Map<string, Row> {
  const doc = parseJsonObject(text) as { verdicts?: unknown } | unknown[];
  const rows = Array.isArray(doc) ? doc : (doc as { verdicts?: unknown }).verdicts;
  if (!Array.isArray(rows)) throw new Error('reply has no "verdicts" array');

  const wanted = new Set(faultIds);
  const out = new Map<string, Row>();
  for (const raw of rows as Array<Record<string, unknown>>) {
    const id = typeof raw?.id === "string" ? raw.id : "";
    if (!wanted.has(id)) continue; // an invented id is ignored, not trusted
    for (const t of TOOLS) {
      if (!isVerdict(raw[t])) throw new Error(`fault "${id}": ${t} must be "yes", "no" or "unclear"`);
    }
    out.set(id, raw as unknown as Row);
  }
  const missing = faultIds.filter((id) => !out.has(id));
  if (missing.length > 0) {
    throw new Error(`reply is missing ${missing.length} fault(s): ${missing.slice(0, 10).join(", ")}${missing.length > 10 ? ", ..." : ""}`);
  }
  return out;
}

/** Decisions on which the judges did not all give the same verdict. */
export function disputedCells(judges: Map<string, Map<string, Row>>, faultIds: string[]): Cell[] {
  const out: Cell[] = [];
  for (const id of faultIds) {
    for (const tool of TOOLS) {
      const votes = new Set([...judges.values()].map((rows) => rows.get(id)?.[tool]));
      if (votes.size > 1) out.push({ id, tool });
    }
  }
  return out;
}

const PANEL_RULES = (label: string, size: number): string =>
  [
    `You are ${label}, one of ${size} adjudicators on this panel. Every judge first decided alone, blind to the others.`,
    "The panel now discusses only the decisions it split on. For each one you are shown every judge's vote and reasoning,",
    "labelled Judge-1, Judge-2 and so on. Who the other judges are is hidden, as is which tool is which product.",
    "",
    "For every disputed decision listed, state your position:",
    "- Keep your vote if you still think it is right under the standard above. Change it only if an argument convinced you.",
    "- Do not change a vote just to join the majority. A minority view that the standard supports is worth keeping.",
    "- Answer the strongest opposing argument directly, in at most 60 words.",
    "- If another judge's argument changed your vote, name that judge in changed_by; otherwise null.",
    "",
    'Reply with ONLY this JSON object: {"positions":[{"id":"<fault id>","tool":"A"|"B"|"C","vote":"yes"|"no"|"unclear","argument":"<= 60 words","changed_by":"Judge-N"|null}]}',
    "with one entry for every disputed decision, no omissions, no prose and no code fence.",
  ].join("\n");

export interface DiscussionEntry {
  judge: string;
  vote: Verdict;
  match?: string | null;
  reason?: string | null;
}

/**
 * What one judge is shown in a discussion round: the packet again (it needs the
 * findings to argue from), then, for each disputed decision, every judge's latest
 * vote and reasoning. Its own entry is marked so it knows which one it is.
 */
export function discussionMessages(input: {
  standingPrompt: string;
  packet: Packet;
  self: string;
  panelSize: number;
  round: number;
  disputed: Array<Cell & { entries: DiscussionEntry[] }>;
}): ChatMessage[] {
  const faults = new Map(input.packet.faults.map((f) => [f.id, f]));
  const items = input.disputed.map((d) => ({
    id: d.id,
    fault: faults.get(d.id)?.label ?? d.id,
    tool: `Tool ${d.tool}`,
    judges: d.entries.map((e) => ({
      judge: e.judge === input.self ? `${e.judge} (you)` : e.judge,
      vote: e.vote,
      ...(e.match ? { cited_finding: e.match } : {}),
      ...(e.reason ? { reasoning: e.reason } : {}),
    })),
  }));
  return [
    {
      role: "system",
      content: `${input.standingPrompt}\n\n${PANEL_RULES(input.self, input.panelSize)}`,
    },
    {
      role: "user",
      content:
        `judge-packet.json:\n${JSON.stringify(input.packet)}\n\n` +
        `Discussion round ${input.round}. ${items.length} disputed decision(s), with every judge's current position:\n` +
        JSON.stringify(items),
    },
  ];
}

/** Parses and checks a discussion reply: one position per disputed decision. */
export function parsePositions(text: string, disputed: Cell[], judgeLabels: string[]): Map<string, Position> {
  const doc = parseJsonObject(text) as { positions?: unknown };
  if (!Array.isArray(doc.positions)) throw new Error('reply has no "positions" array');
  const wanted = new Set(disputed.map(cellKey));
  const labels = new Set(judgeLabels);
  const out = new Map<string, Position>();
  for (const raw of doc.positions as Array<Record<string, unknown>>) {
    const tool = String(raw?.tool ?? "").replace(/^Tool\s+/i, "") as ToolLetter;
    const key = cellKey({ id: String(raw?.id ?? ""), tool });
    if (!wanted.has(key)) continue;
    if (!isVerdict(raw.vote)) throw new Error(`position ${key}: vote must be "yes", "no" or "unclear"`);
    const changedBy = typeof raw.changed_by === "string" && labels.has(raw.changed_by) ? raw.changed_by : null;
    out.set(key, {
      id: String(raw.id),
      tool,
      vote: raw.vote,
      argument: typeof raw.argument === "string" ? raw.argument.slice(0, 600) : "",
      changed_by: changedBy,
    });
  }
  const missing = disputed.filter((c) => !out.has(cellKey(c)));
  if (missing.length > 0) {
    throw new Error(`reply is missing ${missing.length} position(s): ${missing.slice(0, 10).map(cellKey).join(", ")}`);
  }
  return out;
}

/**
 * Fleiss' kappa for a fixed number of raters per subject. `counts[i][j]` is how
 * many raters put subject i in category j. 1 is perfect agreement, 0 is what
 * chance alone would give, below 0 is worse than chance.
 */
export function fleissKappa(counts: number[][]): number {
  if (counts.length === 0) return Number.NaN;
  const n = counts[0]!.reduce((a, b) => a + b, 0);
  if (n < 2) return Number.NaN;
  if (counts.some((row) => row.reduce((a, b) => a + b, 0) !== n)) {
    throw new Error("every subject needs the same number of ratings");
  }
  const N = counts.length;
  const k = counts[0]!.length;
  const p = Array.from({ length: k }, (_, j) => counts.reduce((s, row) => s + row[j]!, 0) / (N * n));
  const P = counts.map((row) => (row.reduce((s, c) => s + c * c, 0) - n) / (n * (n - 1)));
  const Pbar = P.reduce((a, b) => a + b, 0) / N;
  const Pe = p.reduce((s, x) => s + x * x, 0);
  if (Pe === 1) return 1; // every rating in one category: agreement is total, chance is undefined
  return (Pbar - Pe) / (1 - Pe);
}

/** Per-decision category counts across judges, in VERDICTS order, for fleissKappa. */
export function verdictCounts(judges: Array<Map<string, Row>>, faultIds: string[]): number[][] {
  const out: number[][] = [];
  for (const id of faultIds) {
    for (const t of TOOLS) {
      out.push(VERDICTS.map((v) => judges.filter((j) => j.get(id)?.[t] === v).length));
    }
  }
  return out;
}

/** "yes" only when more than half the panel said yes, the same bar as score-consensus.ts's 2/3. */
export const majorityYes = (votes: Verdict[]): boolean => votes.filter((v) => v === "yes").length * 2 > votes.length;

/** Deterministic PRNG, the same one build-judge-packet.ts uses, so a seed reproduces a run. */
export function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function shuffle<T>(arr: T[], rng: () => number): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [a[i], a[j]] = [a[j]!, a[i]!];
  }
  return a;
}
