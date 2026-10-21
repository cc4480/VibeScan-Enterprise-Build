import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  disputedCells,
  extractStandingPrompt,
  fleissKappa,
  majorityYes,
  parsePositions,
  parseVerdicts,
  type Packet,
  type Row,
} from "./panel-core";
import { runPanel, type Complete } from "./panel-run";

const HERE = dirname(fileURLToPath(import.meta.url));

const row = (id: string, A: Row["A"], B: Row["B"], C: Row["C"]): Row => ({ id, A, B, C, A_match: null, B_match: null, C_match: null, equipped: true });

describe("extractStandingPrompt", () => {
  it("takes the quoted prompt from ADJUDICATOR-PROMPT.md, without quote markers", () => {
    const prompt = extractStandingPrompt(readFileSync(join(HERE, "ADJUDICATOR-PROMPT.md"), "utf8"));
    expect(prompt.startsWith("You are adjudicating a security-scanner detection benchmark")).toBe(true);
    expect(prompt).toContain('Use "unclear" genuinely');
    expect(prompt.split("\n").some((l) => l.startsWith(">"))).toBe(false);
    // The "Known limitation" section after the prompt is for the reader, not the judge.
    expect(prompt).not.toContain("Known limitation");
  });

  it("refuses a file without the section", () => {
    expect(() => extractStandingPrompt("# nothing here")).toThrow(/The prompt/);
  });
});

describe("parseVerdicts", () => {
  const ids = ["f1", "f2"];

  it("accepts a reply wrapped in a code fence", () => {
    const text = '```json\n{"verdicts":[{"id":"f1","A":"yes","B":"no","C":"unclear"},{"id":"f2","A":"no","B":"no","C":"no"}]}\n```';
    const rows = parseVerdicts(text, ids);
    expect(rows.get("f1")?.C).toBe("unclear");
  });

  it("names the faults a reply left out", () => {
    expect(() => parseVerdicts('{"verdicts":[{"id":"f1","A":"yes","B":"no","C":"no"}]}', ids)).toThrow(/missing 1 fault\(s\): f2/);
  });

  it("refuses a verdict outside yes, no and unclear", () => {
    expect(() => parseVerdicts('{"verdicts":[{"id":"f1","A":"maybe","B":"no","C":"no"},{"id":"f2","A":"no","B":"no","C":"no"}]}', ids)).toThrow(/f1/);
  });

  it("ignores a fault id the packet does not contain", () => {
    const text = '{"verdicts":[{"id":"f1","A":"no","B":"no","C":"no"},{"id":"f2","A":"no","B":"no","C":"no"},{"id":"invented","A":"yes","B":"yes","C":"yes"}]}';
    expect([...parseVerdicts(text, ids).keys()]).toEqual(["f1", "f2"]);
  });
});

describe("disputedCells", () => {
  it("lists only decisions on which the judges were not unanimous", () => {
    const j1 = new Map([["f1", row("f1", "yes", "no", "no")]]);
    const j2 = new Map([["f1", row("f1", "yes", "no", "unclear")]]);
    expect(disputedCells(new Map([["J1", j1], ["J2", j2]]), ["f1"])).toEqual([{ id: "f1", tool: "C" }]);
  });
});

describe("fleissKappa", () => {
  it("matches the worked example in Fleiss (1971), as reproduced on Wikipedia: 0.210", () => {
    const counts = [
      [0, 0, 0, 0, 14],
      [0, 2, 6, 4, 2],
      [0, 0, 3, 5, 6],
      [0, 3, 9, 2, 0],
      [2, 2, 8, 1, 1],
      [7, 7, 0, 0, 0],
      [3, 2, 6, 3, 0],
      [2, 5, 3, 2, 2],
      [6, 5, 2, 1, 0],
      [0, 2, 2, 3, 7],
    ];
    expect(fleissKappa(counts)).toBeCloseTo(0.21, 3);
  });

  it("is 1 when every subject is unanimous", () => {
    expect(fleissKappa([[3, 0, 0], [0, 3, 0], [0, 0, 3]])).toBe(1);
  });

  it("refuses subjects rated by different numbers of judges", () => {
    expect(() => fleissKappa([[2, 0, 0], [1, 1, 1]])).toThrow(/same number/);
  });
});

describe("majorityYes", () => {
  it("needs more than half, so a tie is not a yes", () => {
    expect(majorityYes(["yes", "yes", "no", "no"])).toBe(false);
    expect(majorityYes(["yes", "yes", "yes", "no"])).toBe(true);
  });
});

describe("parsePositions", () => {
  const disputed = [{ id: "f1", tool: "C" as const }];

  it("accepts 'Tool C', and drops a changed_by naming no judge on the panel", () => {
    const got = parsePositions(
      '{"positions":[{"id":"f1","tool":"Tool C","vote":"no","argument":"x","changed_by":"Judge-99"}]}',
      disputed,
      ["Judge-1", "Judge-2"],
    );
    expect(got.get("f1|C")).toMatchObject({ vote: "no", changed_by: null });
  });

  it("names a missing position", () => {
    expect(() => parsePositions('{"positions":[]}', disputed, ["Judge-1"])).toThrow(/f1\|C/);
  });
});

describe("runPanel", () => {
  const packet: Packet = {
    faults: [
      { id: "f1", label: "Missing CSP", category: "Headers" },
      { id: "f2", label: "Open redirect", category: "Vulnerabilities" },
    ],
    tools: { "Tool A": { distinct_findings: ["CSP not set"] }, "Tool B": { distinct_findings: [] }, "Tool C": { distinct_findings: [] } },
  };
  const verdicts = (f1A: string): string =>
    JSON.stringify({ verdicts: [{ id: "f1", A: f1A, B: "no", C: "no", reason: f1A === "no" ? "too broad" : null }, { id: "f2", A: "no", B: "no", C: "no" }] });

  function memoryStore(): { files: Map<string, string>; store: { read: (p: string) => string | null; write: (p: string, d: string) => void } } {
    const files = new Map<string, string>();
    return { files, store: { read: (p) => files.get(p) ?? null, write: (p, d) => void files.set(p, d) } };
  }

  /**
   * Four scripted judges on one disputed decision (f1 / Tool A): m1-m3 say yes, m4 says no.
   * m3's first reply is unusable and it recovers on the retry. m5 never answers usefully.
   * In discussion m4 is persuaded by Judge-1.
   */
  function scripted(calls: string[]): Complete {
    const firstTry = new Set<string>();
    return async (model, messages) => {
      const discussion = messages[0]!.content.includes("adjudicators on this panel");
      calls.push(`${model}:${discussion ? "discussion" : "round0"}`);
      if (model === "m5") return { text: "I would rather not." };
      if (!discussion) {
        if (model === "m3" && !firstTry.has(model)) {
          firstTry.add(model);
          return { text: '{"verdicts":[]}', usage: { costUsd: 0.01 } };
        }
        return { text: verdicts(model === "m4" ? "no" : "yes"), usage: { promptTokens: 100, completionTokens: 50, costUsd: 0.02 } };
      }
      const self = /You are (Judge-\d+)/.exec(messages[0]!.content)![1];
      const persuaded = model === "m4";
      return {
        text: JSON.stringify({
          positions: [{ id: "f1", tool: "A", vote: "yes", argument: persuaded ? "Judge-1 is right: the finding names the header." : `${self} holds.`, changed_by: persuaded ? "Judge-1" : null }],
        }),
      };
    };
  }

  const judges = ["m1", "m2", "m3", "m4", "m5"].map((model, i) => ({ label: `Judge-${i + 1}`, model }));

  it("runs a blind round, discusses only the split decision, and records who moved and why", async () => {
    const calls: string[] = [];
    const { files, store } = memoryStore();
    const result = await runPanel({ packet, standingPrompt: "STANDARD", judges, rounds: 2, complete: scripted(calls), store, concurrency: 2 });

    // m5 is dropped, the rest are seated.
    expect(result.judges.map((j) => j.model)).toEqual(["m1", "m2", "m3", "m4"]);
    expect(result.failed).toEqual([expect.objectContaining({ model: "m5", phase: "round-0" })]);

    // Round 0 is kept as it was: m4's blind "no" is not rewritten by the discussion.
    expect(result.round0["Judge-4"]!.f1!.A).toBe("no");
    expect(result.final["Judge-4"]!.f1!.A).toBe("yes");

    // One discussion round settles it, so there is no second round.
    expect(result.discussion).toHaveLength(1);
    expect(result.discussion[0]!.disputed).toEqual([{ id: "f1", tool: "A" }]);
    expect(result.discussion[0]!.positions["Judge-4"]!["f1|A"]!.changed_by).toBe("Judge-1");

    // The judge that came back with an unusable reply was asked once more, and both replies are kept.
    expect(files.has("raw/round-0/Judge-3.txt")).toBe(true);
    expect(files.has("raw/round-0/Judge-3.retry.txt")).toBe(true);
    expect(result.usage["Judge-3"]!.costUsd).toBeCloseTo(0.03);
    expect(files.has("transcript.json")).toBe(true);
  });

  it("shows each judge the others' reasoning, marks its own entry, and never shows a model name", async () => {
    const seen: string[] = [];
    const base = scripted([]);
    const spy: Complete = async (model, messages) => {
      if (messages[0]!.content.includes("adjudicators on this panel")) seen.push(messages[1]!.content);
      return base(model, messages);
    };
    await runPanel({ packet, standingPrompt: "STANDARD", judges, rounds: 1, complete: spy, store: memoryStore().store });
    const forJudge4 = seen.find((s) => s.includes("Judge-4 (you)"))!;
    expect(forJudge4).toContain("too broad");
    expect(forJudge4).not.toMatch(/\bm[1-5]\b/);
  });

  it("reuses saved round-0 verdicts on a rerun instead of paying for them again", async () => {
    const { store } = memoryStore();
    await runPanel({ packet, standingPrompt: "STANDARD", judges, rounds: 1, complete: scripted([]), store });
    const calls: string[] = [];
    await runPanel({ packet, standingPrompt: "STANDARD", judges, rounds: 1, complete: scripted(calls), store });
    // Only m5, which never produced a saved verdict, is asked again in round 0.
    expect(calls.filter((c) => c.endsWith("round0")).every((c) => c.startsWith("m5"))).toBe(true);
  });

  it("refuses to report a panel of fewer than three", async () => {
    const two = judges.slice(3); // m4 answers, m5 does not
    await expect(runPanel({ packet, standingPrompt: "S", judges: two, rounds: 1, complete: scripted([]), store: memoryStore().store })).rejects.toThrow(/at least 3/);
  });
});
