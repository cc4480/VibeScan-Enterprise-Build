import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll } from "vitest";
import http from "node:http";
import { Console } from "node:console";
import { Writable } from "node:stream";
import type { AddressInfo, Socket } from "node:net";

/**
 * The AI call's retry behaviour, against a real local server that plays the provider. LLM_ENDPOINT (the operator setting
 * that points the call at any OpenAI-compatible provider) is aimed at it before the module loads. Each test scripts the
 * provider's answers in order; the last one repeats.
 */

type Step =
  | { status: number; body?: string; headers?: Record<string, string> }
  | { hang: true }
  | { drop: true };

const GOOD = {
  overallRisk: "One issue.",
  topPriorities: [],
  quickWins: [],
  complianceNotes: null,
  agentFixPrompt: "Fix it.",
};
const ok = (): Step => ({ status: 200, body: JSON.stringify({ choices: [{ message: { content: JSON.stringify(GOOD) } }] }) });
const status = (code: number, body = "provider said no", headers: Record<string, string> = {}): Step => ({ status: code, body, headers });
const content = (c: string): Step => ({ status: 200, body: JSON.stringify({ choices: [{ message: { content: c } }] }) });

let steps: Step[] = [];
let calls = 0;
const sockets = new Set<Socket>();
const server = http.createServer((req, res) => {
  req.resume();
  req.on("end", () => {
    const step = steps[Math.min(calls, steps.length - 1)]!;
    calls++;
    if ("hang" in step) return; // never answers
    if ("drop" in step) { req.socket.destroy(); return; }
    res.writeHead(step.status, step.headers ?? {});
    res.end(step.body ?? "");
  });
});
server.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
process.env["LLM_ENDPOINT"] = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/chat/completions`;

// Imported only now: the endpoint is read when the module loads.
const { callDeepSeekDetailed, callDeepSeek, classifyAiStatus } = await import("./deepseek");

function script(...s: Step[]) {
  steps = s;
  calls = 0;
}

const sleeps: number[] = [];
const sleep = async (ms: number) => void sleeps.push(ms); // the pause between attempts is a parameter; recording it avoids waiting
const run = (opts = {}) => callDeepSeekDetailed("https://example.test", [], [], "deep", [], { sleep, ...opts });

// The call reports to the operator through console. A real Console writing to a captured stream stands in for the global
// one, which keeps the test output quiet and lets a test read what the operator would have seen.
let realKey: string | undefined;
let realConsole: Console;
let operatorLog = "";
beforeEach(() => {
  realKey = process.env.DEEPSEEK_API_KEY;
  process.env.DEEPSEEK_API_KEY = "test-key";
  sleeps.length = 0;
  operatorLog = "";
  const sink = new Writable({ write(chunk, _enc, cb) { operatorLog += String(chunk); cb(); } });
  realConsole = globalThis.console;
  globalThis.console = new Console({ stdout: sink, stderr: sink });
});
afterEach(() => {
  globalThis.console = realConsole;
  if (realKey === undefined) delete process.env.DEEPSEEK_API_KEY;
  else process.env.DEEPSEEK_API_KEY = realKey;
});
afterAll(async () => {
  for (const s of sockets) s.destroy();
  await new Promise((r) => server.close(r));
  delete process.env["LLM_ENDPOINT"];
});

describe("classifyAiStatus", () => {
  it.each([
    [401, "auth"], [403, "auth"], [402, "billing"], [429, "rate_limit"],
    [500, "provider_error"], [503, "provider_error"], [400, "rejected"], [404, "rejected"], [422, "rejected"],
  ] as const)("%i is %s", (code, kind) => expect(classifyAiStatus(code)).toBe(kind));
});

describe("callDeepSeekDetailed", () => {
  it("returns the analysis on the first try without pausing", async () => {
    script(ok());
    const r = await run();
    expect(r.ok).toBe(true);
    expect(calls).toBe(1);
    expect(sleeps).toEqual([]);
  });

  it("retries a rate limit once and succeeds, honouring a short Retry-After", async () => {
    script(status(429, "slow down", { "retry-after": "2" }), ok());
    const r = await run();
    expect(r.ok).toBe(true);
    expect(calls).toBe(2);
    expect(sleeps).toEqual([2000]);
  });

  it("caps an unreasonable Retry-After", async () => {
    script(status(429, "x", { "retry-after": "600" }), ok());
    await run();
    expect(sleeps).toEqual([5000]);
  });

  it("retries a server error, then reports it as a provider error after two attempts", async () => {
    script(status(503));
    const r = await run();
    expect(r).toEqual({ ok: false, failure: { kind: "provider_error", status: 503, attempts: 2 } });
    expect(calls).toBe(2);
  });

  it.each([
    [401, "auth"], [402, "billing"], [400, "rejected"], [404, "rejected"],
  ] as const)("does not retry a %i (%s): it would fail the same way", async (code, kind) => {
    script(status(code));
    const r = await run();
    expect(r).toEqual({ ok: false, failure: { kind, status: code, attempts: 1 } });
    expect(calls).toBe(1);
    expect(sleeps).toEqual([]);
  });

  it("retries a timeout and reports it as one", async () => {
    // The provider accepts the request and never answers; each attempt gives up after 200 ms.
    script({ hang: true });
    const r = await run({ attemptTimeoutMs: 200 });
    expect(r).toEqual({ ok: false, failure: { kind: "timeout", attempts: 2 } });
    expect(calls).toBe(2);
  });

  it("retries a dropped connection and can recover", async () => {
    script({ drop: true }, ok());
    const r = await run();
    expect(r.ok).toBe(true);
    expect(calls).toBe(2);
  });

  it("treats an empty or non-JSON answer as retryable, then as empty", async () => {
    script(content(""));
    expect(await run()).toEqual({ ok: false, failure: { kind: "empty", status: 200, attempts: 2 } });
    script(content("not json"));
    expect(await run()).toEqual({ ok: false, failure: { kind: "empty", status: 200, attempts: 2 } });
  });

  it("reports a missing key without calling the provider", async () => {
    delete process.env.DEEPSEEK_API_KEY;
    script(ok());
    const r = await run();
    expect(r).toEqual({ ok: false, failure: { kind: "not_configured", attempts: 0 } });
    expect(calls).toBe(0);
  });

  it("never puts the provider's response text into the failure it returns", async () => {
    script(status(400, "model deepseek-flash does not exist; key sk-secret-123"));
    const r = await run();
    expect(JSON.stringify(r)).not.toContain("sk-secret-123");
    expect(JSON.stringify(r)).not.toContain("does not exist");
  });

  it("logs the provider's detail for the operator", async () => {
    script(status(400, "model does not exist"));
    await run();
    expect(operatorLog).toContain("model does not exist");
  });
});

describe("callDeepSeek (the older null-or-result form)", () => {
  it("still returns the analysis, or null on failure", async () => {
    script(ok());
    expect(await callDeepSeek("https://example.test", [], [], "deep")).toMatchObject({ overallRisk: "One issue." });
    script(status(401));
    expect(await callDeepSeek("https://example.test", [], [], "deep")).toBeNull();
  });
});
