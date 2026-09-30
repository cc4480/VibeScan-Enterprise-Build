import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { callDeepSeekDetailed, callDeepSeek, classifyAiStatus } from "./deepseek";

const GOOD = {
  overallRisk: "One issue.",
  topPriorities: [],
  quickWins: [],
  complianceNotes: null,
  agentFixPrompt: "Fix it.",
};
const ok = () => new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify(GOOD) } }] }), { status: 200 });
const status = (code: number, body = "provider said no", headers: Record<string, string> = {}) =>
  new Response(body, { status: code, headers });

let realFetch: typeof fetch;
let realKey: string | undefined;
let calls: number;
const sleeps: number[] = [];
const sleep = async (ms: number) => void sleeps.push(ms);

function script(...steps: Array<() => Response | Promise<Response>>) {
  calls = 0;
  globalThis.fetch = (async () => {
    const step = steps[Math.min(calls, steps.length - 1)]!;
    calls++;
    return step();
  }) as unknown as typeof fetch;
}

const run = (opts = {}) => callDeepSeekDetailed("https://example.test", [], [], "deep", [], { sleep, ...opts });

beforeEach(() => {
  realFetch = globalThis.fetch;
  realKey = process.env.DEEPSEEK_API_KEY;
  process.env.DEEPSEEK_API_KEY = "test-key";
  sleeps.length = 0;
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});
afterEach(() => {
  globalThis.fetch = realFetch;
  if (realKey === undefined) delete process.env.DEEPSEEK_API_KEY;
  else process.env.DEEPSEEK_API_KEY = realKey;
  vi.restoreAllMocks();
});

describe("classifyAiStatus", () => {
  it.each([
    [401, "auth"], [403, "auth"], [402, "billing"], [429, "rate_limit"],
    [500, "provider_error"], [503, "provider_error"], [400, "rejected"], [404, "rejected"], [422, "rejected"],
  ] as const)("%i is %s", (code, kind) => expect(classifyAiStatus(code)).toBe(kind));
});

describe("callDeepSeekDetailed", () => {
  it("returns the analysis on the first try without pausing", async () => {
    script(ok);
    const r = await run();
    expect(r.ok).toBe(true);
    expect(calls).toBe(1);
    expect(sleeps).toEqual([]);
  });

  it("retries a rate limit once and succeeds, honouring a short Retry-After", async () => {
    script(() => status(429, "slow down", { "retry-after": "2" }), ok);
    const r = await run();
    expect(r.ok).toBe(true);
    expect(calls).toBe(2);
    expect(sleeps).toEqual([2000]);
  });

  it("caps an unreasonable Retry-After", async () => {
    script(() => status(429, "x", { "retry-after": "600" }), ok);
    await run();
    expect(sleeps).toEqual([5000]);
  });

  it("retries a server error, then reports it as a provider error after two attempts", async () => {
    script(() => status(503));
    const r = await run();
    expect(r).toEqual({ ok: false, failure: { kind: "provider_error", status: 503, attempts: 2 } });
    expect(calls).toBe(2);
  });

  it.each([
    [401, "auth"], [402, "billing"], [400, "rejected"], [404, "rejected"],
  ] as const)("does not retry a %i (%s): it would fail the same way", async (code, kind) => {
    script(() => status(code));
    const r = await run();
    expect(r).toEqual({ ok: false, failure: { kind, status: code, attempts: 1 } });
    expect(calls).toBe(1);
    expect(sleeps).toEqual([]);
  });

  it("retries a timeout and reports it as one", async () => {
    script(() => { throw Object.assign(new Error("aborted"), { name: "AbortError" }); });
    const r = await run();
    expect(r).toEqual({ ok: false, failure: { kind: "timeout", attempts: 2 } });
  });

  it("retries a network error and can recover", async () => {
    script(() => { throw new TypeError("fetch failed"); }, ok);
    const r = await run();
    expect(r.ok).toBe(true);
    expect(calls).toBe(2);
  });

  it("treats an empty or non-JSON answer as retryable, then as empty", async () => {
    script(() => new Response(JSON.stringify({ choices: [{ message: { content: "" } }] }), { status: 200 }));
    expect(await run()).toEqual({ ok: false, failure: { kind: "empty", status: 200, attempts: 2 } });
    script(() => new Response(JSON.stringify({ choices: [{ message: { content: "not json" } }] }), { status: 200 }));
    expect(await run()).toEqual({ ok: false, failure: { kind: "empty", status: 200, attempts: 2 } });
  });

  it("reports a missing key without calling the provider", async () => {
    delete process.env.DEEPSEEK_API_KEY;
    script(ok);
    const r = await run();
    expect(r).toEqual({ ok: false, failure: { kind: "not_configured", attempts: 0 } });
    expect(calls).toBe(0);
  });

  it("never puts the provider's response text into the failure it returns", async () => {
    script(() => status(400, "model deepseek-flash does not exist; key sk-secret-123"));
    const r = await run();
    expect(JSON.stringify(r)).not.toContain("sk-secret-123");
    expect(JSON.stringify(r)).not.toContain("does not exist");
  });

  it("logs the provider's detail for the operator", async () => {
    script(() => status(400, "model does not exist"));
    await run();
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("model does not exist"));
  });
});

describe("callDeepSeek (the older null-or-result form)", () => {
  it("still returns the analysis, or null on failure", async () => {
    script(ok);
    expect(await callDeepSeek("https://example.test", [], [], "deep")).toMatchObject({ overallRisk: "One issue." });
    script(() => status(401));
    expect(await callDeepSeek("https://example.test", [], [], "deep")).toBeNull();
  });
});
