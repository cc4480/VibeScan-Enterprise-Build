import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * The direct-to-authority DNS attempt is an optimisation and must not decide how long a check takes.
 * On Railway the first scheduled re-verification timed out on every domain (30 s backstop) because
 * the authoritative queries hung; this pins that the attempt is abandoned after AUTHORITY_DEADLINE_MS
 * and the recursive resolver answers instead.
 */
const state = { cancelled: 0, authorityNeverAnswers: true };

vi.mock("node:dns/promises", () => {
  class Resolver {
    private reject?: (e: Error) => void;
    setServers() {}
    cancel() {
      state.cancelled++;
      this.reject?.(Object.assign(new Error("cancelled"), { code: "ECANCELLED" }));
    }
    resolveTxt(): Promise<string[][]> {
      if (!state.authorityNeverAnswers) return Promise.resolve([["the-token"]]);
      return new Promise((_, reject) => { this.reject = reject; });
    }
  }
  return {
    resolveNs: vi.fn(async () => ["ns1.example.net", "ns2.example.net"]),
    resolve4: vi.fn(async () => ["93.184.216.34"]),
    resolveTxt: vi.fn(async () => [["the-token"]]),
    Resolver,
  };
});

const { checkTxtRecord, AUTHORITY_DEADLINE_MS } = await import("./domainVerify");

beforeEach(() => {
  state.cancelled = 0;
  state.authorityNeverAnswers = true;
  vi.useFakeTimers();
});
afterEach(() => vi.useRealTimers());

describe("checkTxtRecord with unreachable authoritative nameservers", () => {
  it("falls back to the recursive resolver once the authority deadline passes, and cancels the stuck queries", async () => {
    const result = checkTxtRecord("example.com", "the-token");
    let settled = false;
    void result.then(() => { settled = true; });

    await vi.advanceTimersByTimeAsync(AUTHORITY_DEADLINE_MS - 1);
    expect(settled).toBe(false);

    await vi.advanceTimersByTimeAsync(2);
    await expect(result).resolves.toBe(true);
    expect(state.cancelled).toBe(1);
  });

  it("does not wait for the deadline when the authority answers", async () => {
    state.authorityNeverAnswers = false;
    await expect(checkTxtRecord("example.com", "the-token")).resolves.toBe(true);
    expect(state.cancelled).toBe(0);
  });

  it("keeps the deadline well inside the re-verification backstop", () => {
    expect(AUTHORITY_DEADLINE_MS).toBeLessThanOrEqual(10_000);
  });
});
