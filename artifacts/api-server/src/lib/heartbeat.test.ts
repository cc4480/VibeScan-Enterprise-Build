import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  startHeartbeat,
  stopHeartbeat,
  isHeartbeatFresh,
  heartbeatPath,
} from "./heartbeat";

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "hb-"));
  process.env["HEARTBEAT_FILE"] = path.join(dir, "beat");
});

afterEach(() => {
  stopHeartbeat();
  delete process.env["HEARTBEAT_FILE"];
  fs.rmSync(dir, { recursive: true, force: true });
});

/**
 * The first write is fire-and-forget, so its timing is not ours to predict —
 * under a loaded test run it can land well after any fixed delay. Poll for the
 * outcome instead of sleeping for a guessed interval, or this becomes a test
 * that fails a few times a month for no reason anyone can reproduce.
 */
async function waitForHeartbeat(timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    // Existence is not enough: wait for a heartbeat that actually reads as
    // fresh, which is what the healthcheck asks.
    if (isHeartbeatFresh(60_000)) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(`no fresh heartbeat appeared at ${heartbeatPath()}`);
}

describe("heartbeat", () => {
  it("reports not-fresh before the worker has written anything", () => {
    // A container that has not started yet must not pass its healthcheck.
    expect(isHeartbeatFresh(60_000)).toBe(false);
  });

  it("writes the file as soon as it is started", async () => {
    startHeartbeat();
    await waitForHeartbeat();
    expect(isHeartbeatFresh(60_000)).toBe(true);
  });

  it("goes stale once the timestamp is older than the threshold", async () => {
    startHeartbeat();
    await waitForHeartbeat();

    // Judged against a clock far enough ahead that the last write is old.
    const wayLater = Date.now() + 120_000;
    expect(isHeartbeatFresh(60_000, wayLater)).toBe(false);
    expect(isHeartbeatFresh(60_000)).toBe(true);
  });

  it("treats an unreadable or garbled file as not fresh", () => {
    fs.writeFileSync(heartbeatPath(), "not-a-timestamp", "utf8");
    expect(isHeartbeatFresh(60_000)).toBe(false);
  });

  it("stops writing after stopHeartbeat, so a draining worker stops claiming health", async () => {
    startHeartbeat();
    await waitForHeartbeat();
    stopHeartbeat();

    // The interval is 15 s, so nothing should rewrite the file in this window
    // whether or not the machine is busy.
    const stamp = fs.readFileSync(heartbeatPath(), "utf8");
    await new Promise((r) => setTimeout(r, 60));
    expect(fs.readFileSync(heartbeatPath(), "utf8")).toBe(stamp);
  });

  it("is safe to start twice", async () => {
    startHeartbeat();
    startHeartbeat();
    await waitForHeartbeat();
    expect(isHeartbeatFresh(60_000)).toBe(true);
  });
});
