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

describe("heartbeat", () => {
  it("reports not-fresh before the worker has written anything", () => {
    // A container that has not started yet must not pass its healthcheck.
    expect(isHeartbeatFresh(60_000)).toBe(false);
  });

  it("writes the file as soon as it is started", async () => {
    startHeartbeat();
    await new Promise((r) => setTimeout(r, 20));
    expect(fs.existsSync(heartbeatPath())).toBe(true);
    expect(isHeartbeatFresh(60_000)).toBe(true);
  });

  it("goes stale once the timestamp is older than the threshold", async () => {
    startHeartbeat();
    await new Promise((r) => setTimeout(r, 20));

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
    await new Promise((r) => setTimeout(r, 20));
    stopHeartbeat();

    const stamp = fs.readFileSync(heartbeatPath(), "utf8");
    await new Promise((r) => setTimeout(r, 40));
    expect(fs.readFileSync(heartbeatPath(), "utf8")).toBe(stamp);
  });

  it("is safe to start twice", async () => {
    startHeartbeat();
    startHeartbeat();
    await new Promise((r) => setTimeout(r, 20));
    expect(isHeartbeatFresh(60_000)).toBe(true);
  });
});
