import { describe, it, expect } from "vitest";

import { CreateMonitorBody, MONITOR_URL_MAX_LENGTH } from "./monitorShared";

const withLength = (n: number) => {
  const prefix = "https://example.com/";
  return `${prefix}${"a".repeat(n - prefix.length)}`;
};

describe("monitor subscription body", () => {
  it("accepts a target URL exactly at the length limit", () => {
    const url = withLength(MONITOR_URL_MAX_LENGTH);
    expect(url).toHaveLength(MONITOR_URL_MAX_LENGTH);
    expect(CreateMonitorBody.safeParse({ targetUrl: url }).success).toBe(true);
  });

  it("refuses a target URL one character past the limit, instead of letting the index insert fail", () => {
    const result = CreateMonitorBody.safeParse({ targetUrl: withLength(MONITOR_URL_MAX_LENGTH + 1) });
    expect(result.success).toBe(false);
  });

  it("refuses an over-long webhook URL too", () => {
    const result = CreateMonitorBody.safeParse({
      targetUrl: "https://example.com/",
      webhookUrl: withLength(MONITOR_URL_MAX_LENGTH + 1),
    });
    expect(result.success).toBe(false);
  });
});
