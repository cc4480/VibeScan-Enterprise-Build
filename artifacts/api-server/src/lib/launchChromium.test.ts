import { describe, it, expect, vi, afterEach } from "vitest";
import { launchChromium } from "./launchChromium";

type Opts = { args: string[] };
afterEach(() => { delete process.env["CHROMIUM_SANDBOX"]; });

const fake = (failWhen?: (o: Opts) => boolean) => {
  const launch = vi.fn(async (o: Opts) => {
    if (failWhen?.(o)) throw new Error("No usable sandbox");
    return { launched: o.args };
  });
  return { launch };
};

describe("launchChromium", () => {
  it("keeps --no-sandbox by default", async () => {
    const c = fake();
    await launchChromium(c);
    expect(c.launch.mock.calls[0]![0].args).toContain("--no-sandbox");
    expect(c.launch).toHaveBeenCalledTimes(1);
  });

  it("starts with the sandbox, and without --no-zygote, when asked and available", async () => {
    process.env["CHROMIUM_SANDBOX"] = "true";
    const c = fake();
    await launchChromium(c);
    const args = c.launch.mock.calls[0]![0].args;
    expect(args).not.toContain("--no-sandbox");
    expect(args).not.toContain("--disable-setuid-sandbox");
    expect(args).not.toContain("--no-zygote");
    expect(args).toContain("--disable-dev-shm-usage");
    expect(c.launch).toHaveBeenCalledTimes(1);
  });

  it("falls back to --no-sandbox when the sandbox will not start", async () => {
    process.env["CHROMIUM_SANDBOX"] = "true";
    const c = fake((o) => !o.args.includes("--no-sandbox"));
    await launchChromium(c);
    expect(c.launch).toHaveBeenCalledTimes(2);
    expect(c.launch.mock.calls[1]![0].args).toContain("--no-sandbox");
  });

  it("passes the proxy through", async () => {
    const c = fake();
    await launchChromium(c, { server: "http://127.0.0.1:9" });
    expect((c.launch.mock.calls[0]![0] as unknown as { proxy: unknown }).proxy).toEqual({ server: "http://127.0.0.1:9" });
  });
});
