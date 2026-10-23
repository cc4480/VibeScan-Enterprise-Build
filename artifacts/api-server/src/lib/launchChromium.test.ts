import { describe, it, expect, afterEach } from "vitest";
import { launchChromium } from "./launchChromium";

type Opts = { args: string[] };
afterEach(() => { delete process.env["CHROMIUM_SANDBOX"]; });

/** A launcher handed to launchChromium, which takes one: it records the options each launch was asked for. */
const fake = (failWhen?: (o: Opts) => boolean) => {
  const calls: Opts[] = [];
  const launch = async (o: Opts) => {
    calls.push(o);
    if (failWhen?.(o)) throw new Error("No usable sandbox");
    return { launched: o.args };
  };
  return { launch, calls };
};

describe("launchChromium", () => {
  it("starts with the sandbox by default", async () => {
    const c = fake();
    await launchChromium(c);
    const args = c.calls[0]!.args;
    expect(args).not.toContain("--no-sandbox");
    expect(args).not.toContain("--disable-setuid-sandbox");
    expect(args).not.toContain("--no-zygote");
    expect(c.calls).toHaveLength(1);
  });

  it("starts with the sandbox when CHROMIUM_SANDBOX=true", async () => {
    process.env["CHROMIUM_SANDBOX"] = "true";
    const c = fake();
    await launchChromium(c);
    const args = c.calls[0]!.args;
    expect(args).not.toContain("--no-sandbox");
    expect(args).toContain("--disable-dev-shm-usage");
    expect(c.calls).toHaveLength(1);
  });

  it("disables the sandbox only on an explicit CHROMIUM_SANDBOX=false", async () => {
    process.env["CHROMIUM_SANDBOX"] = "false";
    const c = fake();
    await launchChromium(c);
    expect(c.calls).toHaveLength(1);
    expect(c.calls[0]!.args).toContain("--no-sandbox");
  });

  it("treats any other value as sandbox on", async () => {
    process.env["CHROMIUM_SANDBOX"] = "0";
    const c = fake();
    await launchChromium(c);
    expect(c.calls[0]!.args).not.toContain("--no-sandbox");
  });

  it("falls back to --no-sandbox when the sandbox will not start", async () => {
    process.env["CHROMIUM_SANDBOX"] = "true";
    const c = fake((o) => !o.args.includes("--no-sandbox"));
    await launchChromium(c);
    expect(c.calls).toHaveLength(2);
    expect(c.calls[1]!.args).toContain("--no-sandbox");
  });

  it("passes the proxy through", async () => {
    const c = fake();
    await launchChromium(c, { server: "http://127.0.0.1:9" });
    expect((c.calls[0]! as unknown as { proxy: unknown }).proxy).toEqual({ server: "http://127.0.0.1:9" });
  });
});
