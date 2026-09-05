import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const ORIGINAL_ENV = { ...process.env };

beforeEach(() => {
  vi.resetModules();
  vi.stubGlobal("fetch", vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
  process.env = { ...ORIGINAL_ENV };
});

describe("addToMarketingAudience", () => {
  it("skips silently when RESEND_AUDIENCE_API_KEY or RESEND_AUDIENCE_ID is unset", async () => {
    delete process.env.RESEND_AUDIENCE_API_KEY;
    delete process.env.RESEND_AUDIENCE_ID;
    const { addToMarketingAudience } = await import("./mailer.js");

    await addToMarketingAudience("user@example.com");

    expect(fetch).not.toHaveBeenCalled();
  });

  it("posts the contact to the configured audience when both vars are set", async () => {
    process.env.RESEND_AUDIENCE_API_KEY = "re_test_key";
    process.env.RESEND_AUDIENCE_ID = "aud_123";
    vi.mocked(fetch).mockResolvedValue(new Response("{}", { status: 200 }));
    const { addToMarketingAudience } = await import("./mailer.js");

    await addToMarketingAudience("user@example.com", "Alex");

    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = vi.mocked(fetch).mock.calls[0]!;
    expect(String(url)).toBe("https://api.resend.com/audiences/aud_123/contacts");
    expect((init as RequestInit).headers).toMatchObject({ Authorization: "Bearer re_test_key" });
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body).toMatchObject({ email: "user@example.com", first_name: "Alex", unsubscribed: false });
  });

  it("does not throw when the Resend API call fails", async () => {
    process.env.RESEND_AUDIENCE_API_KEY = "re_test_key";
    process.env.RESEND_AUDIENCE_ID = "aud_123";
    vi.mocked(fetch).mockResolvedValue(new Response("boom", { status: 500 }));
    const { addToMarketingAudience } = await import("./mailer.js");

    await expect(addToMarketingAudience("user@example.com")).resolves.toBeUndefined();
  });
});

describe("sendWelcomeEmail", () => {
  it("skips silently when RESEND_API_KEY is unset", async () => {
    delete process.env.RESEND_API_KEY;
    const { sendWelcomeEmail } = await import("./mailer.js");

    await sendWelcomeEmail("user@example.com");

    expect(fetch).not.toHaveBeenCalled();
  });

  it("sends via the standard Resend emails endpoint when RESEND_API_KEY is set", async () => {
    process.env.RESEND_API_KEY = "re_test_key";
    vi.mocked(fetch).mockResolvedValue(new Response("{}", { status: 200 }));
    const { sendWelcomeEmail } = await import("./mailer.js");

    await sendWelcomeEmail("user@example.com", "Alex");

    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = vi.mocked(fetch).mock.calls[0]!;
    expect(String(url)).toBe("https://api.resend.com/emails");
    const body = JSON.parse((init as RequestInit).body as string);
    expect(body.to).toEqual(["user@example.com"]);
    expect(body.html).toContain("Alex");
  });
});
