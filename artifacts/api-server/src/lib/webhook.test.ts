import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireWebhook } from "./webhook";

/**
 * A monitor subscription takes a webhook URL from the user and the server then
 * makes requests to it. That is server-side request forgery by construction,
 * and it is the exact class this scanner sells itself on finding in other
 * people's applications — so it would be a poor look to ship it.
 *
 * The control is correct today: https-only, host rules shared with the
 * scan-target path so the two cannot drift, redirects refused outright, and the
 * check runs before anything is sent. None of that was tested, which is one
 * refactor away from being bypassed with nobody noticing — an SSRF guard fails
 * silently by definition, because the successful attack looks like a delivered
 * webhook.
 *
 * These assert the guard by its effect: whether fetch was reached at all.
 */

// These tests are about the SSRF guard, not about preferences. Mocked so a
// real database lookup (which would fail to the placeholder DATABASE_URL and
// fall through) cannot slow them down or change what they assert.
vi.mock("./notificationPrefs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./notificationPrefs")>();
  return { ...actual, notificationPrefs: async () => actual.defaultPrefs() };
});

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  fetchMock.mockResolvedValue({ ok: true });
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function fire(url: string) {
  await fireWebhook(url, "scan_complete", "https://example.com", "sub-1", { grade: "A" }, {
    userId: "user-1",
  });
}

describe("fireWebhook — hosts the guard must refuse", () => {
  it("refuses loopback", async () => {
    for (const url of [
      "https://127.0.0.1/hook",
      "https://localhost/hook",
      "https://[::1]/hook",
    ]) {
      fetchMock.mockClear();
      await fire(url);
      expect(fetchMock, url).not.toHaveBeenCalled();
    }
  });

  it("refuses RFC-1918 private ranges", async () => {
    for (const url of [
      "https://10.0.0.5/hook",
      "https://192.168.1.10/hook",
      "https://172.16.0.9/hook",
    ]) {
      fetchMock.mockClear();
      await fire(url);
      expect(fetchMock, url).not.toHaveBeenCalled();
    }
  });

  it("refuses the cloud metadata address", async () => {
    // The single most valuable SSRF target on a hosted deployment: it serves
    // instance credentials to anything that can reach it.
    fetchMock.mockClear();
    await fire("https://169.254.169.254/latest/meta-data/");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses plain http even on a public host", async () => {
    // A webhook URL often carries a secret token in its path or query. Over
    // http that token leaves in cleartext, so this is refused on transport
    // grounds rather than host grounds.
    fetchMock.mockClear();
    await fire("http://hooks.slack.com/services/T000/B000/xxxx");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a URL that will not parse", async () => {
    for (const url of ["not-a-url", "", "javascript:alert(1)", "file:///etc/passwd"]) {
      fetchMock.mockClear();
      await fire(url);
      expect(fetchMock, JSON.stringify(url)).not.toHaveBeenCalled();
    }
  });
});

describe("fireWebhook — what it does deliver", () => {
  it("posts to a legitimate https endpoint", async () => {
    await fire("https://hooks.slack.com/services/T000/B000/xxxx");

    // The control that makes every refusal above mean something: if fetch were
    // never called for anything, all of those would pass while proving nothing.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [, init] = fetchMock.mock.calls[0]!;
    expect(init.method).toBe("POST");
  });

  it("never follows a redirect", async () => {
    // A permitted host that answers 302 to 169.254.169.254 is the standard way
    // around a hostname allowlist. Refusing redirects outright closes it more
    // firmly than re-checking each hop.
    await fire("https://hooks.slack.com/services/T000/B000/xxxx");
    const [, init] = fetchMock.mock.calls[0]!;
    expect(init.redirect).toBe("error");
  });

  it("bounds the request so a hung endpoint cannot pin the worker", async () => {
    await fire("https://hooks.slack.com/services/T000/B000/xxxx");
    const [, init] = fetchMock.mock.calls[0]!;
    expect(init.signal).toBeDefined();
  });
});

describe("fireWebhook — failure is never the caller's problem", () => {
  it("retries once on a non-2xx, then gives up quietly", async () => {
    fetchMock.mockResolvedValue({ ok: false });
    await expect(fire("https://hooks.slack.com/services/T000/B000/xxxx")).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("swallows a thrown network error rather than failing the scan around it", async () => {
    // Delivery runs inside the scan pipeline. A webhook nobody can reach must
    // not turn a completed scan into a failed one.
    fetchMock.mockRejectedValue(new Error("ECONNREFUSED"));
    await expect(fire("https://hooks.slack.com/services/T000/B000/xxxx")).resolves.toBeUndefined();
  });
});

describe("fireWebhook — notification preferences", () => {
  const SLACK = "https://hooks.slack.com/services/T000/B000/xxxx";

  async function fireWith(
    prefs: Parameters<typeof import("./notificationPrefs").shouldNotify>[0],
    event: Parameters<typeof fireWebhook>[1],
    severity?: string,
  ) {
    const mod = await import("./notificationPrefs");
    vi.spyOn(mod, "notificationPrefs").mockResolvedValue(prefs);
    await fireWebhook(SLACK, event, "https://example.com", "sub-1", {}, {
      userId: "user-1",
      severity,
    });
  }

  it("does not deliver a kind the user turned off", async () => {
    const { defaultPrefs } = await import("./notificationPrefs");
    await fireWith(
      { ...defaultPrefs(), optedOutKinds: new Set(["scan_complete"] as const) },
      "scan_complete",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("still delivers the kinds they kept", async () => {
    const { defaultPrefs } = await import("./notificationPrefs");
    await fireWith(
      { ...defaultPrefs(), optedOutKinds: new Set(["scan_complete"] as const) },
      "cve_alert",
      "high",
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("drops an alert under the severity floor", async () => {
    const { defaultPrefs } = await import("./notificationPrefs");
    await fireWith({ ...defaultPrefs(), minSeverity: "high" }, "cve_alert", "low");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("ignores the EMAIL opt-out — that switch is not about webhooks", async () => {
    // One-click List-Unsubscribe sets alertEmailsOptedOut. If that also killed
    // webhooks, a user tidying their inbox would silently break their team's
    // Slack integration, and nothing would say why.
    const { defaultPrefs } = await import("./notificationPrefs");
    await fireWith({ ...defaultPrefs(), emailOptedOut: true }, "cve_alert", "high");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
