import { describe, it, expect } from "vitest";
import { redactContext, scanJavaScriptForSecrets } from "./jsScanner";

// Fake, test-only values, shaped like the real thing so the patterns fire.
const STRIPE = "sk_live_51JvFakeKeyDoNotUse0000000000000";
const AWS_ID = "AKIAQZPXMC4278HDVBNR";
const AWS_SECRET = "gggggggggggggggggggggggggggggggggggggggg";

describe("secret evidence is masked in full", () => {
  it("masks the matched secret inside its own context window", () => {
    const out = redactContext(`const key = "${STRIPE}";`, STRIPE);
    expect(out).not.toContain(STRIPE);
    expect(out).toContain('const key = "');
  });

  it("masks neighbouring secrets that were not the match", () => {
    const ctx = `const AWS_ACCESS_KEY_ID = "${AWS_ID}"; const awsSecretAccessKey = "${AWS_SECRET}";`;
    const out = redactContext(ctx, AWS_SECRET);
    expect(out).not.toContain(AWS_ID);
    expect(out).not.toContain(AWS_SECRET);
  });

  it("masks a key cut in half at the window's edge, which no pattern can match", () => {
    const half = STRIPE.slice(10); // "51JvFakeKey…" — no sk_live_ prefix left
    expect(redactContext(`${half}"; const x = 1;`, "unrelated")).not.toContain(half);
  });

  it("never writes a found key out whole in a finding's evidence", async () => {
    const html = `<html><script>const cfg = { aws: "${AWS_ID}", awsSecretAccessKey: "${AWS_SECRET}", stripe: "${STRIPE}" };</script></html>`;
    const vulns = await scanJavaScriptForSecrets(html, "https://example.test/");
    expect(vulns.length).toBeGreaterThan(0);
    for (const v of vulns) {
      for (const secret of [STRIPE, AWS_ID, AWS_SECRET]) expect(v.evidence).not.toContain(secret);
    }
  });
});
