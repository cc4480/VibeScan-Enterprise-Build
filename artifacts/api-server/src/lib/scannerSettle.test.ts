import { describe, it, expect } from "vitest";
import { settleFindings } from "./scannerSettle";
import { TestLedger } from "./testLedger";
import type { ScanVulnerability } from "./scannerTypes";

const finding = (name: string, category: string): ScanVulnerability =>
  ({ id: name, name, category, severity: "medium", description: "d", evidence: "e", solution: "s", confidence: 80 }) as ScanVulnerability;

const notChallenge = { isChallenge: false, vendor: null, signal: null } as never;
const challenge = { isChallenge: true, vendor: "Cloudflare", signal: "cf-chl" } as never;
const wall = { isGate: true, kind: "sign-in wall", vendor: "Vercel", signal: "sso" } as never;

const HEADER = "Rate Limiting Not Advertised in Response Headers";
const BEHAVIOURAL = "No Rate Limiting Observed on Sensitive API Endpoints";

describe("settleFindings: rate-limit inference", () => {
  it("drops the header inference when the burst test demonstrated the problem, and says so", () => {
    const { deduped, withheld } = settleFindings({
      vulnerabilities: [finding(HEADER, "Rate Limiting"), finding(BEHAVIOURAL, "Rate Limiting"), finding("Other", "Headers")],
      intercepted: false, challengeVerdict: notChallenge, gateVerdict: null, ledger: new TestLedger(),
    });
    expect(deduped.map((v) => v.name)).toEqual([BEHAVIOURAL, "Other"]);
    expect(withheld).toEqual([
      { name: HEADER, severity: "medium", category: "Rate Limiting", reason: "covered by the rate-limit test that sent real requests, which is reported instead" },
    ]);
  });

  it("keeps the header finding when nothing demonstrated it", () => {
    const { deduped, withheld } = settleFindings({
      vulnerabilities: [finding(HEADER, "Rate Limiting")],
      intercepted: false, challengeVerdict: notChallenge, gateVerdict: null, ledger: new TestLedger(),
    });
    expect(deduped.map((v) => v.name)).toEqual([HEADER]);
    expect(withheld).toEqual([]);
  });
});

describe("settleFindings: an edge or platform answered instead of the app", () => {
  const ran = (name: string) => ({ group: "passive", name, status: "ran" as const, findings: 1, durationMs: 1, found: ["x"] });

  it("withholds findings read from a bot-protection page, naming the vendor, and keeps those that never read it", () => {
    const ledger = new TestLedger();
    ledger.records.push(ran("security.txt"), ran("DNS and email authentication"));
    const { deduped, withheld } = settleFindings({
      vulnerabilities: [finding("Missing CSP", "Security Headers"), finding("Weak SPF", "DNS & Email Security")],
      intercepted: true, challengeVerdict: challenge, gateVerdict: null, ledger,
    });
    const keptNames = deduped.map((v) => v.name);
    expect(keptNames.length + withheld.length).toBe(2);
    expect(withheld.every((w) => w.reason === "read from Cloudflare's bot-protection page, not from this site")).toBe(true);
    // The tests that read the page are no longer reported as having run; the ones that did not are left alone.
    expect(ledger.records.find((r) => r.name === "security.txt")).toMatchObject({ status: "skipped", reason: "not tested on the app: a bot-protection page answered instead of the site", findings: 0 });
    expect(ledger.records.find((r) => r.name === "DNS and email authentication")).toMatchObject({ status: "ran" });
  });

  it("words the reason for a sign-in wall differently from a challenge", () => {
    const ledger = new TestLedger();
    ledger.records.push(ran("security.txt"));
    const { withheld } = settleFindings({
      vulnerabilities: [finding("Missing CSP", "Security Headers")],
      intercepted: true, challengeVerdict: notChallenge, gateVerdict: wall, ledger,
    });
    expect(withheld.map((w) => w.reason)).toEqual(["read from Vercel sign-in page, not from the app"]);
    expect(ledger.records[0]).toMatchObject({ status: "skipped", reason: "not tested on the app: a sign-in page answered instead of the app" });
  });

  it("changes nothing when nothing intercepted the scan", () => {
    const ledger = new TestLedger();
    ledger.records.push(ran("security.txt"));
    const { deduped, withheld } = settleFindings({
      vulnerabilities: [finding("Missing CSP", "Security Headers")],
      intercepted: false, challengeVerdict: notChallenge, gateVerdict: null, ledger,
    });
    expect(deduped).toHaveLength(1);
    expect(withheld).toEqual([]);
    expect(ledger.records[0]).toMatchObject({ status: "ran" });
  });
});
