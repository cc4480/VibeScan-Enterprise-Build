import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * The probe stage hands the site's downloaded JavaScript to the checks that look for a backend.
 *
 * Found with a Lovable-style target app (React + Vite, Supabase): its page is an empty shell and one
 * `<script type="module">`, and the project URL, the key and the table names are all in that script. The
 * Supabase, BaaS and storage checks were given only the page, so each answered "nothing to test" and
 * the target scored 2 of 10 faults with two tables readable by anyone. The stage already downloaded
 * the same script for the secret scanner; it just never passed it on.
 */

const spies = vi.hoisted(() => ({
  vibe: vi.fn(async (..._a: unknown[]) => []),
  baas: vi.fn(async (..._a: unknown[]) => []),
  storage: vi.fn(async (..._a: unknown[]) => []),
  all: vi.fn(async (..._a: unknown[]) => []),
  collect: vi.fn(async (..._a: unknown[]) => ""),
  secrets: vi.fn(async (..._a: unknown[]) => []),
}));

vi.mock("./vibeStackProbes", () => ({ checkVibeStackSecurity: spies.vibe }));
vi.mock("./baasProbes", () => ({ runBaasProbes: spies.baas }));
vi.mock("./storageProbe", () => ({ runStorageProbe: spies.storage }));
vi.mock("./probes", () => ({ runAllProbes: spies.all }));
vi.mock("./jsScanner", () => ({ scanJavaScriptForSecrets: spies.secrets, collectFirstPartyJavaScript: spies.collect }));

// Everything else the stage starts: not under test here, and several of them reach the network.
vi.mock("./crawler", () => ({ crawlAndCheck: async () => ({ vulnerabilities: [], pagesVisited: [], probedNotFound: [] }) }));
vi.mock("./dnsChecks", () => ({ checkDnsSecurity: async () => [] }));
vi.mock("./mailTls.js", () => ({ inspectMailTls: async () => ({}), mailTlsFindings: () => [] }));
vi.mock("./structuredData.js", () => ({ structuredDataFindings: () => [] }));
vi.mock("./manifestSca.js", () => ({ scaFromExposedManifest: async () => [] }));
vi.mock("./cveCheck", () => ({ checkForKnownVulnerabilities: async () => [] }));
vi.mock("./jwtAnalysis", () => ({ analyzeJwts: async () => [] }));
vi.mock("./subdomainTakeover", () => ({ checkSubdomainTakeover: async () => [] }));
vi.mock("./pathTraversal", () => ({ checkPathTraversal: async () => [] }));
vi.mock("./injectionProbe", () => ({ runInjectionProbes: async () => [] }));
vi.mock("./sourceMaps", () => ({ checkSourceMaps: async () => [] }));
vi.mock("./graphqlProbe", () => ({ runGraphqlProbe: async () => [] }));
vi.mock("./apiDocsProbe", () => ({ runApiDocsProbe: async () => [] }));
vi.mock("./healthEndpointProbe", () => ({ runHealthEndpointProbe: async () => [] }));
vi.mock("./nextjsProbe", () => ({ runNextjsProbe: async () => [] }));
vi.mock("./githubSourceProbe", () => ({ parseGithubRepoRef: () => null, scanGithubRepo: async () => ({}), githubProbeOutcome: () => ({ findings: [] }) }));

import { runProbeStage } from "./scannerProbeStage";
import { TestLedger } from "./testLedger";

const SHELL = `<html><head><script type="module" crossorigin src="/assets/index-Ct6cDlio.js"></script></head><body><div id="root"></div></body></html>`;
const BUNDLE = `const sM="https://abcdefghijklmnopqrst.supabase.co",aM="eyJ-the-key",Tn=cO(sM,aM);Tn.from("orders");Tn.storage.from("avatars");`;
const URL_ = "https://app.example.test/";

const stage = (allowActiveProbes: boolean) =>
  runProbeStage({
    finalUrl: URL_, html: SHELL, rawHeaders: {}, setCookies: [], status: 200, tier: "deep",
    allowActiveProbes, ledger: new TestLedger(), crawlPageBudget: 0,
  });

beforeEach(() => {
  for (const s of Object.values(spies)) s.mockClear();
  spies.collect.mockResolvedValue(BUNDLE);
});

describe("runProbeStage with active checks allowed", () => {
  it("downloads the site's own scripts once and gives the page plus the scripts to the Supabase check", async () => {
    await stage(true);
    expect(spies.collect).toHaveBeenCalledTimes(1);
    expect(spies.collect).toHaveBeenCalledWith(SHELL, URL_);
    const content = String(spies.vibe.mock.calls[0]![0]);
    expect(content).toContain(SHELL);
    expect(content).toContain(BUNDLE);
  });

  it("gives them to the BaaS check and to the cloud-storage check", async () => {
    await stage(true);
    expect(String(spies.baas.mock.calls[0]![1])).toContain(BUNDLE);
    expect(String(spies.storage.mock.calls[0]![1])).toContain(BUNDLE);
  });

  it("gives them to the Supabase RLS check inside the HTTP probes", async () => {
    await stage(true);
    const siteCode = spies.all.mock.calls[0]![7];
    expect(await siteCode).toBe(BUNDLE);
  });

  it("still runs the checks, on the page alone, when the scripts cannot be downloaded", async () => {
    spies.collect.mockRejectedValue(new Error("connection reset"));
    await stage(true);
    expect(String(spies.vibe.mock.calls[0]![0])).toBe(`${SHELL}\n`);
    expect(String(spies.baas.mock.calls[0]![1])).toBe(`${SHELL}\n`);
    expect(String(spies.storage.mock.calls[0]![1])).toBe(`${SHELL}\n`);
  });
});

describe("runProbeStage without active checks (a target the user has not verified)", () => {
  it("downloads no extra scripts and starts none of the backend checks", async () => {
    await stage(false);
    expect(spies.collect).not.toHaveBeenCalled();
    expect(spies.vibe).not.toHaveBeenCalled();
    expect(spies.baas).not.toHaveBeenCalled();
    expect(spies.storage).not.toHaveBeenCalled();
  });

  it("passes the HTTP probes an empty script text, so nothing is fetched on their behalf", async () => {
    await stage(false);
    expect(await spies.all.mock.calls[0]![7]).toBe("");
  });
});
