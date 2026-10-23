import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { buildEvidencePack, csvCell, type PackInput } from "./evidencePack";
import { sha256Hex, verifyManifestSignature } from "./evidenceSign";
import { readZip } from "./zipReader.testkit";

const KEY = randomBytes(32).toString("base64");
const prevKey = process.env["ENCRYPTION_KEY"];
beforeAll(() => { process.env["ENCRYPTION_KEY"] = KEY; });
afterAll(() => { if (prevKey === undefined) delete process.env["ENCRYPTION_KEY"]; else process.env["ENCRYPTION_KEY"] = prevKey; });

const ran = (name: string, findings = 0) => ({ group: "HTTP probes", name, status: "ran", findings, durationMs: 5 });
const data = (over: Record<string, unknown> = {}) => ({
  summary: { grade: "C", riskScore: 52 },
  vulnerabilities: [
    { id: "f1", name: "Missing Content-Security-Policy (CSP)", severity: "high", category: "Security Headers", description: "No CSP.", evidence: "GET /", solution: "Add one.", cweId: "CWE-693", wstgId: "WSTG-CONF-12", cvssScore: 6.1, confidence: 90 },
    { id: "f2", name: "Server Version Disclosed", severity: "low", category: "Information Disclosure", description: "nginx/1.18", evidence: "Server: nginx/1.18", solution: "Hide it." },
    { id: "f3", name: "Environment File Exposed (.env)", severity: "critical", category: "Information Disclosure", description: "The .env file is served.", evidence: "GET /.env", solution: "Remove it." },
    { id: "n1", name: "Active security testing was skipped for this scan", severity: "info", category: "Scan Coverage", description: "Not verified.", evidence: "", solution: "" },
  ],
  tests: [ran("security headers", 1), ran("security.txt"), { group: "active", name: "injection probes", status: "skipped", findings: 0, durationMs: 0, reason: "domain not verified: active tests need proof you own the site" }],
  ...over,
});
const input = (over: Partial<PackInput> = {}): PackInput => ({
  reportId: "11111111-2222-4333-8444-555555555555", targetUrl: "https://shop.example.com/", scannedAt: new Date("2026-10-23T09:30:10.000Z"),
  tier: "deep", data: data(), origin: "https://secscan.us", ...over,
});
const files = (over: Partial<PackInput> = {}) => new Map(readZip(buildEvidencePack(input(over)).bytes).map((e) => [e.name, e.data]));
const text = (m: Map<string, Buffer>, name: string) => m.get(name)!.toString("utf8");

describe("buildEvidencePack: what is in it", () => {
  it("holds the report, the SARIF, both tables, the summary, the manifest, the signature and a README", () => {
    expect([...files().keys()].sort()).toEqual(
      ["MANIFEST.json", "MANIFEST.sha256", "README.txt", "SIGNATURE.json", "coverage.csv", "findings.csv", "report.json", "report.sarif.json", "summary.md"],
    );
  });

  it("names the file for the site and the scan date", () => {
    expect(buildEvidencePack(input()).filename).toBe("secscan-evidence-shop.example.com-2026-10-23.zip");
    expect(buildEvidencePack(input({ targetUrl: "not a url" })).filename).toBe("secscan-evidence-report-2026-10-23.zip");
  });

  it("report.json is the stored report, exactly", () => {
    expect(JSON.parse(text(files(), "report.json"))).toEqual(data());
  });

  it("report.sarif.json is SARIF 2.1.0 with the findings", () => {
    const sarif = JSON.parse(text(files(), "report.sarif.json"));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThanOrEqual(3);
  });

  it("findings.csv has one row per finding, worst first, and leaves the scan's own notes out", () => {
    const rows = text(files(), "findings.csv").trim().split("\r\n");
    expect(rows[0]).toBe("id,severity,name,category,cwe,owasp_wstg,cvss,confidence,description,recommended_fix");
    expect(rows).toHaveLength(1 + 3);
    expect(rows[1]).toMatch(/^f3,critical,/);
    expect(rows[2]).toMatch(/^f1,high,/);
    expect(rows[3]).toMatch(/^f2,low,/);
    expect(rows.join("\n")).not.toContain("Active security testing was skipped");
  });

  it("coverage.csv lists every test with its reason", () => {
    const rows = text(files(), "coverage.csv").trim().split("\r\n");
    expect(rows).toHaveLength(1 + 3);
    expect(rows.join("\n")).toContain("injection probes,skipped,0,domain not verified");
  });
});

describe("buildEvidencePack: the summary says what it should", () => {
  it("states the grade, the counts, the critical and high findings, and the coverage", () => {
    const s = text(files(), "summary.md");
    expect(s).toContain("| Grade | C (risk score 52/100) |");
    expect(s).toContain("3 findings: 1 critical, 1 high, 0 medium, 1 low, 0 info.");
    expect(s).toContain("**critical**: Environment File Exposed (.env)");
    expect(s).toContain("**high**: Missing Content-Security-Policy (CSP)");
    expect(s).toContain("2 of 3 tests ran; 1 skipped; 0 failed.");
    expect(s).toContain("https://secscan.us/report/11111111-2222-4333-8444-555555555555");
  });

  it("says the active tests did not run, and which tests were not run, when the domain was not verified", () => {
    const s = text(files(), "summary.md");
    expect(s).toContain("Did not run: the domain was not verified");
    expect(s).toContain("Never read these areas as safe");
    expect(s).toContain("injection probes: domain not verified");
  });

  it("says the active tests ran when every test ran", () => {
    const s = text(files({ data: data({ tests: [ran("a"), ran("b")] }) }), "summary.md");
    expect(s).toContain("Ran: the site's owner verified the domain");
    expect(s).not.toContain("Not tested on this scan");
  });

  it("is plain that it is a point-in-time record, not a certification", () => {
    expect(text(files(), "summary.md")).toMatch(/not a certification or an audit/);
  });

  it("names who it is prepared for, as one line of plain text, and only when given", () => {
    expect(text(files(), "summary.md")).not.toContain("Prepared for");
    expect(text(files({ preparedFor: "Acme Ltd" }), "summary.md")).toContain("Prepared for **Acme Ltd**.");
    expect(text(files({ preparedFor: "Acme\n# Injected heading" }), "summary.md")).not.toMatch(/^# Injected heading/m);
  });

  it("copes with an old report that has no tests or counts", () => {
    const s = text(files({ data: { summary: { grade: "B" }, vulnerabilities: [] } }), "summary.md");
    expect(s).toContain("The report does not record test coverage.");
    expect(s).toContain("| Grade | B |");
  });

  it("copes with a report that is not an object at all", () => {
    expect(() => buildEvidencePack(input({ data: null }))).not.toThrow();
  });
});

describe("buildEvidencePack: integrity", () => {
  it("the manifest lists every file with its real SHA-256 and size", () => {
    const m = files();
    const manifest = JSON.parse(text(m, "MANIFEST.json"));
    expect(manifest.reportId).toBe("11111111-2222-4333-8444-555555555555");
    expect(manifest.files.map((f: { name: string }) => f.name).sort()).toEqual(["coverage.csv", "findings.csv", "report.json", "report.sarif.json", "summary.md"]);
    for (const f of manifest.files) {
      expect(f.sha256, f.name).toBe(sha256Hex(m.get(f.name)!));
      expect(f.bytes, f.name).toBe(m.get(f.name)!.length);
    }
  });

  it("MANIFEST.sha256 passes sha256sum -c, if this machine has it", () => {
    let have = true;
    try { execFileSync("sha256sum", ["--version"], { stdio: "ignore" }); } catch { have = false; }
    if (!have) return;
    const dir = mkdtempSync(join(tmpdir(), "secscan-pack-"));
    try {
    for (const [name, bytes] of files()) writeFileSync(join(dir, name), bytes);
    const out = execFileSync("sha256sum", ["-c", "MANIFEST.sha256"], { cwd: dir }).toString();
    expect(out).toMatch(/report\.json: OK/);
    expect(out).not.toMatch(/FAILED/);
    // And it notices a file that was changed.
    writeFileSync(join(dir, "report.json"), "{}");
    expect(() => execFileSync("sha256sum", ["-c", "MANIFEST.sha256"], { cwd: dir, stdio: "pipe" })).toThrow();
    expect(readFileSync(join(dir, "MANIFEST.sha256"), "utf8")).toContain("  report.json");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("is signed, and the signature in SIGNATURE.json verifies the manifest's hash", () => {
    const pack = buildEvidencePack(input());
    const m = new Map(readZip(pack.bytes).map((e) => [e.name, e.data]));
    const sig = JSON.parse(text(m, "SIGNATURE.json"));
    expect(pack.signed).toBe(true);
    expect(sig.manifestSha256).toBe(sha256Hex(m.get("MANIFEST.json")!));
    expect(sig.manifestSha256).toBe(pack.manifestSha256);
    expect(verifyManifestSignature(sig.manifestSha256, sig.signature)).toBe(true);
    expect(sig.verifyAt).toBe("https://secscan.us/api/evidence/verify");
  });

  it("the signature stops verifying when the manifest is edited", () => {
    const m = files();
    const sig = JSON.parse(text(m, "SIGNATURE.json"));
    const edited = text(m, "MANIFEST.json").replace("shop.example.com", "other.example.com");
    expect(verifyManifestSignature(sha256Hex(edited), sig.signature)).toBe(false);
  });

  it("without a signing key it says so rather than pretending", () => {
    delete process.env["ENCRYPTION_KEY"];
    try {
      const pack = buildEvidencePack(input());
      const m = new Map(readZip(pack.bytes).map((e) => [e.name, e.data]));
      expect(pack.signed).toBe(false);
      expect(JSON.parse(text(m, "SIGNATURE.json")).signature).toBeNull();
      expect(text(m, "README.txt")).toContain("made without a signature");
    } finally {
      process.env["ENCRYPTION_KEY"] = KEY;
    }
  });

  it("is reproducible: the same report gives the same archive", () => {
    expect(buildEvidencePack(input()).bytes.equals(buildEvidencePack(input()).bytes)).toBe(true);
  });

  it("changes when the report changes", () => {
    const other = buildEvidencePack(input({ data: data({ summary: { grade: "A", riskScore: 5 } }) }));
    expect(other.manifestSha256).not.toBe(buildEvidencePack(input()).manifestSha256);
  });

  it("README tells the reader how to check it", () => {
    const r = text(files(), "README.txt");
    expect(r).toContain("sha256sum -c MANIFEST.sha256");
    expect(r).toContain("https://secscan.us/api/evidence/verify");
  });
});

describe("csvCell", () => {
  it.each([
    ["plain", "plain"],
    ["has,comma", '"has,comma"'],
    ['has "quote"', '"has ""quote"""'],
    ["two\nlines", '"two\nlines"'],
    [null, ""],
    [undefined, ""],
    [12, "12"],
  ])("%j -> %j", (input, expected) => {
    expect(csvCell(input)).toBe(expected);
  });

  it.each(["=HYPERLINK(\"http://evil.example\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd"])("defuses a spreadsheet formula: %j", (cell) => {
    expect(csvCell(cell).startsWith("'") || csvCell(cell).startsWith("\"'")).toBe(true);
  });
});
