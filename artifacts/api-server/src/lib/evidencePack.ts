/**
 * The evidence pack for a report: what an auditor, a customer's security team or a procurement form asks for, in one file.
 *
 * A ZIP holding the full report, the same findings as SARIF, a findings table and a test-coverage table (both CSV), a plain
 * summary, and a manifest of every file's SHA-256 signed by SecScan (evidenceSign.ts). Everything is built from the stored
 * report, so the pack says what the report says and nothing more, and the same report always gives the same archive.
 *
 * Plain about its limits: a scan is a point-in-time test of what could be reached, not a certification, and the summary says
 * which tests did not run, because a grade with skipped tests is not a statement about the skipped areas.
 */
import { summariseReport } from "./apiV1Report";
import { isScanNote } from "./scanNotes";
import { scanRanVerified } from "./reportBadge";
import { toSarif } from "./sarif";
import { sha256Hex, signManifest, SIGNATURE_VERSION } from "./evidenceSign";
import { zip, type ZipEntry } from "./zipWriter";

export interface PackInput {
  reportId: string;
  targetUrl: string;
  scannedAt: Date;
  tier: string;
  data: unknown;
  /** Who the pack is prepared for (an organisation name). Shown on the summary; never changes any finding. */
  preparedFor?: string | null;
  /** Where to send a reader who wants to check the signature. */
  origin: string;
}

const rec = (v: unknown): Record<string, unknown> => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const str = (v: unknown) => (typeof v === "string" ? v : "");
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

/** One CSV cell. A cell that starts like a formula is prefixed so a spreadsheet shows it as text rather than running it. */
export function csvCell(value: unknown): string {
  let s = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
const csvRow = (cells: unknown[]) => cells.map(csvCell).join(",");

const oneLine = (s: string, max = 300) => {
  const t = s.replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ").replace(/\s+/g, " ").trim();
  return t.length > max ? `${t.slice(0, max - 1).trimEnd()}…` : t;
};

function findingsCsv(data: unknown): string {
  const vulns = Array.isArray(rec(data)["vulnerabilities"]) ? (rec(data)["vulnerabilities"] as unknown[]) : [];
  const rows = vulns.filter((v) => !isScanNote(v)).map(rec).sort((a, b) => SEV_ORDER.indexOf(str(a["severity"]).toLowerCase()) - SEV_ORDER.indexOf(str(b["severity"]).toLowerCase()));
  return [
    csvRow(["id", "severity", "name", "category", "cwe", "owasp_wstg", "cvss", "confidence", "description", "recommended_fix"]),
    ...rows.map((v) => csvRow([v["id"], v["severity"], v["name"], v["category"], v["cweId"], v["wstgId"], v["cvssScore"], v["confidence"], oneLine(str(v["description"]), 1000), oneLine(str(v["solution"]), 1000)])),
  ].join("\r\n") + "\r\n";
}

function coverageCsv(data: unknown): string {
  const tests = Array.isArray(rec(data)["tests"]) ? (rec(data)["tests"] as unknown[]).map(rec) : [];
  return [
    csvRow(["group", "test", "status", "findings", "reason"]),
    ...tests.map((t) => csvRow([t["group"], t["name"], t["status"], t["findings"], oneLine(str(t["reason"]), 500)])),
  ].join("\r\n") + "\r\n";
}

function summaryMd(input: PackInput): string {
  const s = summariseReport(input.data);
  const verified = scanRanVerified(input.data);
  const tests = Array.isArray(rec(input.data)["tests"]) ? (rec(input.data)["tests"] as unknown[]).map(rec) : [];
  const notRun = tests.filter((t) => t["status"] !== "ran");
  const vulns = (Array.isArray(rec(input.data)["vulnerabilities"]) ? (rec(input.data)["vulnerabilities"] as unknown[]) : []).filter((v) => !isScanNote(v)).map(rec);
  const top = vulns.filter((v) => ["critical", "high"].includes(str(v["severity"]).toLowerCase()));
  const f = s.findings;
  return [
    `# Security scan evidence: ${oneLine(input.targetUrl, 200)}`,
    "",
    ...(input.preparedFor ? [`Prepared for **${oneLine(input.preparedFor, 120)}**.`, ""] : []),
    "| | |",
    "|---|---|",
    `| Site | ${oneLine(input.targetUrl, 200)} |`,
    `| Scanned | ${input.scannedAt.toISOString()} |`,
    `| Scan type | ${oneLine(input.tier, 40)} |`,
    `| Grade | ${s.grade ?? "not recorded"}${s.riskScore != null ? ` (risk score ${s.riskScore}/100)` : ""} |`,
    `| Active tests | ${verified ? "Ran: the site's owner verified the domain" : "Did not run: the domain was not verified, so the grade covers passive checks only"} |`,
    `| Report | ${input.origin}/report/${input.reportId} |`,
    "",
    "## Findings",
    "",
    f
      ? `${f.total} finding${f.total === 1 ? "" : "s"}: ${SEV_ORDER.map((k) => `${f[k as keyof typeof f]} ${k}`).join(", ")}.`
      : "The report does not record a findings count.",
    ...(top.length ? ["", "Critical and high:", ...top.map((v) => `- **${str(v["severity"])}**: ${oneLine(str(v["name"]), 160)}`)] : []),
    "",
    "## What was and was not tested",
    "",
    s.coverage ? `${s.coverage.ran} of ${s.coverage.total} tests ran; ${s.coverage.skipped} skipped; ${s.coverage.failed} failed.` : "The report does not record test coverage.",
    ...(notRun.length ? ["", "Not tested on this scan. Never read these areas as safe:", ...notRun.map((t) => `- ${oneLine(str(t["name"]), 120)}: ${t["status"] === "failed" ? "failed to run" : oneLine(str(t["reason"]) || "skipped", 200)}`)] : []),
    "",
    "## What this is, and is not",
    "",
    "This is a record of one automated scan at the time shown. It is not a certification or an audit, and a clean result means the tests that ran found nothing, not that nothing is wrong. Findings can change the next day.",
    "",
    "## Files in this pack",
    "",
    "- `report.json`: the full report as stored.",
    "- `report.sarif.json`: the findings in SARIF 2.1.0, for code-scanning tools.",
    "- `findings.csv`: one row per finding.",
    "- `coverage.csv`: every test, and whether it ran.",
    "- `MANIFEST.json` and `MANIFEST.sha256`: the SHA-256 of each file above.",
    "- `SIGNATURE.json`: SecScan's signature over the manifest.",
    "",
  ].join("\n");
}

function readme(input: PackInput, manifestSha256: string, signed: boolean): string {
  return [
    "SecScan evidence pack",
    "=====================",
    "",
    `Report:  ${input.origin}/report/${input.reportId}`,
    `Site:    ${oneLine(input.targetUrl, 200)}`,
    `Scanned: ${input.scannedAt.toISOString()}`,
    "",
    "Start with summary.md.",
    "",
    "Checking that nothing was changed",
    "---------------------------------",
    "1. Check each file against the manifest:  sha256sum -c MANIFEST.sha256",
    `2. The manifest's own SHA-256 is:         ${manifestSha256}`,
    signed
      ? `3. Ask SecScan whether it issued that manifest: POST ${input.origin}/api/evidence/verify with the manifestSha256 and signature from SIGNATURE.json. Only SecScan can check the signature; it shows SecScan issued this manifest and that it has not been edited since. It says nothing about whether the findings are complete.`
      : "3. This pack was made without a signature: the server had no signing key. Steps 1 and 2 still show the files match the manifest.",
    "",
  ].join("\n");
}

export interface EvidencePack {
  filename: string;
  bytes: Buffer;
  manifestSha256: string;
  signed: boolean;
}

export function buildEvidencePack(input: PackInput): EvidencePack {
  const sarif = toSarif({ targetUrl: input.targetUrl, scannedAt: input.scannedAt, data: input.data as never });
  const body: ZipEntry[] = [
    { name: "summary.md", data: Buffer.from(summaryMd(input), "utf8") },
    { name: "report.json", data: Buffer.from(JSON.stringify(input.data, null, 2), "utf8") },
    { name: "report.sarif.json", data: Buffer.from(JSON.stringify(sarif, null, 2), "utf8") },
    { name: "findings.csv", data: Buffer.from(findingsCsv(input.data), "utf8") },
    { name: "coverage.csv", data: Buffer.from(coverageCsv(input.data), "utf8") },
  ];

  const manifest = {
    generatedBy: "SecScan",
    version: 1,
    reportId: input.reportId,
    targetUrl: input.targetUrl,
    scannedAt: input.scannedAt.toISOString(),
    files: body.map((e) => ({ name: e.name, sha256: sha256Hex(e.data), bytes: e.data.length })),
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2), "utf8");
  const manifestSha256 = sha256Hex(manifestBytes);
  const signature = signManifest(manifestSha256);

  const files: ZipEntry[] = [
    ...body,
    { name: "MANIFEST.json", data: manifestBytes },
    // sha256sum's format, so `sha256sum -c MANIFEST.sha256` works as it is.
    { name: "MANIFEST.sha256", data: Buffer.from(manifest.files.map((f) => `${f.sha256}  ${f.name}`).join("\n") + "\n", "utf8") },
    { name: "SIGNATURE.json", data: Buffer.from(JSON.stringify({ version: SIGNATURE_VERSION, manifestSha256, signature, issuedBy: "SecScan", verifyAt: `${input.origin}/api/evidence/verify` }, null, 2), "utf8") },
    { name: "README.txt", data: Buffer.from(readme(input, manifestSha256, signature !== null), "utf8") },
  ];

  let host = "report";
  try { host = new URL(input.targetUrl).hostname.replace(/[^A-Za-z0-9.-]/g, "-"); } catch { /* keep the generic name */ }
  return {
    filename: `secscan-evidence-${host}-${input.scannedAt.toISOString().slice(0, 10)}.zip`,
    bytes: zip(files, input.scannedAt),
    manifestSha256,
    signed: signature !== null,
  };
}
