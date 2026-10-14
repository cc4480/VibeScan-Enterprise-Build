/** Copy the report as Markdown. */
import { Copy, Check } from "lucide-react";
import { useState } from "react";
import type { Vulnerability } from "@workspace/api-client-react";
import { APP_ORIGIN } from "@/lib/origin";
import { scanNotesMarkdown } from "@/lib/scan-notes";
import { coverageMarkdown, sourceCodeMarkdown, type CoverageTest } from "./shared-report-components";
import { withheldMarkdown, type Interception } from "./report-viewer-provenance";
import { SEVERITY_EMOJI, type ComplianceData } from "./report-viewer-data";

// ─── Copy report as markdown (for AI agents / no-code tools) ─────────────────

export interface ReportCopyData {
  targetUrl: string;
  scannedAt: string | Date;
  summary: { grade: string; riskScore: number; executiveSummary: string; critical: number; high: number; medium: number; low: number; info: number; totalVulnerabilities: number };
  confirmedVulns: Vulnerability[];
  unverifiedVulns: Vulnerability[];
  /** The scan's notes about itself, which are not findings (see lib/scan-notes.ts). */
  scanNotes?: Vulnerability[];
  technologies: string[];
  server?: string | null;
  tlsGrade?: string | null;
  aiAnalysis?: { overallRisk: string; topPriorities: string[]; quickWins: string[]; complianceNotes?: string | null } | null;
  compliance?: ComplianceData | null;
  tests?: CoverageTest[] | null;
  withheld?: unknown;
  interception?: Interception | null;
}

export function formatReportMarkdown(d: ReportCopyData): string {
  const dateStr = new Date(d.scannedAt).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });

  const fmtVuln = (v: Vulnerability, i: number) => {
    const emoji = SEVERITY_EMOJI[v.severity] ?? "•";
    const refs = [v.cweId, v.cvssScore != null ? `CVSS ${v.cvssScore.toFixed(1)}` : null, v.wstgId].filter(Boolean).join(" | ");
    return [
      `#### ${emoji} ${v.severity.toUpperCase()} — ${v.name}`,
      `**Category:** ${v.category}`,
      ``,
      `**Description:** ${v.description}`,
      ``,
      v.evidence ? `**Evidence:**\n\`\`\`\n${v.evidence}\n\`\`\`` : null,
      `**How to Fix:** ${v.solution}`,
      refs ? `\n**References:** ${refs}` : null,
      `\n---`,
    ].filter((l) => l !== null).join("\n");
  };

  const lines: string[] = [
    `# SecScan Security Report`,
    ``,
    `**Target:** ${d.targetUrl}`,
    `**Scanned:** ${dateStr}`,
    `**Security Grade:** ${d.summary.grade} | Risk Score: ${d.summary.riskScore}/100`,
    `**Total Findings:** ${d.summary.totalVulnerabilities}  (${d.summary.critical} critical · ${d.summary.high} high · ${d.summary.medium} medium · ${d.summary.low} low · ${d.summary.info} info)`,
    ``,
    `## Executive Summary`,
    ``,
    d.summary.executiveSummary,
    ``,
    ...sourceCodeMarkdown(d.tests, [...d.confirmedVulns, ...d.unverifiedVulns]),
    ...coverageMarkdown(d.tests),
    ...withheldMarkdown(d.withheld, d.interception),
  ];

  if (d.confirmedVulns.length > 0) {
    lines.push(`## ✅ Confirmed Findings (${d.confirmedVulns.length})`, ``);
    d.confirmedVulns.forEach((v, i) => { lines.push(fmtVuln(v, i + 1), ``); });
  }

  if (d.unverifiedVulns.length > 0) {
    lines.push(`## ⚠️ Needs Verification (${d.unverifiedVulns.length})`, ``);
    lines.push(`> These findings used heuristic detection — verify manually before acting.`, ``);
    d.unverifiedVulns.forEach((v, i) => { lines.push(fmtVuln(v, i + 1), ``); });
  }

  lines.push(...scanNotesMarkdown(d.scanNotes ?? [], d.confirmedVulns.length + d.unverifiedVulns.length > 0, fmtVuln));

  if (d.aiAnalysis) {
    lines.push(`## 🤖 AI Analysis`, ``);
    lines.push(`### Overall Risk`, ``, d.aiAnalysis.overallRisk, ``);
    if (d.aiAnalysis.topPriorities?.length) {
      lines.push(`### Top Priorities`, ``);
      d.aiAnalysis.topPriorities.forEach((p, i) => lines.push(`${i + 1}. ${p}`));
      lines.push(``);
    }
    if (d.aiAnalysis.quickWins?.length) {
      lines.push(`### Quick Wins`, ``);
      d.aiAnalysis.quickWins.forEach((w) => lines.push(`- ✓ ${w}`));
      lines.push(``);
    }
    if (d.aiAnalysis.complianceNotes) {
      lines.push(`### Compliance Notes`, ``, d.aiAnalysis.complianceNotes, ``);
    }
  }

  if (d.compliance && d.compliance.frameworks.length > 0) {
    lines.push(`## Compliance Mapping`, ``);
    lines.push(`Which findings are evidence for a recognised framework control — not a compliance verdict.`, ``);
    d.compliance.frameworks.forEach((fw) => {
      lines.push(`### ${fw.framework.name} (${fw.framework.version})`, ``);
      fw.controls.forEach((c) => {
        lines.push(`- \`${c.control}\` ${c.title} (${c.findings} finding${c.findings === 1 ? "" : "s"})`);
      });
      lines.push(``, `_${fw.framework.note}_`, ``);
    });
    lines.push(`> ${d.compliance.disclaimer}`, ``);
  }

  lines.push(`## 🖥️ Tech Profile`, ``);
  if (d.tlsGrade) lines.push(`- **TLS Grade:** ${d.tlsGrade}`);
  if (d.server) lines.push(`- **Server:** ${d.server}`);
  if (d.technologies.length) lines.push(`- **Technologies:** ${d.technologies.join(", ")}`);
  lines.push(``, `---`, `*Generated by SecScan — ${APP_ORIGIN}*`);

  return lines.join("\n");
}

export function CopyReportButton({ data }: { data: ReportCopyData }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const text = formatReportMarkdown(data);
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      prompt("Copy this report (Ctrl+A, Ctrl+C):", text);
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  return (
    <button
      onClick={handleCopy}
      className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary/10 border border-primary/30 text-sm font-medium text-primary hover:bg-primary/20 transition-colors"
      title="Copy the full report as markdown — paste into ChatGPT, Claude, Cursor, Lovable, or any AI tool to get tailored fix recommendations"
    >
      {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
      {copied ? "Copied!" : "Copy for AI"}
    </button>
  );
}
