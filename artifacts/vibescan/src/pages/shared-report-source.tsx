/** The source-code section of a report: which repository was read, how much of it, and what each check found. */
import { CheckCircle2, AlertTriangle, MinusCircle, GitBranch } from "lucide-react";
import { SeverityBadge } from "./learn-parts";
import { isCoverageTest, type CoverageTest } from "./shared-report-coverage";
import type { Severity } from "./learn-types";

/** The name the scanner records the repository scan under (one record for all five of its checks). */
export const SOURCE_TEST_NAME = "GitHub source code secrets";

export interface SourceCheck { name: string; files: number; findings: number; note?: string }

export interface SourceRecord {
  repository: string;
  via?: "public" | "github-app";
  treeFiles?: number;
  chosen?: number;
  read?: number;
  bytesRead?: number;
  leftOut?: number;
  /** Files left alone on purpose: binary files, and folders that are not the project's own. */
  notRead?: { binary: number; vendored: number };
  tooLarge?: number;
  failedReads?: number;
  truncatedTree?: boolean;
  checks?: SourceCheck[];
}

export interface SourceFinding { name: string; severity: string; evidence?: string | null }

/** The repository test's record, or null when the scan was not given a repository (then there is no section). */
export function sourceTestOf(tests: unknown): (CoverageTest & { source?: SourceRecord }) | null {
  const list = Array.isArray(tests) ? tests.filter(isCoverageTest) : [];
  const t = list.find((x) => x.name === SOURCE_TEST_NAME) as (CoverageTest & { source?: SourceRecord }) | undefined;
  if (!t) return null;
  // No repository was given (or what was given is not one GitHub names): nothing to show. A repository that was
  // given and not read, on a scan from before the record kept its name, is still worth saying so about.
  if (t.status === "skipped" && !t.source && /no repository was supplied|recognisable GitHub repository/.test(t.reason ?? "")) return null;
  return t;
}

/** Findings that were read from the repository's files: they all say "Repository: owner/repo" first. */
/** Findings listed in the report's side card; the rest are in the findings list. A card as long as the report is slow to paint. */
export const SIDEBAR_FINDINGS = 12;
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** The first `max` findings by severity, keeping the order the scan gave within a severity. */
export function mostSevere<T extends { severity?: unknown }>(list: readonly T[], max: number): T[] {
  return list
    .map((v, i) => ({ v, i }))
    .sort((a, b) => (SEVERITY_RANK[String(a.v.severity)] ?? 5) - (SEVERITY_RANK[String(b.v.severity)] ?? 5) || a.i - b.i)
    .slice(0, max)
    .map((x) => x.v);
}

export function repoFindingsOf<T extends SourceFinding>(vulns: readonly T[] | null | undefined): T[] {
  return (vulns ?? []).filter((v) => typeof v.evidence === "string" && v.evidence.startsWith("Repository: "));
}

/** "supabase/migrations/0001.sql" from an evidence block's "File:" line. */
export function findingFile(evidence: string | null | undefined): string | null {
  const m = /^File: (.+)$/m.exec(evidence ?? "");
  return m?.[1] ?? null;
}

/** Whether the scan could not read all of the repository, so a clean result covers only part of it. */
export function isPartial(s: SourceRecord): boolean {
  return Boolean(s.truncatedTree) || (s.leftOut ?? 0) > 0 || (s.tooLarge ?? 0) > 0 || (s.failedReads ?? 0) > 0;
}

const mb = (bytes: number) => (bytes >= 100_000 ? `${(bytes / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1000))} KB`);

/** One sentence on how much was read. */
export function readSummary(s: SourceRecord): string {
  const read = s.read ?? 0;
  const of = s.treeFiles != null ? ` of ${s.treeFiles} in the repository` : "";
  const size = s.bytesRead != null ? ` (${mb(s.bytesRead)})` : "";
  const left =
    s.notRead && s.notRead.binary + s.notRead.vendored > 0
      ? ` Left alone on purpose: ${s.notRead.binary} binary file${s.notRead.binary === 1 ? "" : "s"} (images, fonts, archives), ${s.notRead.vendored} in vendored or fixture folders (node_modules, dist, build, fixtures).`
      : "";
  return `Read ${read} file${read === 1 ? "" : "s"}${size}${of}.${left}`;
}

/** What was left unread, as short phrases; empty when the whole selection was read. */
export function partialNotes(s: SourceRecord): string[] {
  return [
    ...((s.leftOut ?? 0) > 0 ? [`${s.leftOut} left out by the file and size limits`] : []),
    ...((s.tooLarge ?? 0) > 0 ? [`${s.tooLarge} over the per-file size limit`] : []),
    ...((s.failedReads ?? 0) > 0 ? [`${s.failedReads} could not be downloaded`] : []),
    ...(s.truncatedTree ? ["GitHub cut the repository's file list short"] : []),
  ];
}

const how = (via?: SourceRecord["via"]) => (via === "github-app" ? "Read through the GitHub App you connected" : "Read as a public repository");

/** A scan from before the report kept what the repository scan read: it ran, but how much is unknown. */
export const NOT_RECORDED = "The repository check ran, but what it read was not recorded for this scan (it ran before reports kept that). Scan again to see which files were read.";

const STATUS_HINT =
  "This is a read of the repository's source files for secrets, database rules, CI settings, risky code patterns and vulnerable dependencies. It is not a full code review.";

export function SourceCodeCard({ tests, vulnerabilities }: { tests?: unknown; vulnerabilities?: readonly SourceFinding[] | null }) {
  const t = sourceTestOf(tests);
  if (!t) return null;
  const s = t.source;
  const findings = repoFindingsOf(vulnerabilities).filter((v) => v.name !== "GitHub source scan covered only part of the repository");
  const repo = s?.repository;

  return (
    <div className="glass-card rounded-2xl p-6" id="source-code">
      <div className="flex items-center gap-2 mb-1">
        <GitBranch className="w-4 h-4 text-primary" aria-hidden="true" />
        <h3 className="text-lg font-bold">Source code</h3>
      </div>
      {repo && (
        <p className="text-sm text-muted-foreground mb-3">
          <a href={`https://github.com/${repo}`} target="_blank" rel="noopener noreferrer" className="font-mono text-primary hover:underline">
            {repo}
          </a>
          {t.status === "ran" && s?.via && <> · {how(s.via)}</>}
        </p>
      )}

      {t.status !== "ran" ? (
        <div className="flex items-start gap-2 text-sm">
          {t.status === "failed" ? (
            <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-amber-400" aria-hidden="true" />
          ) : (
            <MinusCircle className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" aria-hidden="true" />
          )}
          <span>
            <span className="font-medium">The repository was not read.</span>
            <span className="block text-xs text-muted-foreground">
              {t.status === "failed" ? `The scan could not read it${t.reason ? `: ${t.reason}` : ""}.` : (t.reason ?? "Skipped.")} A clean result says nothing
              about this code.
            </span>
          </span>
        </div>
      ) : (
        <>
          {s ? <p className="text-sm text-foreground mb-3">{readSummary(s)}</p> : <p className="text-sm text-amber-300/90 mb-3">{NOT_RECORDED}</p>}

          {s?.checks && s.checks.length > 0 && (
            <ul className="space-y-1.5 mb-4">
              {s.checks.map((c) => (
                <li key={c.name} className="text-sm flex items-start gap-2">
                  {c.files === 0 ? (
                    <MinusCircle className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                  ) : c.findings > 0 ? (
                    <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-amber-400" aria-hidden="true" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0 text-green-400" aria-hidden="true" />
                  )}
                  <span className="flex-1 min-w-0">
                    <span className="font-medium">{c.name}</span>
                    <span className="block text-xs text-muted-foreground">
                      {c.files === 0
                        ? (c.note ?? "nothing of this kind to read")
                        : `${c.files} file${c.files === 1 ? "" : "s"} read · ${c.findings} finding${c.findings === 1 ? "" : "s"}${c.note ? ` · ${c.note}` : ""}`}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          )}

          {findings.length > 0 ? (
            <div className="mb-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                Found in the repository ({findings.length})
              </p>
              <ul className="space-y-2">
                {mostSevere(findings, SIDEBAR_FINDINGS).map((v, i) => (
                  <li key={`${v.name}-${i}`} className="text-sm flex items-start gap-2">
                    <SeverityBadge severity={(v.severity as Severity) ?? "info"} />
                    <span className="flex-1 min-w-0 break-words">
                      <span className="font-medium">{v.name}</span>
                      {findingFile(v.evidence) && <span className="block text-xs font-mono text-muted-foreground">{findingFile(v.evidence)}</span>}
                    </span>
                  </li>
                ))}
                {findings.length > SIDEBAR_FINDINGS && (
                  <li className="text-xs text-muted-foreground">…and {findings.length - SIDEBAR_FINDINGS} more, the least severe, in the findings list.</li>
                )}
              </ul>
              <p className="text-xs text-muted-foreground mt-2">Each is in the findings list with its evidence and the fix.</p>
            </div>
          ) : s ? (
            <p className="text-sm flex items-start gap-2 mb-3">
              <CheckCircle2 className="w-4 h-4 mt-0.5 shrink-0 text-green-400" aria-hidden="true" />
              <span>Nothing was found in the files that were read.</span>
            </p>
          ) : null}

          {s && isPartial(s) && (
            <p className="text-xs text-amber-300/90 leading-relaxed mb-2">
              Not everything could be read: {partialNotes(s).join("; ")}. A clean result covers only the files that were read.
            </p>
          )}
          <p className="text-xs text-muted-foreground/80 leading-relaxed">{STATUS_HINT}</p>
        </>
      )}
    </div>
  );
}

/** Print and PDF form: plain, light-on-white, nothing collapsed. */
export function PrintSourceCode({ tests, vulnerabilities }: { tests?: unknown; vulnerabilities?: readonly SourceFinding[] | null }) {
  const t = sourceTestOf(tests);
  if (!t) return null;
  const s = t.source;
  const findings = repoFindingsOf(vulnerabilities).filter((v) => v.name !== "GitHub source scan covered only part of the repository");
  return (
    <div className="mb-8 pt-6 border-t-2 border-gray-200">
      <h2 className="text-lg font-bold mb-2 text-gray-900">Source code{s?.repository ? `: ${s.repository}` : ""}</h2>
      {t.status !== "ran" ? (
        <p className="text-gray-700 text-sm">
          The repository was not read{t.reason ? ` (${t.reason})` : ""}. A clean result says nothing about this code.
        </p>
      ) : (
        <>
          {s ? <p className="text-gray-700 text-sm mb-2">{readSummary(s)} {how(s.via)}.</p> : <p className="text-gray-700 text-sm mb-2">{NOT_RECORDED}</p>}
          {s?.checks && (
            <ul className="space-y-1 mb-2">
              {s.checks.map((c) => (
                <li key={c.name} className="text-gray-700 text-sm">
                  <strong>{c.name}</strong>
                  <span className="text-gray-500">
                    {" — "}
                    {c.files === 0 ? (c.note ?? "nothing of this kind to read") : `${c.files} file${c.files === 1 ? "" : "s"}, ${c.findings} finding${c.findings === 1 ? "" : "s"}`}
                  </span>
                </li>
              ))}
            </ul>
          )}
          <p className="text-gray-700 text-sm">
            {findings.length > 0
              ? `${findings.length} finding${findings.length === 1 ? "" : "s"} from the repository: ${findings.map((v) => v.name).join("; ")}.`
              : s ? "Nothing was found in the files that were read." : ""}
          </p>
          {s && isPartial(s) && <p className="text-xs text-gray-500 mt-1">Not everything could be read: {partialNotes(s).join("; ")}.</p>}
        </>
      )}
    </div>
  );
}

/** The same section as markdown lines for the copied report. Empty when the scan had no repository. */
export function sourceCodeMarkdown(tests: unknown, vulnerabilities?: readonly SourceFinding[] | null): string[] {
  const t = sourceTestOf(tests);
  if (!t) return [];
  const s = t.source;
  const findings = repoFindingsOf(vulnerabilities).filter((v) => v.name !== "GitHub source scan covered only part of the repository");
  const out = [`## Source code${s?.repository ? `: ${s.repository}` : ""}`, ""];
  if (t.status !== "ran") {
    out.push(`The repository was not read${t.reason ? ` — ${t.reason}` : ""}. A clean result says nothing about this code.`, "");
    return out;
  }
  out.push(s ? `${readSummary(s)} ${how(s.via)}.` : NOT_RECORDED, "");
  for (const c of s?.checks ?? []) {
    out.push(`- ${c.name}: ${c.files === 0 ? (c.note ?? "nothing of this kind to read") : `${c.files} file${c.files === 1 ? "" : "s"} read, ${c.findings} finding${c.findings === 1 ? "" : "s"}`}`);
  }
  if ((s?.checks ?? []).length > 0) out.push("");
  out.push(
    findings.length > 0
      ? `Found in the repository: ${findings.map((v) => `${v.name}${findingFile(v.evidence) ? ` (${findingFile(v.evidence)})` : ""}`).join("; ")}.`
      : s ? "Nothing was found in the files that were read." : "",
    "",
  );
  if (s && isPartial(s)) out.push(`Not everything could be read: ${partialNotes(s).join("; ")}. A clean result covers only the files that were read.`, "");
  return out;
}
