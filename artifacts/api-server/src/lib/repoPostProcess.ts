/**
 * Shaping a repository scan's findings before they are reported, so the report says what matters and says it once.
 *
 *   softenSamplePaths  A finding whose every file is a test, an example or a document describes a sample, not the
 *                      project's shipped code: a migration under test/ with no RLS, a compose file in examples/. It is
 *                      kept, as information, under a name that says so.
 *   mergeSameName      A rule that fires in thirty files is one thing to fix, not thirty cards. Low and information
 *                      findings of one name become one, listing every file. Higher severities stay separate, because each
 *                      deserves its own look, and so do dependencies, which are one package each.
 */
import { asTestFileFinding, isTestOrExamplePath } from "./repoFinding";
import type { ScanVulnerability } from "./scanner";

const SOFTENED_NAME = /\((?:in a test or example file|a value that looks deliberately fake|looks like a development default)\)/;

/** The files a finding names ("File: path (line 12)"). */
const filesIn = (v: ScanVulnerability): string[] => [...new Set([...(v.evidence ?? "").matchAll(/^File: (.+?)(?: \(line \d+\))?$/gm)].map((m) => m[1]!.trim()))];

export function softenSamplePaths(findings: ScanVulnerability[]): ScanVulnerability[] {
  return findings.map((v) => {
    if (v.category === "Scan Coverage" || v.category === "Vulnerable Components" || SOFTENED_NAME.test(v.name) || v.severity === "info") return v;
    const files = filesIn(v);
    return files.length > 0 && files.every(isTestOrExamplePath) ? asTestFileFinding(v, "test-file") : v;
  });
}

const MAX_FILES_LISTED = 25;

function merge(group: ScanVulnerability[]): ScanVulnerability {
  const first = group[0]!;
  const header = /^Repository: .*$/m.exec(first.evidence ?? "")?.[0];
  const bodies = group.slice(0, MAX_FILES_LISTED).map((v) => (v.evidence ?? "").replace(/^Repository: .*\n?/m, "").trim());
  const more = group.length - bodies.length;
  const files = new Set(group.flatMap(filesIn)).size;
  return {
    ...first,
    description: `${first.description} It appears in ${files} file${files === 1 ? "" : "s"}; each is listed in the evidence.`,
    evidence: [header, bodies.join("\n---\n"), more > 0 ? `...and ${more} more` : ""].filter(Boolean).join("\n"),
  };
}

export function mergeSameName(findings: ScanVulnerability[]): ScanVulnerability[] {
  const key = (v: ScanVulnerability) => `${v.severity}|${v.name}`;
  const groups = new Map<string, ScanVulnerability[]>();
  const kept: ScanVulnerability[] = [];
  for (const v of findings) {
    const mergeable = (v.severity === "low" || v.severity === "info") && v.category !== "Vulnerable Components" && v.category !== "Scan Coverage" && (v.evidence ?? "").startsWith("Repository: ");
    if (!mergeable) { kept.push(v); continue; }
    const g = groups.get(key(v));
    if (g) g.push(v);
    else { groups.set(key(v), [v]); kept.push(v); }
  }
  return kept.map((v) => {
    const g = groups.get(key(v));
    return g && g.length > 1 && g[0] === v ? merge(g) : v;
  });
}
