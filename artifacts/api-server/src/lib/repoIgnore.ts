/**
 * `.secscanignore`: the owner's way to say "I have looked at this, it is not a problem here".
 *
 * A scanner that cannot be told when it is wrong gets switched off. This is that voice, and it is deliberately narrow and
 * visible: it lives in the repository (so it is reviewed like code and has history), it is read only from the repository
 * root, and every finding it removes is counted and named in the report (suppressedNotice), so a suppression can be seen,
 * questioned and removed. It never hides that it ran.
 *
 * One rule per line; blank lines and lines starting with # are ignored.
 *
 *   path/or/glob            findings whose every file matches (gitignore-style: *, **, ?, a leading /, a trailing /)
 *   rule: some name         findings whose name contains the text (case-insensitive)
 *   rule: some name @ glob  both at once: that rule, in those files
 *
 * A finding with no file (a coverage note) is never suppressed.
 */
import { repoFinding, type RepoRef } from "./repoFinding";
import type { ScanVulnerability } from "./scanner";

export const IGNORE_FILE = ".secscanignore";

export interface IgnoreRule { source: string; name?: string; path?: RegExp }

/** gitignore-style glob to a regular expression. */
export function globToRegExp(glob: string): RegExp {
  let g = glob.trim();
  const anchored = g.startsWith("/");
  if (anchored) g = g.slice(1);
  const dirOnly = g.endsWith("/");
  if (dirOnly) g = g.slice(0, -1);
  let re = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i]!;
    if (c === "*") {
      if (g[i + 1] === "*") { re += ".*"; i++; if (g[i + 1] === "/") i++; } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  // Without a slash it matches at any depth (like .gitignore); a trailing slash or none, it also covers everything below.
  const prefix = anchored || g.includes("/") ? "^" : "(?:^|.*/)";
  return new RegExp(`${prefix}${re}${dirOnly ? "/.*" : "(?:/.*)?"}$`);
}

export function parseIgnore(content: string): IgnoreRule[] {
  const rules: IgnoreRule[] = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const rule = /^rule\s*:\s*(.+?)(?:\s+@\s+(\S+))?$/i.exec(line);
    if (rule) rules.push({ source: line, name: rule[1]!.trim().toLowerCase(), ...(rule[2] ? { path: globToRegExp(rule[2]) } : {}) });
    else rules.push({ source: line, path: globToRegExp(line) });
  }
  return rules;
}

const filesIn = (v: ScanVulnerability): string[] => [...new Set([...(v.evidence ?? "").matchAll(/^File: (.+?)(?: \(line \d+\))?$/gm)].map((m) => m[1]!.trim()))];

function matches(rule: IgnoreRule, v: ScanVulnerability): boolean {
  if (rule.name && !v.name.toLowerCase().includes(rule.name)) return false;
  if (rule.path) {
    const files = filesIn(v);
    if (files.length === 0 || !files.every((f) => rule.path!.test(f))) return false;
  }
  return Boolean(rule.name || rule.path);
}

export function applyIgnore(findings: ScanVulnerability[], rules: IgnoreRule[]): { kept: ScanVulnerability[]; suppressed: Array<{ finding: ScanVulnerability; rule: IgnoreRule }> } {
  if (rules.length === 0) return { kept: findings, suppressed: [] };
  const kept: ScanVulnerability[] = [];
  const suppressed: Array<{ finding: ScanVulnerability; rule: IgnoreRule }> = [];
  for (const v of findings) {
    const rule = v.category === "Scan Coverage" ? undefined : rules.find((r) => matches(r, v));
    if (rule) suppressed.push({ finding: v, rule });
    else kept.push(v);
  }
  return { kept, suppressed };
}

/** The report's record of what was suppressed, by which rule: a suppression must be visible. */
export function suppressedNotice(suppressed: Array<{ finding: ScanVulnerability; rule: IgnoreRule }>, ref: RepoRef): ScanVulnerability | null {
  if (suppressed.length === 0) return null;
  const byRule = new Map<string, Map<string, number>>();
  for (const { finding, rule } of suppressed) {
    const names = byRule.get(rule.source) ?? new Map<string, number>();
    names.set(finding.name, (names.get(finding.name) ?? 0) + 1);
    byRule.set(rule.source, names);
  }
  const detail = [...byRule.entries()].slice(0, 15).map(([rule, names]) => `${rule}  ->  ${[...names.entries()].slice(0, 4).map(([n, c]) => `${n}${c > 1 ? ` x${c}` : ""}`).join("; ")}`).join("\n");
  return repoFinding({
    ref, path: IGNORE_FILE, name: `${suppressed.length} finding${suppressed.length === 1 ? "" : "s"} suppressed by ${IGNORE_FILE}`,
    severity: "info", category: "Scan Coverage", cweId: null, cvssScore: 0, confidence: 100,
    description: `The repository's ${IGNORE_FILE} tells the scanner to leave ${suppressed.length === 1 ? "one finding" : `${suppressed.length} findings`} out of this report. They were found and then removed on the owner's instruction. This note is here so a suppression can be seen and reviewed; delete the rule to bring a finding back.`,
    detail,
    solution: `Review ${IGNORE_FILE} from time to time: a rule that was right when written can hide a real problem later.`,
  });
}
