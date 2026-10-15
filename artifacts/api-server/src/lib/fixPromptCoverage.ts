/**
 * The checklist that every AI fix prompt ends with: one line per finding in the report, most severe first, with the files
 * it is in. The model writes the prompt as a summary, so on a real scan it named only a few of the findings. This list is
 * built from the report itself, so every finding is in the prompt whatever the model chose to mention.
 */
import type { ScanVulnerability } from "./scanner";
import { filesOf } from "./fixPromptFallback";

const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function everyFindingChecklist(vulnerabilities: ScanVulnerability[]): string {
  const sorted = [...vulnerabilities].sort((a, b) => (RANK[a.severity] ?? 5) - (RANK[b.severity] ?? 5));
  return sorted
    .map((v) => {
      const { files, more } = filesOf(v);
      const where = files.length ? ` (${files.join(", ")}${more ? ` and ${more} more` : ""})` : "";
      return `- ${v.severity.toUpperCase()}: ${v.name}${where}`;
    })
    .join("\n");
}

/** The model's prompt, followed by the checklist of every finding. Unchanged when the report has no findings. */
export function withEveryFinding(prompt: string, vulnerabilities: ScanVulnerability[]): string {
  if (vulnerabilities.length === 0) return prompt;
  const head = prompt.trim() ? `${prompt.trimEnd()}\n\n` : "";
  return `${head}Every finding in this report, so none is missed (${vulnerabilities.length} in total; the ones marked INFO are information, check each before changing code):\n${everyFindingChecklist(vulnerabilities)}`;
}
