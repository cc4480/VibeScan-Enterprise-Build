/** The two information notes a scan adds about its own coverage: a render that was set aside, and check groups that did not run. */
import { vuln, type ScanVulnerability } from "./scannerTypes";

export function coverageNotes(renderRejected: string | undefined, unrunFamilies: string[]): ScanVulnerability[] {
  const notes: ScanVulnerability[] = [];
  if (renderRejected) {
    notes.push(vuln({
      name: "Browser Rendering Was Not Used",
      severity: "info",
      category: "Scan Coverage",
      description:
        "This page looks like a JavaScript app, so the scan tried to load it in a headless browser, but " +
        `${renderRejected}. The scan used the page as the plain request received it instead. This is not a finding about your site. ` +
        "Anything that only appears after the page's scripts run (bundled secrets, calls the page makes at runtime) may not have been seen, so re-run before treating a clean result there as meaningful.",
      evidence: renderRejected,
      solution: "If a bot-protection rule treats headless browsers differently, allow the scanner's User-Agent, then re-run the scan.",
      confidence: 100,
    }));
  }

  if (unrunFamilies.length > 0) {
    notes.push(vuln({
      name: `${unrunFamilies.length} check group${unrunFamilies.length > 1 ? "s" : ""} could not be completed`,
      severity: "info",
      category: "Scan Coverage",
      description:
        `${unrunFamilies.length} group${unrunFamilies.length > 1 ? "s" : ""} of checks failed to run on this scan — a network error, a timeout, or an internal fault. ` +
        `This is not a finding about your site, and it does not mean anything is wrong with it. It is here because the alternative is worse: ` +
        `a check group that dies silently returns nothing, which looks exactly like a check group that ran and found nothing. ` +
        `Anything those groups would have caught is simply unknown for this scan, so re-run it before treating a clean result in these areas as meaningful.`,
      evidence: `Not completed:\n${unrunFamilies.map((f) => `  • ${f}`).join("\n")}`,
      solution:
        "Re-run the scan. If the same group fails repeatedly, the target may be rate-limiting or blocking the scanner, or the check has a genuine fault worth reporting to us.",
      confidence: 100,
    }));
  }

  return notes;
}
