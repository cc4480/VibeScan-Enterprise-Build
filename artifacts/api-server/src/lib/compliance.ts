/**
 * Compliance mapping: which control each finding is EVIDENCE FOR.
 *
 * ── Read this before using any of it in a report or a sales deck ──
 *
 * This module maps findings to control identifiers. It does NOT determine
 * compliance, and nothing here may be presented as though it does. The
 * distinction is not pedantry — it is the difference between a useful artifact
 * and a misleading one:
 *
 *  • A scanner sees one thing: the HTTP surface of a running application at one
 *    moment. SOC 2 and ISO 27001 are overwhelmingly about things it cannot see —
 *    written policy, personnel screening, change management, vendor review,
 *    incident response, physical security, access reviews. The majority of every
 *    framework below is invisible to any scan.
 *  • So a clean scan is NOT a passed control, and a finding is NOT a failed
 *    audit. A finding is evidence an auditor can weigh; its absence is the
 *    absence of that particular evidence, nothing more.
 *  • Only a licensed CPA firm issues a SOC 2 report. Only a QSA signs off PCI
 *    DSS. Only an accredited body certifies ISO 27001. This file makes none of
 *    those claims and neither may any UI built on it.
 *
 * What it IS good for: an auditor or a customer's security reviewer asking
 * "show me you test for injection" can be handed the findings mapped to
 * PCI DSS 6.2.4 and ASVS V5, which is real, checkable work. That is the value,
 * and overstating it would destroy it.
 *
 * ── Why CWE is the primary key ──
 * 302 of the scanner's findings already carry a cweId, assigned per-check by the
 * author of that check. Mapping from a stable identifier beats re-deriving
 * meaning from a title with regexes, which is how the OWASP mapper works and why
 * it needs "order matters (most specific first)" comments to stay correct.
 * `category` is the fallback for the minority of findings with no CWE.
 *
 * (NIST SP 800-53 and the HIPAA Security Rule are mapped in complianceExtra.ts.)
 *
 * Framework versions are pinned in FRAMEWORKS so a report can state which
 * revision it mapped against — control numbering changes between revisions, and
 * an unversioned control reference is not checkable.
 */

import { EXTRA_FRAMEWORKS, extraControlsForFinding } from "./complianceExtra";
import { CWE_CONTROLS_INJECTION_SECRETS } from "./complianceCwe";
import { CWE_CONTROLS_INFRASTRUCTURE } from "./complianceCweInfra";

export interface FrameworkMeta {
  id: string;
  name: string;
  version: string;
  /** What a mapped finding means for this framework, in the report's own words. */
  note: string;
}

export const FRAMEWORKS: Record<string, FrameworkMeta> = {
  ...EXTRA_FRAMEWORKS,
  soc2: {
    id: "soc2",
    name: "SOC 2",
    version: "2017 TSC (rev. 2022)",
    note:
      "Trust Services Criteria. Most criteria cover policy, personnel and process that no scan can observe; " +
      "these findings are technical evidence for the subset an application scan can speak to.",
  },
  pci: {
    id: "pci",
    name: "PCI DSS",
    version: "4.0.1",
    note:
      "Applies only if the environment stores, processes or transmits cardholder data. " +
      "Requirement 11.3.2 expects external vulnerability scanning by an ASV; this scan is not an ASV scan.",
  },
  iso27001: {
    id: "iso27001",
    name: "ISO/IEC 27001",
    version: "2022 Annex A",
    note:
      "Annex A controls. Certification is granted by an accredited body against the management system as a whole, " +
      "not against a scan result.",
  },
  asvs: {
    id: "asvs",
    name: "OWASP ASVS",
    version: "4.0.3",
    note:
      "Application Security Verification Standard — the framework here designed for exactly this kind of testing, " +
      "so the mapping is tightest and the coverage most meaningful.",
  },
};

export interface ControlRef {
  framework: keyof typeof FRAMEWORKS;
  /** The control identifier as the framework itself numbers it. */
  control: string;
  title: string;
}

/**
 * CWE → controls. Each entry says "a finding of this weakness class is evidence
 * relevant to these controls".
 *
 * Kept deliberately conservative: a weakness is listed against a control only
 * where the control actually speaks to it. Padding the mapping so every finding
 * touches every framework would make the report look thorough and be useless —
 * an auditor checks a sample, and a stretched mapping fails on the first check.
 */
const CWE_CONTROLS: Record<string, ControlRef[]> = {
  ...CWE_CONTROLS_INJECTION_SECRETS,
  ...CWE_CONTROLS_INFRASTRUCTURE,
};

/**
 * Category → controls, for findings with no CWE.
 *
 * Coarser than the CWE map by nature, so entries stay at the level the category
 * genuinely supports rather than guessing at a specific control.
 */
const CATEGORY_CONTROLS: Record<string, ControlRef[]> = {
  "Email Security": [
    { framework: "asvs", control: "V14.4.1", title: "Domain security configuration" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
  ],
  "Mail Transport Security": [
    { framework: "pci", control: "4.2.1", title: "Strong cryptography during transmission" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography" },
  ],
  "DNS Security": [
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
  ],
  "CVE / Known Vulnerability": [
    { framework: "asvs", control: "V14.2.1", title: "Dependencies free of known vulnerabilities" },
    { framework: "pci", control: "6.3.3", title: "Third-party components patched" },
    { framework: "iso27001", control: "A.8.8", title: "Management of technical vulnerabilities" },
  ],
  "Outdated Software": [
    { framework: "pci", control: "6.3.3", title: "Third-party components patched" },
    { framework: "iso27001", control: "A.8.8", title: "Management of technical vulnerabilities" },
  ],
  "Supply Chain Security": [
    { framework: "asvs", control: "V14.2.3", title: "Third-party assets integrity-checked" },
    { framework: "iso27001", control: "A.5.21", title: "Managing ICT supply chain security" },
  ],
  "Network Exposure": [
    { framework: "pci", control: "1.4.1", title: "Network controls restrict untrusted traffic" },
    { framework: "iso27001", control: "A.8.20", title: "Network security" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],
  "Database Security": [
    { framework: "pci", control: "7.2.1", title: "Access assigned by need-to-know" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],
  "BaaS Misconfiguration": [
    { framework: "asvs", control: "V4.1.1", title: "Access control enforced server-side" },
    { framework: "iso27001", control: "A.5.15", title: "Access control" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],
  "Cloud Storage Misconfiguration": [
    { framework: "iso27001", control: "A.5.15", title: "Access control" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],
};

/**
 * The controls a finding is evidence for. Empty when nothing maps — an honest
 * empty list beats inventing a control reference to fill the column.
 */
export function controlsForFinding(finding: {
  cweId?: string | null;
  category?: string | null;
}): ControlRef[] {
  const byCwe = finding.cweId ? CWE_CONTROLS[finding.cweId] : undefined;
  const base = byCwe?.length ? byCwe : ((finding.category ? CATEGORY_CONTROLS[finding.category] : undefined) ?? []);
  return [...base, ...extraControlsForFinding(finding, Boolean(byCwe?.length))];
}

export interface FrameworkCoverage {
  framework: FrameworkMeta;
  /** Controls this scan produced findings against, with how many. */
  controls: Array<{ control: string; title: string; findings: number }>;
}

/**
 * Group a scan's findings by framework and control.
 *
 * Reports "controls with findings against them". It deliberately does NOT
 * report a pass rate or a percentage: the denominator would have to be the
 * framework's full control set, most of which no scan can assess, and any
 * percentage derived from that is a fabrication that reads as an audit score.
 */
export function summariseCompliance(
  findings: Array<{ cweId?: string | null; category?: string | null }>,
): FrameworkCoverage[] {
  const acc = new Map<string, Map<string, { title: string; findings: number }>>();

  for (const f of findings) {
    for (const ref of controlsForFinding(f)) {
      if (!acc.has(ref.framework)) acc.set(ref.framework, new Map());
      const controls = acc.get(ref.framework)!;
      const existing = controls.get(ref.control);
      if (existing) existing.findings++;
      else controls.set(ref.control, { title: ref.title, findings: 1 });
    }
  }

  return [...acc.entries()]
    .map(([fw, controls]) => ({
      framework: FRAMEWORKS[fw]!,
      controls: [...controls.entries()]
        .map(([control, v]) => ({ control, title: v.title, findings: v.findings }))
        .sort((a, b) => b.findings - a.findings || a.control.localeCompare(b.control)),
    }))
    .sort((a, b) => a.framework.name.localeCompare(b.framework.name));
}

/**
 * The sentence any compliance view must carry. Exported so it cannot drift
 * between the report, the PDF and the API — and so removing it is a visible,
 * deliberate act rather than an oversight.
 */
export const COMPLIANCE_DISCLAIMER =
  "This mapping shows which controls these findings are evidence for. It is not a compliance " +
  "assessment, an audit, or an attestation. An application scan observes the HTTP surface of a " +
  "running system at one point in time; SOC 2, PCI DSS and ISO 27001 are largely concerned with " +
  "policy, process and personnel that no scan can see. A clean scan is not a passed control. " +
  "Only a licensed CPA firm issues a SOC 2 report, only a QSA validates PCI DSS, and only an " +
  "accredited certification body certifies ISO 27001.";
