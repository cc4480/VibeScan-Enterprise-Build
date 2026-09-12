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
 * Framework versions are pinned in FRAMEWORKS so a report can state which
 * revision it mapped against — control numbering changes between revisions, and
 * an unversioned control reference is not checkable.
 */

export interface FrameworkMeta {
  id: string;
  name: string;
  version: string;
  /** What a mapped finding means for this framework, in the report's own words. */
  note: string;
}

export const FRAMEWORKS: Record<string, FrameworkMeta> = {
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
  // ── Injection ──────────────────────────────────────────────────────────────
  "CWE-89": [
    { framework: "asvs", control: "V5.3.4", title: "Parameterised database queries" },
    { framework: "pci", control: "6.2.4", title: "Software engineering techniques prevent injection attacks" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],
  "CWE-79": [
    { framework: "asvs", control: "V5.3.3", title: "Output encoding prevents cross-site scripting" },
    { framework: "pci", control: "6.2.4", title: "Software engineering techniques prevent injection attacks" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],
  "CWE-22": [
    { framework: "asvs", control: "V12.3.1", title: "File path traversal prevented" },
    { framework: "pci", control: "6.2.4", title: "Software engineering techniques prevent injection attacks" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
  ],
  "CWE-918": [
    { framework: "asvs", control: "V12.6.1", title: "Server-side request forgery protection" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],
  "CWE-601": [
    { framework: "asvs", control: "V5.5.1", title: "Redirects and forwards validated" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
  ],
  "CWE-915": [
    { framework: "asvs", control: "V5.1.2", title: "Mass assignment / parameter binding controlled" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
  ],
  "CWE-1395": [
    { framework: "asvs", control: "V14.2.1", title: "Dependencies free of known vulnerabilities" },
    { framework: "pci", control: "6.3.3", title: "Third-party components patched" },
    { framework: "iso27001", control: "A.8.8", title: "Management of technical vulnerabilities" },
  ],

  // ── Secrets and credentials ────────────────────────────────────────────────
  "CWE-798": [
    { framework: "asvs", control: "V6.4.1", title: "Secrets not embedded in code or client assets" },
    { framework: "pci", control: "8.3.1", title: "Strong authentication; credentials not hard-coded" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography — key management" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — credentials protected" },
  ],
  "CWE-312": [
    { framework: "asvs", control: "V6.1.1", title: "Sensitive data not stored in cleartext" },
    { framework: "pci", control: "3.5.1", title: "Stored account data rendered unreadable" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — credentials protected" },
  ],
  "CWE-522": [
    { framework: "asvs", control: "V2.7.1", title: "Credentials transmitted and stored protected" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — credentials protected" },
  ],
  "CWE-259": [
    { framework: "asvs", control: "V6.4.1", title: "Secrets not embedded in code or client assets" },
    { framework: "pci", control: "8.3.1", title: "Strong authentication; credentials not hard-coded" },
  ],
  "CWE-532": [
    { framework: "asvs", control: "V7.1.1", title: "Logs free of credentials and sensitive data" },
    { framework: "iso27001", control: "A.8.15", title: "Logging" },
    { framework: "soc2", control: "CC7.2", title: "Monitoring — anomalies identified" },
  ],
  "CWE-524": [
    { framework: "asvs", control: "V8.1.1", title: "Sensitive data not cached by clients or proxies" },
  ],
  "CWE-540": [
    { framework: "asvs", control: "V14.3.2", title: "Source and debug artefacts not exposed" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
  ],
  "CWE-538": [
    { framework: "asvs", control: "V14.3.2", title: "Source and debug artefacts not exposed" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
  ],
  "CWE-552": [
    { framework: "asvs", control: "V12.1.1", title: "Files outside the web root not served" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],

  // ── Transport and cryptography ─────────────────────────────────────────────
  "CWE-319": [
    { framework: "asvs", control: "V9.1.1", title: "TLS used for all client connectivity" },
    { framework: "pci", control: "4.2.1", title: "Strong cryptography during transmission" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography" },
    { framework: "soc2", control: "CC6.7", title: "Transmission of data is protected" },
  ],
  "CWE-326": [
    { framework: "asvs", control: "V9.1.2", title: "Strong TLS configuration" },
    { framework: "pci", control: "4.2.1", title: "Strong cryptography during transmission" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography" },
  ],
  "CWE-327": [
    { framework: "asvs", control: "V6.2.2", title: "Approved cryptographic algorithms only" },
    { framework: "pci", control: "4.2.1", title: "Strong cryptography during transmission" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography" },
  ],
  "CWE-321": [
    { framework: "asvs", control: "V6.4.2", title: "Keys not hard-coded or shared" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography — key management" },
  ],
  "CWE-324": [
    { framework: "asvs", control: "V6.4.2", title: "Key lifecycle managed" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography — key management" },
  ],
  "CWE-347": [
    { framework: "asvs", control: "V3.5.2", title: "Token signatures verified" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — authentication enforced" },
  ],

  // ── Access control, authentication, session ────────────────────────────────
  "CWE-284": [
    { framework: "asvs", control: "V4.1.1", title: "Access control enforced server-side" },
    { framework: "pci", control: "7.2.1", title: "Access assigned by need-to-know" },
    { framework: "iso27001", control: "A.5.15", title: "Access control" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],
  "CWE-862": [
    { framework: "asvs", control: "V4.1.3", title: "Authorisation checked on every request" },
    { framework: "pci", control: "7.2.1", title: "Access assigned by need-to-know" },
    { framework: "iso27001", control: "A.5.15", title: "Access control" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],
  "CWE-639": [
    { framework: "asvs", control: "V4.2.1", title: "Object-level authorisation enforced" },
    { framework: "iso27001", control: "A.5.15", title: "Access control" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],
  "CWE-290": [
    { framework: "asvs", control: "V2.2.1", title: "Authentication cannot be bypassed or spoofed" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — authentication enforced" },
  ],
  "CWE-613": [
    { framework: "asvs", control: "V3.3.1", title: "Session timeout and invalidation" },
    { framework: "pci", control: "8.2.8", title: "Idle session re-authentication" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — session management" },
  ],
  "CWE-614": [
    { framework: "asvs", control: "V3.4.1", title: "Session cookies set Secure" },
    { framework: "pci", control: "4.2.1", title: "Strong cryptography during transmission" },
    { framework: "soc2", control: "CC6.7", title: "Transmission of data is protected" },
  ],
  "CWE-1004": [
    { framework: "asvs", control: "V3.4.2", title: "Session cookies set HttpOnly" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — session management" },
  ],
  "CWE-523": [
    { framework: "asvs", control: "V9.1.1", title: "Credentials transmitted over TLS only" },
    { framework: "pci", control: "4.2.1", title: "Strong cryptography during transmission" },
  ],
  "CWE-352": [
    { framework: "asvs", control: "V4.2.2", title: "Cross-site request forgery defences present" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
  ],
  "CWE-306": [
    { framework: "asvs", control: "V4.1.1", title: "Access control enforced server-side" },
    { framework: "pci", control: "8.3.1", title: "Strong authentication required for access" },
    { framework: "iso27001", control: "A.5.15", title: "Access control" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — authentication enforced" },
  ],
  "CWE-307": [
    { framework: "asvs", control: "V2.2.1", title: "Anti-automation controls on authentication" },
    { framework: "pci", control: "8.3.4", title: "Invalid authentication attempts are limited" },
    { framework: "iso27001", control: "A.5.15", title: "Access control" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],
  "CWE-311": [
    { framework: "asvs", control: "V6.1.1", title: "Sensitive data encrypted at rest and in transit" },
    { framework: "pci", control: "3.5.1", title: "Stored account data rendered unreadable" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography" },
    { framework: "soc2", control: "CC6.7", title: "Transmission of data is protected" },
  ],
  "CWE-770": [
    { framework: "asvs", control: "V2.2.1", title: "Anti-automation controls on authentication" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],

  // ── Configuration and exposure ─────────────────────────────────────────────
  "CWE-16": [
    { framework: "asvs", control: "V14.4.1", title: "Security headers configured" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],
  "CWE-693": [
    { framework: "asvs", control: "V14.4.3", title: "Content Security Policy in place" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
  ],
  "CWE-1021": [
    { framework: "asvs", control: "V14.4.7", title: "Framing protections prevent clickjacking" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
  ],
  "CWE-200": [
    { framework: "asvs", control: "V14.3.3", title: "No unintended information disclosure" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],
  "CWE-209": [
    { framework: "asvs", control: "V7.4.1", title: "Error messages reveal no internal detail" },
  ],
  "CWE-205": [
    { framework: "asvs", control: "V14.3.3", title: "No unintended information disclosure" },
  ],
  "CWE-213": [
    { framework: "asvs", control: "V8.3.4", title: "Sensitive data exposure controlled" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],
  "CWE-548": [
    { framework: "asvs", control: "V12.1.2", title: "Directory listing disabled" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
  ],
  "CWE-942": [
    { framework: "asvs", control: "V14.5.3", title: "Cross-origin resource sharing restricted" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
  ],
  "CWE-346": [
    { framework: "asvs", control: "V14.5.3", title: "Origin validated on cross-origin requests" },
  ],
  "CWE-350": [
    { framework: "asvs", control: "V14.5.1", title: "Host header validated" },
  ],
  "CWE-345": [
    { framework: "asvs", control: "V14.5.1", title: "Request authenticity verified" },
  ],
  "CWE-353": [
    { framework: "asvs", control: "V14.5.1", title: "Integrity of requests verified" },
  ],
  "CWE-441": [
    { framework: "asvs", control: "V12.6.1", title: "Server-side request forgery protection" },
  ],
  "CWE-650": [
    { framework: "asvs", control: "V4.1.1", title: "HTTP methods restricted server-side" },
  ],
  "CWE-778": [
    { framework: "asvs", control: "V7.1.3", title: "Security events logged" },
    { framework: "iso27001", control: "A.8.15", title: "Logging" },
    { framework: "soc2", control: "CC7.2", title: "Monitoring — anomalies identified" },
  ],
  "CWE-1104": [
    { framework: "asvs", control: "V14.2.1", title: "Dependencies free of known vulnerabilities" },
    { framework: "pci", control: "6.3.3", title: "Third-party components patched" },
    { framework: "iso27001", control: "A.8.8", title: "Management of technical vulnerabilities" },
  ],
  "CWE-119": [
    { framework: "asvs", control: "V14.2.1", title: "Dependencies free of known vulnerabilities" },
    { framework: "iso27001", control: "A.8.8", title: "Management of technical vulnerabilities" },
  ],
  "CWE-1": [
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
  ],
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
  if (byCwe?.length) return byCwe;
  const byCategory = finding.category ? CATEGORY_CONTROLS[finding.category] : undefined;
  return byCategory ?? [];
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
