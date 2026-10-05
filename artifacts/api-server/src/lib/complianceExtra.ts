/**
 * NIST SP 800-53 Rev. 5 and the HIPAA Security Rule's technical safeguards, mapped the
 * same way as the frameworks in compliance.ts: which control a finding is EVIDENCE
 * FOR, never a verdict. Everything in that file's header applies here unchanged.
 *
 * Kept in its own file so the original mapping stays readable, and built from small
 * topic tables (one control, the weaknesses that speak to it) rather than one row per
 * weakness. A weakness is listed under a control only where the control's own text
 * covers it; a CWE that fits nothing here gets nothing, which is the honest answer.
 *
 * HIPAA in particular applies only to covered entities and their business associates
 * handling electronic protected health information, and its addressable
 * specifications are decided by the entity's own risk analysis. A scan cannot say
 * whether any of that applies, so the note says so.
 */
import type { ControlRef, FrameworkMeta } from "./compliance";

export const EXTRA_FRAMEWORKS: Record<string, FrameworkMeta> = {
  nist80053: {
    id: "nist80053",
    name: "NIST SP 800-53",
    version: "Rev. 5",
    note:
      "Security and privacy controls for information systems. Most controls cover policy, personnel and " +
      "operations that no scan can observe; these findings are technical evidence for the subset an " +
      "application scan can speak to.",
  },
  hipaa: {
    id: "hipaa",
    name: "HIPAA Security Rule",
    version: "45 CFR 164.312 (technical safeguards)",
    note:
      "Applies only to covered entities and business associates that handle electronic protected health " +
      "information. Whether an addressable specification is required is decided by the entity's own risk " +
      "analysis, which no scan can perform. The administrative and physical safeguards are outside what " +
      "a scan can see.",
  },
};

type Fw = "nist80053" | "hipaa";
interface Topic {
  fw: Fw;
  control: string;
  title: string;
  cwes: string[];
  categories?: string[];
}

const TOPICS: Topic[] = [
  // ── NIST SP 800-53 Rev. 5 ─────────────────────────────────────────────────
  { fw: "nist80053", control: "SI-10", title: "Information input validation", cwes: ["CWE-89", "CWE-79", "CWE-22", "CWE-918", "CWE-502", "CWE-915", "CWE-601", "CWE-1336", "CWE-113"] },
  { fw: "nist80053", control: "SI-16", title: "Memory protection", cwes: ["CWE-119"] },
  { fw: "nist80053", control: "SI-2", title: "Flaw remediation", cwes: ["CWE-1104", "CWE-1395"], categories: ["CVE / Known Vulnerability", "Outdated Software"] },
  { fw: "nist80053", control: "RA-5", title: "Vulnerability monitoring and scanning", cwes: ["CWE-1104", "CWE-1395"], categories: ["CVE / Known Vulnerability", "Outdated Software"] },
  { fw: "nist80053", control: "SR-3", title: "Supply chain controls and processes", cwes: [], categories: ["Supply Chain Security"] },
  { fw: "nist80053", control: "IA-5", title: "Authenticator management", cwes: ["CWE-798", "CWE-259", "CWE-522"] },
  { fw: "nist80053", control: "IA-2", title: "Identification and authentication", cwes: ["CWE-306"] },
  { fw: "nist80053", control: "AC-7", title: "Unsuccessful logon attempts", cwes: ["CWE-307"] },
  { fw: "nist80053", control: "AC-3", title: "Access enforcement", cwes: ["CWE-284", "CWE-862", "CWE-639", "CWE-552", "CWE-538"], categories: ["BaaS Misconfiguration", "Cloud Storage Misconfiguration", "Database Security"] },
  { fw: "nist80053", control: "AC-6", title: "Least privilege", cwes: [], categories: ["Database Security"] },
  { fw: "nist80053", control: "AC-12", title: "Session termination", cwes: ["CWE-613"] },
  { fw: "nist80053", control: "SC-23", title: "Session authenticity", cwes: ["CWE-614", "CWE-1004", "CWE-352"] },
  { fw: "nist80053", control: "SC-8", title: "Transmission confidentiality and integrity", cwes: ["CWE-319", "CWE-311", "CWE-523"], categories: ["Mail Transport Security"] },
  { fw: "nist80053", control: "SC-13", title: "Cryptographic protection", cwes: ["CWE-326", "CWE-327", "CWE-328"] },
  { fw: "nist80053", control: "SC-17", title: "Public key infrastructure certificates", cwes: ["CWE-295", "CWE-297", "CWE-298"] },
  { fw: "nist80053", control: "SC-12", title: "Cryptographic key establishment and management", cwes: ["CWE-321", "CWE-324"] },
  { fw: "nist80053", control: "SC-28", title: "Protection of information at rest", cwes: ["CWE-312"] },
  { fw: "nist80053", control: "SC-7", title: "Boundary protection", cwes: [], categories: ["Network Exposure"] },
  { fw: "nist80053", control: "SC-5", title: "Denial-of-service protection", cwes: ["CWE-770"] },
  { fw: "nist80053", control: "SI-7", title: "Software, firmware and information integrity", cwes: ["CWE-347", "CWE-353"] },
  { fw: "nist80053", control: "SI-11", title: "Error handling", cwes: ["CWE-209"] },
  { fw: "nist80053", control: "AU-2", title: "Event logging", cwes: ["CWE-778"] },
  { fw: "nist80053", control: "CM-6", title: "Configuration settings", cwes: ["CWE-16", "CWE-693", "CWE-489", "CWE-1021", "CWE-942", "CWE-548"] },

  // ── HIPAA Security Rule, 45 CFR 164.312 ───────────────────────────────────
  { fw: "hipaa", control: "164.312(a)(1)", title: "Access control", cwes: ["CWE-284", "CWE-862", "CWE-639", "CWE-552", "CWE-538"], categories: ["BaaS Misconfiguration", "Cloud Storage Misconfiguration", "Database Security"] },
  { fw: "hipaa", control: "164.312(a)(2)(iii)", title: "Automatic logoff", cwes: ["CWE-613"] },
  { fw: "hipaa", control: "164.312(a)(2)(iv)", title: "Encryption and decryption", cwes: ["CWE-312"] },
  { fw: "hipaa", control: "164.312(b)", title: "Audit controls", cwes: ["CWE-778"] },
  { fw: "hipaa", control: "164.312(c)(1)", title: "Integrity", cwes: ["CWE-347", "CWE-353"] },
  { fw: "hipaa", control: "164.312(d)", title: "Person or entity authentication", cwes: ["CWE-306", "CWE-307", "CWE-522"] },
  { fw: "hipaa", control: "164.312(e)(1)", title: "Transmission security", cwes: ["CWE-319", "CWE-311", "CWE-523", "CWE-326", "CWE-327", "CWE-328", "CWE-295", "CWE-297", "CWE-298"], categories: ["Mail Transport Security"] },
];

const ref = (t: Topic): ControlRef => ({ framework: t.fw, control: t.control, title: t.title });

const byCwe = new Map<string, ControlRef[]>();
const byCategory = new Map<string, ControlRef[]>();
for (const t of TOPICS) {
  for (const c of t.cwes) byCwe.set(c, [...(byCwe.get(c) ?? []), ref(t)]);
  for (const c of t.categories ?? []) byCategory.set(c, [...(byCategory.get(c) ?? []), ref(t)]);
}

/**
 * Same precedence as the original mapping: the CWE if it maps, else the category. The
 * caller says whether the original mapping already used the finding's CWE, so a finding
 * with a specific CWE never falls through to the coarser category controls here either.
 */
export function extraControlsForFinding(
  finding: { cweId?: string | null; category?: string | null },
  cweHandledByBase: boolean,
): ControlRef[] {
  const specific = finding.cweId ? byCwe.get(finding.cweId) : undefined;
  if (specific?.length) return specific;
  if (cweHandledByBase) return [];
  return (finding.category ? byCategory.get(finding.category) : undefined) ?? [];
}
