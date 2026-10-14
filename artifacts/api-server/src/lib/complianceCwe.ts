import type { ControlRef } from "./compliance";

/** CWE → controls for injection and secrets/credentials weaknesses. */
export const CWE_CONTROLS_INJECTION_SECRETS: Record<string, ControlRef[]> = {
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
  "CWE-78": [
    { framework: "asvs", control: "V5.3.8", title: "OS command injection protection" },
    { framework: "pci", control: "6.2.4", title: "Software engineering techniques prevent injection attacks" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
  ],
  "CWE-94": [
    { framework: "asvs", control: "V5.2.4", title: "Dynamic code execution, eval and templates, avoided or sandboxed" },
    { framework: "pci", control: "6.2.4", title: "Software engineering techniques prevent injection attacks" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
  ],
  "CWE-95": [
    { framework: "asvs", control: "V5.2.4", title: "Dynamic code execution, eval and templates, avoided or sandboxed" },
    { framework: "pci", control: "6.2.4", title: "Software engineering techniques prevent injection attacks" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
  ],
  "CWE-250": [
    { framework: "asvs", control: "V4.1.3", title: "Principle of least privilege" },
    { framework: "iso27001", control: "A.8.2", title: "Privileged access rights" },
    { framework: "soc2", control: "CC6.3", title: "Logical access — least privilege" },
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
    // V5.5.1 was wrong here -- that control is actually about serialized-object
    // integrity (see CWE-502 below), not redirects. The real ASVS 4.0.3 control
    // for allow-listed redirect destinations is V5.1.5. Verified against the
    // canonical requirement text, not just the section number.
    { framework: "asvs", control: "V5.1.5", title: "Redirects and forwards validated" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
  ],
  "CWE-502": [
    { framework: "asvs", control: "V5.5.3", title: "Deserialization of untrusted data avoided or protected" },
    { framework: "pci", control: "6.2.4", title: "Software engineering techniques prevent injection attacks" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],
  "CWE-1336": [
    { framework: "asvs", control: "V5.2.5", title: "Template injection prevented by sanitising or sandboxing user input" },
    { framework: "pci", control: "6.2.4", title: "Software engineering techniques prevent injection attacks" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
    { framework: "soc2", control: "CC6.6", title: "Logical access — protection against external threats" },
  ],
  "CWE-113": [
    { framework: "pci", control: "6.2.4", title: "Software engineering techniques prevent injection attacks" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
  ],
  "CWE-489": [
    { framework: "asvs", control: "V14.3.2", title: "Source and debug artefacts not exposed" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
  ],
  "CWE-915": [
    { framework: "asvs", control: "V5.1.2", title: "Mass assignment / parameter binding controlled" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
  ],
  "CWE-506": [
    { framework: "asvs", control: "V14.2.4", title: "Third-party components come from trusted, maintained repositories" },
    { framework: "pci", control: "6.3.2", title: "Inventory of third-party software components maintained" },
    { framework: "iso27001", control: "A.5.21", title: "Managing information security in the ICT supply chain" },
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
  "CWE-338": [
    { framework: "asvs", control: "V6.3.1", title: "Random values come from a cryptographically secure generator" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography" },
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
  // ASVS 4.0.3 predates LLM-specific requirements, so no ASVS control names
  // prompt injection directly — dropped rather than forced onto a control
  // about something else, the same discipline CWE-290's entry above documents.
  "CWE-1427": [
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — credentials and instructions protected" },
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
    { framework: "asvs", control: "V12.4.1", title: "Files outside the web root not served" },
    { framework: "iso27001", control: "A.8.9", title: "Configuration management" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],

};
