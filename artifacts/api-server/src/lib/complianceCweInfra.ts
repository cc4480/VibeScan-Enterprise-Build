import type { ControlRef } from "./compliance";

/** A certificate that is expired, issued for another host or not chained to a trusted root (the TLS configuration check). */
const CERTIFICATE_VALIDATION: ControlRef[] = [
  { framework: "asvs", control: "V9.2.1", title: "Server connections use trusted TLS certificates" },
  { framework: "pci", control: "4.2.1", title: "Certificates for open-network transmission are valid and trusted" },
  { framework: "iso27001", control: "A.8.24", title: "Use of cryptography" },
  { framework: "soc2", control: "CC6.7", title: "Transmission of data is protected" },
];

/** CWE → controls for transport, cryptography, access control, authentication, session and configuration weaknesses. */
export const CWE_CONTROLS_INFRASTRUCTURE: Record<string, ControlRef[]> = {
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
  "CWE-328": [
    { framework: "asvs", control: "V6.2.2", title: "Approved cryptographic algorithms only" },
    { framework: "pci", control: "4.2.1", title: "Strong cryptography during transmission" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography" },
  ],
  "CWE-295": CERTIFICATE_VALIDATION,
  "CWE-297": CERTIFICATE_VALIDATION,
  "CWE-298": CERTIFICATE_VALIDATION,
  "CWE-321": [
    { framework: "asvs", control: "V6.4.2", title: "Keys not hard-coded or shared" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography — key management" },
  ],
  "CWE-324": [
    { framework: "asvs", control: "V6.4.2", title: "Key lifecycle managed" },
    { framework: "iso27001", control: "A.8.24", title: "Use of cryptography — key management" },
  ],
  "CWE-347": [
    { framework: "asvs", control: "V3.5.3", title: "Token signatures verified" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — authentication enforced" },
  ],

  // ── Access control, authentication, session ────────────────────────────────
  "CWE-284": [
    { framework: "asvs", control: "V4.1.1", title: "Access control enforced server-side" },
    { framework: "pci", control: "7.2.1", title: "Access assigned by need-to-know" },
    { framework: "iso27001", control: "A.5.15", title: "Access control" },
    { framework: "soc2", control: "CC6.1", title: "Logical access restricted to authorised users" },
  ],
  "CWE-494": [
    { framework: "asvs", control: "V10.3.2", title: "Integrity protections for code and components loaded" },
    { framework: "iso27001", control: "A.5.21", title: "Managing information security in the ICT supply chain" },
  ],
  "CWE-829": [
    { framework: "asvs", control: "V10.3.2", title: "Integrity protections for code and components loaded" },
    { framework: "pci", control: "6.3.2", title: "Inventory of third-party software components maintained" },
    { framework: "iso27001", control: "A.5.21", title: "Managing information security in the ICT supply chain" },
  ],
  "CWE-668": [
    { framework: "asvs", control: "V1.14.1", title: "Components of differing trust levels segregated" },
    { framework: "pci", control: "1.4.1", title: "Controls between trusted and untrusted networks" },
    { framework: "iso27001", control: "A.8.20", title: "Networks security" },
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
  "CWE-472": [
    { framework: "asvs", control: "V11.1.4", title: "Business logic values are enforced on the server" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
    { framework: "soc2", control: "CC7.1", title: "Changes and processing integrity" },
  ],
  "CWE-362": [
    { framework: "asvs", control: "V11.1.6", title: "No TOCTOU or other race conditions in sensitive operations" },
    { framework: "iso27001", control: "A.8.28", title: "Secure coding" },
    { framework: "soc2", control: "CC6.1", title: "Logical access — session and transaction integrity" },
  ],
  "CWE-290": [
    // No ASVS 4.0.3 control actually covers DNS email authentication (SPF/
    // DMARC) -- these findings (dnsChecks.ts) are entirely about email
    // spoofing protection, a domain ASVS doesn't address. The prior entry,
    // V2.2.1, is really about anti-automation/brute-force (see CWE-307/770
    // below, where it's used correctly) -- dropped rather than kept as a
    // plausible-looking but wrong citation.
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
  "CWE-287": [
    { framework: "asvs", control: "V2.1.1", title: "Authentication enforced for every account, with verified identifiers" },
    { framework: "pci", control: "8.3.1", title: "Strong authentication required for access" },
    { framework: "iso27001", control: "A.5.17", title: "Authentication information" },
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
    // V14.4.1's real text is narrowly about the Content-Type header/charset,
    // not headers generally -- these findings (missing X-Content-Type-Options,
    // TRACE enabled, missing Permissions-Policy) are broader HTTP config
    // issues. V14.1.3 ("server configuration hardened per framework/server
    // recommendations") is ASVS's own official CWE-16 citation and covers
    // this as the general-hardening umbrella it actually is.
    { framework: "asvs", control: "V14.1.3", title: "Security headers configured" },
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
    { framework: "asvs", control: "V4.3.2", title: "Directory listing disabled" },
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
    // V14.5.1's real text is "the application server only accepts the HTTP
    // methods in use" -- nothing to do with host headers. This finding
    // (subdomainTakeover.ts ONLY) is genuinely about subdomain takeover, which
    // V10.3.3 names directly. The DNSSEC finding in dnsChecks.ts used to share
    // this CWE and so cited V10.3.3 for an unsigned zone; it is CWE-345 now.
    { framework: "asvs", control: "V10.3.3", title: "Protected against DNS subdomain takeover" },
  ],
  "CWE-345": [
    // Also the DNSSEC finding (unsigned zone: DNS answers cannot be
    // authenticated) -- the same analog, and no closer ASVS control exists.
    // ASVS has no DKIM/email-authenticity control -- this finding
    // (dnsChecks.ts, missing DKIM) is email security, a domain ASVS doesn't
    // cover. V13.2.6 is the closest real analog (message authenticity via
    // digital signature) -- true of the same underlying property, not a
    // literal DKIM/email requirement. Kept rather than dropped only because
    // it's an honest statement, unlike the prior V14.5.1 citation (HTTP
    // methods, unrelated).
    { framework: "asvs", control: "V13.2.6", title: "Message authenticity verified" },
  ],
  "CWE-353": [
    // V14.5.1 (HTTP methods) doesn't fit; this finding is genuinely about
    // missing Subresource Integrity on third-party scripts, which V10.3.2
    // names directly ("must not load or execute code from untrusted
    // sources... subresource integrity").
    { framework: "asvs", control: "V10.3.2", title: "Subresource Integrity used for third-party scripts" },
  ],
  "CWE-441": [
    { framework: "asvs", control: "V12.6.1", title: "Server-side request forgery protection" },
  ],
  "CWE-650": [
    // V4.1.1 is generic access control, not HTTP methods. V13.2.1 is ASVS's
    // own official CWE-650 citation: "enabled RESTful HTTP methods are a
    // valid choice for the user or action" -- an exact match.
    { framework: "asvs", control: "V13.2.1", title: "HTTP methods restricted server-side" },
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
