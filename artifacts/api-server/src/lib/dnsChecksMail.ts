/** Email authentication: SPF, DMARC, DKIM. */
import type { ScanVulnerability } from "./scanner";
import { countSpfLookups, effectiveDmarcPolicy } from "./emailAuthParse.js";
import { findUpChain, dnsQuery, vuln, statusLabel } from "./dnsChecksCore";

// ─────────────────────────────────────────────────────────────────────────────
// SPF CHECK
// ─────────────────────────────────────────────────────────────────────────────

export async function checkSpf(hostname: string): Promise<ScanVulnerability[]> {
  const spf = await findUpChain(hostname, (d) => d, (r) => r.startsWith("v=spf1"));
  // A network failure or an NXDOMAIN on the domain itself teaches us nothing
  // about whether a record exists, so neither may produce a finding.
  if (!spf.conclusive) return [];
  const spfRecord = spf.found;

  if (!spfRecord) {
    // MX answers are filtered to real MX records now, so a CNAMEd web host no
    // longer reads as a mail sender.
    const { answers: mxAnswers } = await dnsQuery(hostname, "MX");
    const sendsMail = mxAnswers.length > 0;

    return [vuln({
      name: "Missing SPF Record — Email Spoofing Possible",
      severity: sendsMail ? "high" : "medium",
      category: "Email Security",
      description: `No SPF (Sender Policy Framework) record was found for ${hostname}. Without SPF, anyone can send emails that appear to come from @${hostname}. Attackers use this to send phishing emails to your customers, partners, and employees under your domain name, with no technical barrier to doing so.`,
      evidence: `DNS TXT queries: ${spf.checked.join(", ")}\nStatus: ${statusLabel(spf.status)}\nNo v=spf1 record found at the host or any parent domain${sendsMail ? `\nMX records present (${mxAnswers.length}) — domain actively sends email` : ""}`,
      solution: `Add a TXT record to your DNS for ${hostname}:\n"v=spf1 include:_spf.yourmailprovider.com ~all"\n\nReplace 'include:...' with your actual mail provider's SPF include. End with '-all' (hard fail) for strictest enforcement. Verify at: https://mxtoolbox.com/spf.aspx`,
      cweId: "CWE-290",
      cvssScore: sendsMail ? 7.5 : 5.3,
    })];
  }

  // SPF exists — check for dangerous configurations
  const vulns: ScanVulnerability[] = [];

  const allQualifier = spfAllQualifier(spfRecord);
  if (allQualifier === "+") {
    vulns.push(vuln({
      name: "SPF Record Uses +all (Allows Any Sender)",
      severity: "critical",
      category: "Email Security",
      description: `The SPF record for ${hostname} ends with "+all", which means ANY mail server on the internet is authorized to send email on behalf of your domain. This completely defeats the purpose of SPF and explicitly permits email spoofing from your domain.`,
      evidence: `TXT record: ${spfRecord}`,
      solution: 'Replace "+all" with "-all" (hard fail — reject unauthorized senders) or "~all" (soft fail — mark as spam). Use "-all" for strictest protection.',
      cweId: "CWE-290",
      cvssScore: 9.1,
    }));
  } else if (allQualifier === "?") {
    vulns.push(vuln({
      name: "SPF Record Uses ?all (Neutral — No Enforcement)",
      severity: "medium",
      category: "Email Security",
      description: `The SPF record uses "?all" which provides no actual enforcement — email from unauthorized senders is treated neutrally and will not be rejected or marked as spam. This offers no spoofing protection.`,
      evidence: `TXT record: ${spfRecord}`,
      solution: 'Change "?all" to "-all" (reject unauthorized senders) or at minimum "~all" (soft fail). Update to "-all" once you have verified all legitimate sending sources are included.',
      cweId: "CWE-290",
      cvssScore: 5.3,
    }));
  }

  // RFC 7208 §4.6.4: PermError only when MORE than 10 lookups happen. Only the
  // lookup mechanisms count (include, a, mx, ptr, exists, redirect); ip4/ip6 do not,
  // and their hex or dots must never be mistaken for one.
  const lookupCount = countSpfLookups(spfRecord);
  if (lookupCount > 10) {
    vulns.push(vuln({
      name: "SPF Record Exceeds DNS Lookup Limit",
      severity: "low",
      category: "Email Security",
      description: `The SPF record contains at least ${lookupCount} DNS-lookup terms, more than the RFC 7208 limit of 10 (nested includes are not expanded, so the true count may be higher). Records that exceed this limit result in a PermError, causing SPF to fail for all senders — meaning legitimate emails may be rejected or SPF protection silently disabled.`,
      evidence: `TXT record: ${spfRecord}\nDNS-lookup terms (include, a, mx, ptr, exists, redirect): ${lookupCount}`,
      solution: "Flatten your SPF record using a tool like dmarcian's SPF Surveyor. Replace nested includes with direct IP ranges using 'ip4:' and 'ip6:' mechanisms to reduce DNS lookups below 10.",
      cweId: "CWE-290",
    }));
  }

  return vulns;
}

// ─────────────────────────────────────────────────────────────────────────────
// DMARC CHECK
// ─────────────────────────────────────────────────────────────────────────────

export async function checkDmarc(hostname: string): Promise<ScanVulnerability[]> {
  // RFC 7489 already says a receiver falls back to the organisational domain
  // when the exact name has no policy, so accepting a parent's record matches
  // what a real mail receiver does.
  const dmarc = await findUpChain(
    hostname,
    (d) => `_dmarc.${d}`,
    (r) => r.startsWith("v=DMARC1"),
    true, // an absent _dmarc label IS the "no policy published" answer
  );
  if (!dmarc.conclusive) return [];
  const dmarcRecord = dmarc.found;

  if (!dmarcRecord) {
    return [vuln({
      name: "Missing DMARC Record — No Email Authentication Enforcement",
      severity: "high",
      category: "Email Security",
      description: `No DMARC (Domain-based Message Authentication, Reporting & Conformance) record exists for ${hostname}. Without DMARC, even if SPF and DKIM are configured, there is no policy telling receiving mail servers what to do with messages that fail authentication. Attackers can bypass SPF/DKIM using the "From" header spoofing that DMARC is specifically designed to prevent.`,
      evidence: `DNS TXT queries: ${dmarc.checked.join(", ")}\nStatus: ${statusLabel(dmarc.status)}\nNo v=DMARC1 record found at the host or any parent domain`,
      solution: `Add a TXT record for _dmarc.${hostname}:\n"v=DMARC1; p=quarantine; rua=mailto:dmarc@${hostname}; ruf=mailto:dmarc@${hostname}; fo=1"\n\nStart with p=none (monitoring) and progress to p=quarantine then p=reject once you verify legitimate email flows. Use https://dmarcian.com to monitor reports.`,
      cweId: "CWE-290",
      cvssScore: 7.5,
    })];
  }

  const vulns: ScanVulnerability[] = [];

  // Check policy strength
  // A record read from a parent domain reaches this host through sp= when it has one.
  const policy = effectiveDmarcPolicy(dmarcRecord, dmarc.at !== `_dmarc.${hostname}`);

  if (policy === "none") {
    vulns.push(vuln({
      name: "DMARC Policy Set to None (Monitoring Only — No Enforcement)",
      severity: "medium",
      category: "Email Security",
      description: `The DMARC policy is p=none, which means emails that fail authentication are delivered normally with no action taken. This is appropriate for initial rollout and monitoring but provides zero spoofing protection. Attackers can still send spoofed emails from your domain that reach recipients' inboxes.`,
      evidence: `TXT record: ${dmarcRecord}`,
      solution: 'After reviewing DMARC aggregate reports (rua=) to ensure all legitimate email is passing authentication, progress to p=quarantine then p=reject. p=reject provides the strongest protection — spoofed emails are outright rejected.',
      cweId: "CWE-290",
      cvssScore: 5.3,
    }));
  }

  // Check for missing reporting addresses
  if (!/\brua=/.test(dmarcRecord)) {
    vulns.push(vuln({
      name: "DMARC Record Missing Aggregate Report Address (rua=)",
      severity: "info",
      category: "Email Security",
      description: "The DMARC record has no aggregate reporting address (rua=). Without reports, you cannot see which mail servers are sending email on behalf of your domain or monitor for spoofing attempts.",
      evidence: `TXT record: ${dmarcRecord}`,
      solution: `Add rua=mailto:dmarc@${hostname} (or use a DMARC monitoring service like Postmark, Dmarcian, or Proofpoint) to receive daily aggregate reports about your email authentication.`,
      cweId: "CWE-778",
    }));
  }

  return vulns;
}

// ─────────────────────────────────────────────────────────────────────────────
// DKIM CHECK
// ─────────────────────────────────────────────────────────────────────────────

export const COMMON_DKIM_SELECTORS = [
  // Standard / service-specific selectors
  "default", "google", "mail", "smtp", "k1", "k2",
  "selector1", "selector2", "email", "mailjet", "mandrill",
  "sendgrid", "pm", "s1", "s2", "dkim", "key1", "key2",
  // Confirmed the hard way: secscan.us's own DKIM record lives at
  // resend._domainkey and was missing here, which would have made this
  // checker report "No DKIM" against a domain actively sending signed mail.
  "resend",
  "mxvault", "everlytickey1", "everlytickey2", "litesrv",
  // Additional common selectors
  "m1", "m2", "dkim1", "dkim2", "mx", "mailgun", "cm",
  "proddkim1024", "sf2", "zendesk1", "zendesk2",
  // Date-based selectors — Google Workspace, Microsoft 365, and many
  // enterprise mail platforms rotate keys with date-stamped selectors.
  // We probe the most recent windows; note that missing these does NOT
  // mean DKIM is absent — only that we couldn't find the active selector.
  "20221201", "20230601", "20231201",
  "20240101", "20240601", "20241201",
  "20250101", "20250601",
];

export async function checkDkim(hostname: string): Promise<ScanVulnerability[]> {
  // Try each common selector in parallel
  const results = await Promise.allSettled(
    COMMON_DKIM_SELECTORS.map((selector) =>
      dnsQuery(`${selector}._domainkey.${hostname}`, "TXT"),
    ),
  );

  const foundAny = results.some(
    (r) => r.status === "fulfilled" && r.value.answers.length > 0,
  );
  // Only report if at least one query returned a valid DNS response (status 0).
  // If ALL queries timed out / errored, we have no basis for a finding.
  const anyQuerySucceeded = results.some(
    (r) => r.status === "fulfilled" && r.value.status === 0,
  );

  if (!foundAny && anyQuerySucceeded) {
    return [vuln({
      name: "No DKIM Records Found Under Common Selectors",
      severity: "low",
      category: "Email Security",
      description: `No DKIM (DomainKeys Identified Mail) TXT records were found for ${hostname} under ${COMMON_DKIM_SELECTORS.length} commonly used selectors. DKIM selectors are arbitrary names chosen by the mail provider and cannot be listed from DNS, so this does not prove DKIM is absent: the domain may sign mail under a custom selector. If you do not sign outgoing mail with DKIM, it is more likely to be marked as spam and DMARC enforcement is weakened.`,
      evidence: `Checked selectors: ${COMMON_DKIM_SELECTORS.slice(0, 8).join(", ")}, and ${COMMON_DKIM_SELECTORS.length - 8} more — none returned a valid DKIM record.`,
      solution: "Enable DKIM signing in your email service provider (Google Workspace, Microsoft 365, SendGrid, Mailgun, etc.) and publish the provided TXT record under [selector]._domainkey.yourdomain.com. The exact steps depend on your mail provider.",
      cweId: "CWE-345",
      // Selectors are guessed, so absence is weak evidence.
      confidence: 40,
    })];
  }

  return [];
}

/**
 * The qualifier of an SPF record's "all" mechanism: "+" (written or implied), "-", "~" or "?"; null when there is none.
 * RFC 7208 section 4.6.2 makes a bare `all` mean `+all`, and the term must stand alone: "include:foo+all.example" is not
 * one, which a text search for "+all" cannot tell.
 */
export function spfAllQualifier(record: string): "+" | "-" | "~" | "?" | null {
  for (const term of record.trim().split(/\s+/).slice(1)) {
    const m = /^([+\-~?])?all$/i.exec(term);
    if (m) return (m[1] as "+" | "-" | "~" | "?" | undefined) ?? "+";
  }
  return null;
}
