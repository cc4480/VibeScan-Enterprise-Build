/**
 * The deployment's own public identity.
 *
 * Every one of these used to be hardcoded to seclayer.io, which is wrong on any
 * other domain: the scanner's User-Agent points at a bot page that must exist,
 * report links in emails must resolve, and the From address must be on a domain
 * verified with the email provider or the mail is rejected.
 */

/** Public origin, no trailing slash. */
export const APP_ORIGIN: string = (
  process.env.APP_ORIGIN ?? "https://secscan.us"
).replace(/\/$/, "");

/** Bare hostname, e.g. "secscan.us". */
export const APP_DOMAIN: string = APP_ORIGIN.replace(/^https?:\/\//, "");

/**
 * User-Agent for outbound scan traffic. Site owners who see this in their logs
 * follow the URL to find out who is probing them, so it has to point at a real
 * page on the deployment.
 */
export const SCANNER_USER_AGENT: string =
  process.env.SCANNER_USER_AGENT ??
  `Mozilla/5.0 (compatible; SecScan-Security-Bot/1.0; +${APP_ORIGIN}/bot)`;

/** From address for notification email. Must be a domain verified with Resend. */
export const FROM_EMAIL: string =
  process.env.FROM_EMAIL ?? `SecScan.us <reports@${APP_DOMAIN}>`;

/**
 * From address for account mail — sign-in codes, password resets, email
 * verification, receipts. Everything whose failure locks someone out.
 *
 * Defaults to FROM_EMAIL, so leaving it unset changes nothing.
 *
 * It exists to be pointed at a SEPARATE SUBDOMAIN once one is verified with
 * Resend, because that is the only split that actually isolates reputation:
 * inbox providers score a sending domain (and IP), not the local-part, so
 * auth@ and reports@ on one domain share one reputation. Today every message
 * this service sends — a sign-in code, a CVE alert, the marketing welcome —
 * leaves from the same address, which means a spam complaint about a
 * notification is a complaint against the address that delivers sign-in
 * codes. Splitting the local-part alone would look like a fix and buy almost
 * nothing, so this is deliberately just the seam; the isolation arrives with
 * the DNS.
 */
export const AUTH_FROM_EMAIL: string =
  process.env.AUTH_FROM_EMAIL?.trim() || FROM_EMAIL;

/**
 * Address replies go to. FROM_EMAIL is a send-only mailbox on the Resend
 * domain — mail sent to it is not delivered anywhere — so without this every
 * reply a customer writes is silently lost. Set REPLY_TO_EMAIL to an inbox a
 * human actually reads; leave it unset and no reply_to header is attached,
 * which is the honest default rather than pointing replies at a black hole.
 */
export const REPLY_TO_EMAIL: string | undefined =
  process.env.REPLY_TO_EMAIL?.trim() || undefined;
