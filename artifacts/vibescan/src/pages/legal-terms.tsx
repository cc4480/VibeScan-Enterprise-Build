/** The terms of service. */
import { Section, CONTACT } from "./legal-shared";

export function Terms() {
  return (
    <>
      <Section title="The agreement">
        <p>
          These terms are between you and SecScan. Using the service means you accept them.
          If you are agreeing on behalf of a company, you confirm you may bind it.
        </p>
      </Section>

      <Section title="Only scan what you are allowed to scan">
        <p className="text-foreground">
          This is the most important term here. Read it.
        </p>
        <p>
          You may submit a target only if you own it, or you have the owner's permission to
          have it security-tested. Scanning a system you have no authority over may be a
          criminal offence — under the Computer Fraud and Abuse Act in the United States,
          the Computer Misuse Act in the United Kingdom, and equivalents elsewhere.
        </p>
        <p>
          Because of this, active testing is gated. Any domain can be checked for what an
          ordinary visitor sees: response headers, TLS, cookies, exposed files, DNS records
          and out-of-date software. The checks that send real attack traffic — SQL injection,
          cross-site scripting, path traversal, broken access control, server-side request
          forgery, database and storage exposure, and port scanning — run only against a
          domain you have proven you control, by DNS record or by publishing a file.
        </p>
        <p>
          You are responsible for what you scan. If a scan you started causes a complaint or
          a claim, that is yours to answer, and you agree to indemnify us for it.
        </p>
      </Section>

      <Section title="What the service does and does not promise">
        <p>
          SecScan tests from the outside, as an attacker would, without access to your source
          code. A clean report means those particular checks found nothing on that day. It is
          not a guarantee that your site is secure, and it is not a substitute for a manual
          penetration test or a code audit.
        </p>
        <p>
          Findings can be wrong in both directions. A scanner can report an issue that turns
          out not to be exploitable in your configuration, and it can miss real problems.
          Verify anything before acting on it.
        </p>
        <p>
          The service is provided as-is, without warranties. To the extent the law allows,
          our total liability to you is limited to what you paid us in the twelve months
          before the claim.
        </p>
      </Section>

      <Section title="Acceptable use">
        <p>
          Do not use the service to attack anyone, to test systems you have no right to
          test, to work around the domain-verification gate, or to resell scans as your own
          service without our agreement. Do not attempt to disrupt the service or to access
          other users' accounts or reports.
        </p>
        <p>We may suspend an account that does any of this.</p>
      </Section>

      <Section title="Payment">
        <p>
          The paid plan is not on sale yet. This section describes how it will work when it
          opens; until then, the free scans above are the only way to run a scan.
        </p>
        <p>
          Every account gets 3 free scans each calendar month (UTC); unused free scans do not
          carry over. Beyond those, scans are covered by a subscription. The price is shown before you pay, and payment is
          taken by Stripe.
        </p>
        <p>
          Scan credits are no longer sold. If you already hold credits, they do not expire and are
          used after your free scans when you have no plan. Because a scan is delivered immediately
          and cannot be un-run, a completed scan is not refundable. If a scan fails for a reason on
          our side and you paid for it with a credit, the credit is returned to your account
          automatically. Unused credits can be refunded within 30 days of purchase.
        </p>
      </Section>

      <Section title="Subscriptions">
        <p>
          Subscriptions are not on sale yet; this describes how they will work when they open.
        </p>
        <p>
          SecScan Unlimited is billed monthly in advance and renews automatically each month
          until you cancel. It includes continuous monitoring for up to 3 sites and unlimited full
          scans. Unlimited means scans are not counted against you, and it is subject to fair use:
          we limit how fast scans can be started (currently 5 an hour and 20 a day per account) so
          the service stays available to everyone, and we may restrict an account that uses it to
          scan sites it does not own or in a way that harms the service.
        </p>
        <p>
          You can cancel at any time from Settings. Cancelling stops the next renewal: you keep
          your plan until the end of the month you have paid for, and are not charged again.
          We do not refund partial months. If a renewal payment fails, Stripe retries it for a
          short period during which your plan stays active; if it still fails, monitoring and
          scanning on your plan pause until the payment is updated.
        </p>
        <p>
          If we change the price of your plan, we will email you before the change applies to
          your subscription, and it will take effect from a renewal after that notice.
        </p>
      </Section>

      <Section title="Availability">
        <p>
          We do not promise a particular uptime. Parts of a scan depend on third parties —
          DNS, certificate transparency logs, vulnerability feeds and the AI provider — and
          can be unavailable or slow through no fault of ours.
        </p>
      </Section>

      <Section title="Your content">
        <p>
          Your scan targets, reports and credentials remain yours. You grant us only the
          permission needed to run the service: to store them, to process them to produce
          your report, and to send findings to the AI provider to write the analysis in each report.
        </p>
      </Section>

      <Section title="Changes and contact">
        <p>
          We may change these terms; material changes will be noted here with a new date.
          Questions go to {CONTACT}.
        </p>
      </Section>
    </>
  );
}
