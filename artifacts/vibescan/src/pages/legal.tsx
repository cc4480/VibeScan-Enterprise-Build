import { Shield, FileText } from "lucide-react";
import { useSeo } from "@/lib/seo";

// Privacy Policy and Terms of Service, rendered from one component because they
// share a layout and differ only in content. Both are real, indexable pages at
// stable paths (/privacy, /terms) rather than anchors inside a larger page:
// Google's OAuth consent screen requires a reachable privacy-policy URL, and
// Stripe requires published terms. An anchor is both weaker legally and fragile
// if the surrounding page is reorganised.
//
// Deliberately plain: these are read, not marketed at.

// Per document: a change to one must not re-date the other.
const LAST_UPDATED: Record<"privacy" | "terms", string> = {
  privacy: "September 25, 2026", // DeepSeek named; sign-up network hash disclosed
  terms: "September 24, 2026", // Starter and Pro plans; free scans renew monthly
};
const CONTACT = "hello@secscan.us";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-10">
      <h2 className="text-lg sm:text-xl font-bold tracking-tight mb-4">{title}</h2>
      <div className="space-y-3 text-sm sm:text-[15px] leading-relaxed text-muted-foreground">
        {children}
      </div>
    </section>
  );
}

function Privacy() {
  return (
    <>
      <Section title="What this covers">
        <p>
          This policy describes what SecScan collects when you use secscan.us, why, and who
          else sees it. It covers the website, the scanner and the emails we send.
        </p>
      </Section>

      <Section title="What we collect">
        <p>
          <strong className="text-foreground">Your account.</strong> Your email address, and
          either a password (stored only as a scrypt hash — we never hold the password
          itself) or the fact that you signed in with Google.
        </p>
        <p>
          <strong className="text-foreground">What you scan.</strong> The URLs you submit,
          the results, and the evidence collected to support each finding. Evidence can
          include fragments of your site's responses — headers, HTML, error messages — so a
          finding can be reproduced. If your site returns personal data in a response, that
          fragment may be stored with the report.
        </p>
        <p>
          <strong className="text-foreground">Credentials you choose to supply.</strong> If
          you give the scanner a login so it can test signed-in pages, those credentials are
          encrypted at rest with AES-256-GCM and used only for that scan.
        </p>
        <p>
          <strong className="text-foreground">Payments.</strong> Stripe processes payments.
          Card details go to Stripe and never reach our servers; we keep the amount, the
          product and Stripe's identifiers.
        </p>
        <p>
          <strong className="text-foreground">Operational logs.</strong> Ordinary server
          logs, including IP address and timestamps, kept to run and secure the service.
        </p>
        <p>
          <strong className="text-foreground">Sign-up network.</strong> To limit how many
          accounts one network can create, we store a one-way keyed hash of the network you
          signed up from (your IP address, or the /64 block of an IPv6 address) alongside
          your account. It is only ever compared for equality and cannot be turned back into
          your IP address.
        </p>
      </Section>

      <Section title="What we do not do">
        <p>We do not sell your data, and we do not run advertising or ad-tracking on it.</p>
        <p>
          We do not use your scan results to market to the owners of the sites you scan.
        </p>
      </Section>

      <Section title="Third parties we send data to">
        <p>
          <strong className="text-foreground">Railway</strong> — hosting and the database
          where all of the above is stored.
        </p>
        <p>
          <strong className="text-foreground">Stripe</strong> — payment processing.
        </p>
        <p>
          <strong className="text-foreground">Resend</strong> — sends our email, so it
          handles your address and the message contents.
        </p>
        <p>
          <strong className="text-foreground">Cloudflare</strong> — sits in front of the
          site, so it sees request metadata including your IP.
        </p>
        <p>
          <strong className="text-foreground">DeepSeek</strong> — our AI analysis provider;
          it generates the written analysis in every report. Every scan sends its findings
          (with evidence fragments), the target URL and the technologies detected on it to
          DeepSeek for that purpose. Your
          account details (name, email, password) are not sent. DeepSeek is based in China, so this is a transfer outside the UK and EEA. There is currently
          no way to run a scan without it, so if you would rather not have findings leave our
          infrastructure, do not run scans.
        </p>
      </Section>

      <Section title="Share links">
        <p>
          If you create a share link for a report, anyone holding that link can read the
          report without signing in. Treat it as public. You can revoke a link at any time,
          which stops it working immediately.
        </p>
      </Section>

      <Section title="Retention and deletion">
        <p>
          Reports and scan history stay until you delete them or delete your account.
        </p>
        <p>
          Deleting your account removes your account record, your scans and reports, your
          stored credentials and your domain verifications. Records we are required to keep
          for accounting — the fact and amount of a payment — are retained as long as the
          law requires, and are held by Stripe as well. Backups are overwritten on their
          own schedule, so a deleted record can persist in a backup for a short period
          before it is gone.
        </p>
      </Section>

      <Section title="Your rights">
        <p>
          If you are in the UK or EEA you have the right to access, correct, export and
          delete your personal data, and to object to processing. California residents have
          comparable rights under the CCPA. You can delete your account and its data
          yourself from Settings, or write to {CONTACT} and we will action it.
        </p>
        <p>
          You can also complain to your data protection regulator — in the UK, the ICO.
        </p>
      </Section>

      <Section title="Changes">
        <p>
          If this policy changes materially we will say so on this page and update the date
          below. Continuing to use the service after that means the new version applies.
        </p>
      </Section>
    </>
  );
}

function Terms() {
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

      <Section title="Credits and payment">
        <p>
          Every account gets 3 free scans each calendar month (UTC); unused free scans do not
          carry over. Beyond those, scans are paid for with a subscription or with scan credits. Prices are shown before you pay, and payment is
          taken by Stripe.
        </p>
        <p>
          Scan credits are sold in packs and do not expire. Because a scan is
          delivered immediately and cannot be un-run, a completed scan is not refundable. If a
          scan fails for a reason on our side, the credit is returned to your account
          automatically. Unused credits can be refunded within 30 days of purchase.
        </p>
      </Section>

      <Section title="Subscriptions">
        <p>
          SecScan Starter and SecScan Pro are billed monthly in advance and renew automatically
          each month until you cancel. Starter includes continuous monitoring for up to 3 sites and 20
          full scans per billing month; Pro includes up to 5 sites and 100 full scans per billing
          month. Included scans reset at each renewal and do not carry over; while you
          have included scans left, they are used before any scan credits.
        </p>
        <p>
          You can cancel at any time from Settings. Cancelling stops the next renewal: you keep
          your plan until the end of the month you have paid for, and are not charged again.
          We do not refund partial months. If a renewal payment fails, Stripe retries it for a
          short period during which your plan stays active; if it still fails, monitoring and
          included scans pause until the payment is updated.
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

export default function LegalPage({ kind }: { kind: "privacy" | "terms" }) {
  const isPrivacy = kind === "privacy";
  const Icon = isPrivacy ? Shield : FileText;
  const title = isPrivacy ? "Privacy Policy" : "Terms of Service";

  useSeo({
    title: `${title} — SecScan`,
    description: isPrivacy
      ? "What SecScan collects, why, and who else sees it."
      : "The terms that apply when you use SecScan, including what you may scan.",
  });

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="flex items-center gap-3 mb-2">
        <div className="w-11 h-11 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
          <Icon className="w-5 h-5 text-primary" />
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">{title}</h1>
      </div>
      <p className="text-sm text-muted-foreground mb-10">Last updated {LAST_UPDATED[kind]}</p>

      {isPrivacy ? <Privacy /> : <Terms />}

      <p className="text-xs text-muted-foreground border-t border-white/10 pt-6">
        Questions about this page: {CONTACT}
      </p>
    </div>
  );
}
