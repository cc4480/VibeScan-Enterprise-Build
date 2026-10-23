/** The privacy policy. */
import { Section, CONTACT } from "./legal-shared";

export function Privacy() {
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
          encrypted at rest with AES-256-GCM, used only for that scan, and deleted as soon as
          the scan finishes or fails.
        </p>
        <p>
          <strong className="text-foreground">Optional scan features.</strong> If you enter a
          public GitHub repository, we read some of its public configuration files through
          GitHub's API; no token is sent and only GitHub is contacted for it, never your site.
          If you choose "Create one for me" on a scan with a login, the scan submits your
          site's public signup form once, with a made-up address at example.com, to get a
          second test account for the access-control test; the report names any account it
          created so you can delete it. Both are off unless you choose them for that scan.
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
          it writes the analysis in each report. Unless you turn it off, a scan sends its findings
          (names, descriptions and evidence fragments, with anything that looks like a credential
          removed on a best-effort basis), the target URL and the technologies detected on it to
          DeepSeek for that purpose. The logins you supply for a scan, and your account details
          (name, email, password), are never sent. DeepSeek is based in China, so this is a
          transfer outside the UK and EEA. You can turn this off in Settings, under Privacy: no
          findings are sent, and the scan and every finding stay the same.
        </p>
        <p>
          <strong className="text-foreground">Google</strong> — if you choose to sign in with
          Google, Google handles that sign-in and tells us your verified email address and name.
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
        <p>
          To stop the monthly free scans being reset by deleting an account and signing up
          again, we keep, until the end of that month, a one-way keyed hash of the email address
          together with the number of free scans used. The address itself is not kept, and the
          hash is deleted after the month ends.
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
