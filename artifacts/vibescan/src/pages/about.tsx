import { UserRound, ShieldCheck, Sparkles, Mail, ListChecks, Radar, FlaskConical } from "lucide-react";
import { Link } from "wouter";
import { useSeo } from "@/lib/seo";

// The founder page, in the third person. The background is Carlos's own account
// (2026-09-24) and is kept to what was said: self-taught, years as a computer
// technician (networking, Windows repair), then building with AI models. Nothing
// here is a credential he did not claim — the whole product promise is not
// overclaiming. No pronouns for him: none were given, so the page uses his name.
// The product facts (monitoring, badge, free tier) are the shipped behaviour;
// prices and counts are deliberately not written here, so the page cannot go stale.

const CONTACT = "hello@secscan.us";

function Section({
  icon: Icon,
  title,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-10">
      <h2 className="text-lg sm:text-xl font-bold tracking-tight mb-4 flex items-center gap-2">
        <Icon className="w-4 h-4 text-primary shrink-0" />
        {title}
      </h2>
      <div className="space-y-3 text-sm sm:text-[15px] leading-relaxed text-muted-foreground">{children}</div>
    </section>
  );
}

export default function AboutPage() {
  useSeo({
    title: "About SecScan.us — Carlos Cuellar, founder",
    description:
      "SecScan is a web application security scanner built by Carlos Cuellar, a self-taught former computer technician. Who built it, why, and the promises it keeps: report what it found, and say plainly what it did not test.",
  });

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
      <h1 className="text-2xl sm:text-3xl font-bold tracking-tight mb-2">About SecScan</h1>
      <p className="text-sm sm:text-base text-muted-foreground mb-10 leading-relaxed">
        SecScan checks a live web application from the outside, explains what it finds in plain English, and
        says plainly what it did not test. It was built by Carlos Cuellar.
      </p>

      <Section icon={UserRound} title="Who builds it">
        <p>
          <strong className="text-foreground">Carlos Cuellar</strong> is self-taught. For years Cuellar worked
          on computers as a technician, repairing Windows machines and doing networking work. Then came an AI
          model, and the work has not stopped since.
        </p>
        <p>
          Cuellar has worked with hundreds of models, prompting and re-prompting until ten words were enough to
          build what was wanted. That taught a lesson the hard way: a builder is only as good as the model in
          use, and a model rarely says what it left out. SecScan is built around that lesson.
        </p>
      </Section>

      <Section icon={ShieldCheck} title="Why SecScan exists">
        <p>
          AI tools made it possible to ship an app in a weekend. They did not make it safe. The same problems
          keep reaching production: databases anyone can read, secret keys in the front-end code, config files
          left public. None of them show up when someone clicks around their own app.
        </p>
        <p>
          SecScan looks at the live app the way an outsider would. Each problem comes with a plain-English
          explanation and a fix that can be pasted straight back into the AI editor the app was built with.
        </p>
      </Section>

      <Section icon={Radar} title="What it does today">
        <ul className="list-disc pl-5 space-y-2">
          <li>
            <strong className="text-foreground">Scans a live site</strong> and grades it A to F, with every
            finding explained and a fix to paste back into the editor.
          </li>
          <li>
            <strong className="text-foreground">Watches a site around the clock.</strong> Uptime, certificate and
            header checks run on a schedule, and a full rescan follows the grade: sites that score worse are
            looked at more often. Problems arrive by email. A first site is watched free; adding it uses one of
            the month's free scans for its first full scan.
          </li>
          <li>
            <strong className="text-foreground">Gives a site a grade badge</strong> for a README or a footer. A
            badge can only be made for a scan of a domain its owner has verified, so it cannot be borrowed from
            someone else's site. It shows the grade and the scan date, never the address or a finding, and it
            goes grey and says "old scan" once it is a month old.
          </li>
          <li>
            <strong className="text-foreground">Works inside AI editors and over an API,</strong> so a scan can
            be started, and its results read, without leaving the tool the app was built in.
          </li>
        </ul>
        <p>
          Every account gets free scans each month. A paid plan changes how many scans there are, never which
          checks run. See{" "}
          <a href="/#pricing" className="text-primary hover:underline">pricing</a> for the current plan.
        </p>
      </Section>

      <Section icon={ListChecks} title="What SecScan promises">
        <p>
          SecScan was built not to be another tool that claims more than it delivers. It keeps these rules:
        </p>
        <ul className="list-disc pl-5 space-y-2">
          <li>
            <strong className="text-foreground">It says what it didn't test.</strong> Every scan records which
            tests ran and which were skipped, and why. A clean report never quietly means "we didn't look".
          </li>
          <li>
            <strong className="text-foreground">The AI explains; it never invents.</strong> Findings come from
            the scanner. The AI writes the explanation and the fix, and is only allowed to talk about what the
            scan actually found.
          </li>
          <li>
            <strong className="text-foreground">It is tested against known answers.</strong> The scanner is run
            against a deliberately vulnerable app, where every problem is planted and must be caught, and
            against well-run sites, where it must stay quiet. The misses are published with the hits.
          </li>
          <li>
            <strong className="text-foreground">Active tests only on sites you prove you own.</strong> Anything
            that sends real attack traffic waits for a DNS record or a file on the domain. Until then the report
            names what is waiting.
          </li>
          <li>
            <strong className="text-foreground">Depth is never for sale.</strong> Free and paid scans run the
            same checks. A plan buys volume, not coverage.
          </li>
          <li>
            <strong className="text-foreground">No certificates it can't give.</strong> SecScan is an automated
            scanner, not a penetration test, and never says an app is "compliant" or "certified".
          </li>
        </ul>
      </Section>

      <Section icon={FlaskConical} title="The evidence">
        <p>
          A promise is only worth what can be checked. The test record is public, with the misses left in:
          a blind-judged comparison against two well-known scanners on an app with planted faults, sweeps of
          real, well-run sites with every high finding checked by hand, and a log of SecScan's own false
          positives and how each was fixed. It lives on{" "}
          <a href="https://secscan.info/testing" className="text-primary hover:underline">secscan.info/testing</a>{" "}
          and{" "}
          <a href="https://secscan.info/false-positives" className="text-primary hover:underline">
            secscan.info/false-positives
          </a>.
        </p>
      </Section>

      <Section icon={Sparkles} title="Built with AI, like the apps it checks">
        <p>
          SecScan itself was built the way many of its users build: with AI models, one prompt at a time, then
          tested until its results could be trusted. That is exactly why it exists. Cuellar knows how fast AI
          lets a person ship, and how easy it is to miss what it did not do.
        </p>
      </Section>

      <Section icon={Mail} title="Get in touch">
        <p>
          Questions, a finding that looks wrong, or an idea:{" "}
          <a href={`mailto:${CONTACT}`} className="text-primary hover:underline">{CONTACT}</a>. The feedback
          button in the corner of any page works too.
        </p>
        <p>
          <Link href="/scan" className="text-primary hover:underline">Scan your app</Link>
          {" · "}
          <Link href="/learn" className="text-primary hover:underline">How the checks work</Link>
          {" · "}
          <a href="https://secscan.info" className="text-primary hover:underline">Full reference on secscan.info</a>
        </p>
      </Section>
    </div>
  );
}
