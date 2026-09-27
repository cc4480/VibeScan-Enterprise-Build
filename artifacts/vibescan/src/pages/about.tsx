import { UserRound, ShieldCheck, Sparkles, Mail, ListChecks } from "lucide-react";
import { Link } from "wouter";
import { useSeo } from "@/lib/seo";

// The founder page. Written from Carlos's own account (2026-09-24) and kept to
// what he said: self-taught, years as a computer technician (networking,
// Windows repair), then building with AI models. Nothing here is a credential
// he did not claim — the whole product promise is not overclaiming.

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
      "Meet Carlos Cuellar, the self-taught builder behind SecScan, and the promises the scanner keeps: report what it found, and say plainly what it didn't test.",
  });

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
      <h1 className="text-2xl sm:text-3xl font-bold tracking-tight mb-2">About SecScan</h1>
      <p className="text-sm text-muted-foreground mb-10">
        SecScan is built by Carlos Cuellar.
      </p>

      <Section icon={UserRound} title="Who builds it">
        <p>
          I'm <strong className="text-foreground">Carlos Cuellar</strong>, and I'm self-taught. For years I
          worked on computers as a technician: repairing Windows machines and doing networking work. Then I
          picked up an AI model and haven't stopped since.
        </p>
        <p>
          I've worked with hundreds of models, prompting and re-prompting until ten words were enough to build
          what I wanted. That taught me something the hard way: you are only as good as the model you're
          using, and a model rarely tells you what it left out.
        </p>
      </Section>

      <Section icon={ShieldCheck} title="Why SecScan exists">
        <p>
          AI tools made it possible to ship an app in a weekend. They didn't make it safe. The same problems
          keep reaching production: databases anyone can read, secret keys in the front-end code, config
          files left public. None of them show up when you click around your own app.
        </p>
        <p>
          SecScan checks a live app from the outside and explains what it finds in plain English, with a fix
          you can paste straight back into the AI editor you built it with.
        </p>
      </Section>

      <Section icon={ListChecks} title="What SecScan promises">
        <p>I built SecScan not to be another tool that claims more than it delivers. So it keeps these rules:</p>
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
            against well-run sites, where it must stay quiet.
          </li>
          <li>
            <strong className="text-foreground">Active tests only on sites you prove you own.</strong> Anything
            that sends real attack traffic waits for a DNS record or a file on your domain.
          </li>
          <li>
            <strong className="text-foreground">No certificates it can't give.</strong> SecScan is an automated
            scanner, not a penetration test, and never says your app is "compliant" or "certified".
          </li>
        </ul>
      </Section>

      <Section icon={Sparkles} title="Built with AI, like the apps it checks">
        <p>
          SecScan itself was built the way many of its users build: with AI models, one prompt at a time, then
          tested until its results could be trusted. That's exactly why it exists. I know how fast AI lets you
          ship, and how easy it is to miss what it didn't do.
        </p>
      </Section>

      <Section icon={Mail} title="Get in touch">
        <p>
          Questions, a finding you think is wrong, or an idea:{" "}
          <a href={`mailto:${CONTACT}`} className="text-primary hover:underline">{CONTACT}</a>. You can also use
          the feedback button in the corner of any page.
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
