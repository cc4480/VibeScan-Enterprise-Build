import { Bot, ShieldCheck, Eye, Lock, Mail } from "lucide-react";
import { useSeo } from "@/lib/seo";

// The page the scanner's User-Agent points at:
//   Mozilla/5.0 (compatible; SecScan-Security-Bot/1.0; +https://secscan.us/bot)
//
// A site owner or security team who sees that string in their logs follows the
// URL to find out who is probing them. The whole allowlist-your-own-auditor
// flow depends on this page existing and being clear — for a long time the UA
// promised it and it 404'd. It is deliberately plain and factual: it is read by
// someone deciding whether to trust traffic they are already seeing.

const CONTACT = "hello@secscan.us";
const USER_AGENT =
  "Mozilla/5.0 (compatible; SecScan-Security-Bot/1.0; +https://secscan.us/bot)";
const UA_TOKEN = "SecScan-Security-Bot";

function Section({
  icon: Icon,
  title,
  children,
}: {
  icon?: React.ComponentType<{ className?: string }>;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-10">
      <h2 className="text-lg sm:text-xl font-bold tracking-tight mb-4 flex items-center gap-2">
        {Icon && <Icon className="w-4 h-4 text-primary shrink-0" />}
        {title}
      </h2>
      <div className="space-y-3 text-sm sm:text-[15px] leading-relaxed text-muted-foreground">
        {children}
      </div>
    </section>
  );
}

export default function BotPage() {
  useSeo({
    title: "SecScan Security Bot — secscan.us/bot",
    description:
      "What the SecScan scanner is, how to recognise it in your logs, and how to let it scan a site you own.",
  });

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="flex items-center gap-3 mb-2">
        <div className="w-11 h-11 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
          <Bot className="w-5 h-5 text-primary" />
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">SecScan Security Bot</h1>
      </div>
      <p className="text-sm text-muted-foreground mb-10">
        You are probably here because you saw this bot in your server logs.
      </p>

      <Section icon={ShieldCheck} title="What this is">
        <p>
          <strong className="text-foreground">SecScan</strong> is a web security scanner at{" "}
          <a href="https://secscan.us" className="text-primary hover:underline">secscan.us</a>.
          It checks a site for common security problems — missing or weak HTTP security
          headers, cookie flags, TLS configuration, exposed files, out-of-date
          libraries with known CVEs, and email-authentication (SPF/DMARC/DNSSEC)
          records — and returns a graded report.
        </p>
        <p>
          A person asked us to scan the target that pointed us at you. We are not
          crawling the web at large, and we are not looking for anything to exploit.
        </p>
      </Section>

      <Section icon={Eye} title="How to recognise it">
        <p>Our scanner identifies itself honestly. Every request carries this User-Agent:</p>
        <pre className="text-xs sm:text-[13px] bg-secondary/40 border border-white/10 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-all text-foreground">
          {USER_AGENT}
        </pre>
        <p>
          The stable part to match is the token{" "}
          <code className="text-foreground bg-secondary/40 px-1.5 py-0.5 rounded">{UA_TOKEN}</code>.
          We do not spoof browser User-Agents, rotate through residential IP pools,
          or attempt to evade bot-protection — doing any of that is the behaviour a
          security scanner exists to detect, so we will not do it to reach a target.
        </p>
      </Section>

      <Section icon={Lock} title="What it will and will not do">
        <p>
          <strong className="text-foreground">By default a scan is passive.</strong> It
          makes ordinary GET requests and DNS lookups against pages you already serve
          publicly. It does not attempt to sign in, submit forms, alter data, or send
          attack payloads.
        </p>
        <p>
          <strong className="text-foreground">Active testing</strong> — injection probes,
          path traversal, a port check — runs <em>only</em> against a domain whose
          ownership the requester has proven to us, by a DNS TXT record or a
          well-known file. If ownership is not proven, the scan stays passive. This is
          the control that stops SecScan being used as an anonymous attack proxy.
        </p>
      </Section>

      <Section icon={ShieldCheck} title="If you own this site and want to let it in">
        <p>
          A bot-protection layer (Cloudflare, DataDome and the like) that answers our
          request instead of your origin means we scan the challenge page, not your
          site — the report will say so and will not be graded. To get a real scan of
          your own site, either of these works:
        </p>
        <ul className="list-disc pl-5 space-y-2">
          <li>
            <strong className="text-foreground">Allowlist the scanner by User-Agent</strong>{" "}
            in your WAF or bot rules for the duration of a scan — match the{" "}
            <code className="text-foreground bg-secondary/40 px-1 py-0.5 rounded">{UA_TOKEN}</code>{" "}
            token. This is the stable identifier; our source IP is not guaranteed
            fixed, so prefer the User-Agent over an IP allowlist. If your controls
            can only match by IP, email us and we will confirm the current source
            address.
          </li>
          <li>
            <strong className="text-foreground">Verify domain ownership</strong> in the
            app, which both unlocks active testing and identifies the scan as
            authorised.
          </li>
        </ul>
        <p>
          This is you letting your own auditor through your own front door — not a
          bypass of anyone else&rsquo;s protection, which we neither do nor support.
        </p>
      </Section>

      <Section icon={Mail} title="Stop it, or ask a question">
        <p>
          If you did not expect this traffic and want it to stop, or you want to
          confirm a request was legitimate, email{" "}
          <a href={`mailto:${CONTACT}`} className="text-primary hover:underline">{CONTACT}</a>{" "}
          with the timestamp and the target hostname from your logs and we will look
          into it.
        </p>
      </Section>

      <p className="text-xs text-muted-foreground border-t border-white/10 pt-6">
        Questions about this page: {CONTACT}
      </p>
    </div>
  );
}
