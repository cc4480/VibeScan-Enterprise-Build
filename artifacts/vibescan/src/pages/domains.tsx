import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useSeo } from "@/lib/seo";
import { useToast } from "@/hooks/use-toast";
import {
  listDomainVerifications,
  startDomainVerification,
  checkDomainVerification,
  type DomainVerification,
} from "@/lib/domain-verification-api";
import {
  ShieldCheck,
  ShieldAlert,
  Globe,
  Copy,
  Check,
  Loader2,
  RefreshCw,
} from "lucide-react";

function getFriendlyError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err ?? "");
  if (!msg) return "Something went wrong. Please try again.";
  if (/unauthorized|401/i.test(msg)) return "Session expired. Please sign in again.";
  const clean = msg.replace(/^HTTP \d{3} [^:]+:\s*/, "");
  return clean.length > 160 ? clean.slice(0, 160) + "…" : clean;
}

/** Copy-to-clipboard control, since every value on this page has to be pasted somewhere else. */
function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard is blocked in some browsers and contexts; the value is
      // on screen and selectable, so this is not worth interrupting anyone over.
    }
  };

  return (
    <div className="mb-3 last:mb-0">
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground mb-1">{label}</div>
      <div className="flex items-stretch gap-2">
        <code className="flex-1 min-w-0 px-3 py-2 rounded-lg bg-black/30 border border-white/10 text-xs font-mono break-all">
          {value}
        </code>
        <button
          type="button"
          onClick={copy}
          aria-label={`Copy ${label}`}
          className="shrink-0 px-3 rounded-lg border border-white/10 hover:bg-white/5 transition-colors"
        >
          {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
        </button>
      </div>
    </div>
  );
}

function VerificationCard({ v }: { v: DomainVerification }) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [checking, setChecking] = useState(false);
  const [notYet, setNotYet] = useState<string | null>(null);

  const check = async () => {
    setChecking(true);
    setNotYet(null);
    try {
      const result = await checkDomainVerification(v.domain);
      if (result.verified) {
        queryClient.invalidateQueries({ queryKey: ["domain-verifications"] });
        toast({
          title: `${v.domain} verified`,
          description: "Active security testing is now enabled for this domain.",
        });
      } else {
        setNotYet(result.detail ?? "Not found yet. DNS changes can take a few minutes.");
      }
    } catch (err) {
      toast({ title: "Check failed", description: getFriendlyError(err), variant: "destructive" });
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="glass-card rounded-2xl p-5 sm:p-6">
      <div className="flex items-start justify-between gap-4 mb-4">
        <div className="flex items-center gap-3 min-w-0">
          <div
            className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border ${
              v.verified
                ? "bg-emerald-500/10 border-emerald-500/25"
                : "bg-amber-500/10 border-amber-500/25"
            }`}
          >
            {v.verified ? (
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            ) : (
              <ShieldAlert className="w-5 h-5 text-amber-400" />
            )}
          </div>
          <div className="min-w-0">
            <div className="font-semibold truncate">{v.domain}</div>
            <div className="text-xs text-muted-foreground">
              {v.verified
                ? `Verified${v.method === "dns" ? " by DNS record" : v.method === "well_known" ? " by file" : ""}`
                : "Awaiting verification"}
            </div>
          </div>
        </div>

        {!v.verified && (
          <button
            type="button"
            onClick={check}
            disabled={checking}
            className="shrink-0 inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-primary-foreground text-sm font-semibold disabled:opacity-60"
          >
            {checking ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
            {checking ? "Checking…" : "Check now"}
          </button>
        )}
      </div>

      {!v.verified && (
        <>
          <p className="text-sm text-muted-foreground mb-4">
            Do <strong>either</strong> of these, then press Check now.
          </p>

          <div className="rounded-xl border border-white/10 p-4 mb-3">
            <div className="text-sm font-semibold mb-3">Option 1 — DNS record</div>
            <CopyField label="Record name" value={v.dns.name} />
            <CopyField label="Type" value={v.dns.type} />
            <CopyField label="Value" value={v.dns.value} />
          </div>

          <div className="rounded-xl border border-white/10 p-4">
            <div className="text-sm font-semibold mb-3">Option 2 — File on your site</div>
            <CopyField label="Upload to this URL" value={v.wellKnown.url} />
            <CopyField label="Containing exactly" value={v.wellKnown.content} />
          </div>

          {notYet && (
            <p className="mt-4 text-sm text-amber-400/90 leading-relaxed">{notYet}</p>
          )}
        </>
      )}
    </div>
  );
}

export default function DomainsPage() {
  useSeo({ title: "Verified domains — SecScan", noindex: true });
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [domainInput, setDomainInput] = useState("");
  const [adding, setAdding] = useState(false);

  const { data: verifications, isLoading, error } = useQuery({
    queryKey: ["domain-verifications"],
    queryFn: listDomainVerifications,
  });

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    const domain = domainInput.trim();
    if (!domain) return;

    setAdding(true);
    try {
      await startDomainVerification(domain);
      setDomainInput("");
      queryClient.invalidateQueries({ queryKey: ["domain-verifications"] });
    } catch (err) {
      toast({ title: "Couldn't add domain", description: getFriendlyError(err), variant: "destructive" });
    } finally {
      setAdding(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="mb-10">
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mb-3">Verified domains</h1>
        <p className="text-muted-foreground text-lg">
          We only send real attack traffic at sites whose owner has asked us to.
        </p>
      </div>

      <div className="glass-panel p-6 sm:p-8 rounded-3xl mb-8">
        <div className="flex items-start gap-4 mb-6">
          <div className="w-12 h-12 rounded-2xl bg-primary/10 flex items-center justify-center border border-primary/20 shrink-0">
            <Globe className="w-6 h-6 text-primary" />
          </div>
          <div>
            <h2 className="text-xl font-bold mb-1">Why this exists</h2>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Any domain can be scanned for the things an ordinary visitor can see — exposed
              files, security headers, TLS, out-of-date software. The checks that actively
              test for flaws — SQL injection, cross-site scripting, path traversal, broken
              access control, exposed databases and port scanning — send real attack traffic,
              so we run those only against domains you have proven you control.
            </p>
          </div>
        </div>

        <form onSubmit={add} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            placeholder="example.com"
            aria-label="Domain to verify"
            className="flex-1 px-4 py-3 rounded-xl bg-black/30 border border-white/10 text-sm focus:outline-none focus:border-primary/50"
          />
          <button
            type="submit"
            disabled={adding || !domainInput.trim()}
            className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-primary text-primary-foreground font-semibold text-sm disabled:opacity-60"
          >
            {adding && <Loader2 className="w-4 h-4 animate-spin" />}
            Add domain
          </button>
        </form>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-muted-foreground text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading your domains…
        </div>
      )}

      {error && (
        <p className="text-sm text-destructive">{getFriendlyError(error)}</p>
      )}

      {verifications && verifications.length === 0 && (
        <div className="glass-card rounded-2xl p-8 text-center">
          <ShieldAlert className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">
            No domains yet. Add the one you want fully tested.
          </p>
        </div>
      )}

      <div className="space-y-4">
        {verifications?.map((v) => (
          <VerificationCard key={v.domain} v={v} />
        ))}
      </div>
    </div>
  );
}
