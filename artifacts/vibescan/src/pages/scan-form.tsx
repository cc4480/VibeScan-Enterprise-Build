import { useState } from "react";
import { useLocation } from "wouter";
import { useCreateScan, useGetCredits } from "@workspace/api-client-react";
import { Shield, Zap, Globe, Lock, CheckCircle2, Loader2, CreditCard } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ScanTier } from "@workspace/api-client-react/src/generated/api.schemas";

const TIERS: { id: ScanTier; name: string; price: string; desc: string; features: string[], popular?: boolean }[] = [
  {
    id: "basic",
    name: "Basic Scan",
    price: "$29",
    desc: "Core OWASP checks and headers",
    features: ["Header analysis", "SSL check", "Tech fingerprint"]
  },
  {
    id: "deep",
    name: "Deep Scan",
    price: "$79",
    desc: "Full analysis + DeepSeek AI report",
    features: ["Everything in Basic", "DeepSeek AI analysis", "Remediation guide"],
    popular: true
  },
  {
    id: "pack_5",
    name: "5-Scan Pack",
    price: "$99",
    desc: "5 Deep Scan credits (Save $296)",
    features: ["5 Deep Scans", "Never expires", "Priority queue"]
  },
  {
    id: "pack_20",
    name: "20-Scan Pack",
    price: "$299",
    desc: "For agencies and dev shops",
    features: ["20 Deep Scans", "Never expires", "Top priority"]
  }
];

export default function ScanFormPage() {
  const [url, setUrl] = useState("");
  const [tier, setTier] = useState<ScanTier>("deep");
  const [, setLocation] = useLocation();
  
  const { data: credits, isLoading: loadingCredits } = useGetCredits();
  const createScan = useCreateScan();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;
    
    // Auto-add https:// if missing
    let targetUrl = url;
    if (!/^https?:\/\//i.test(targetUrl)) {
      targetUrl = "https://" + targetUrl;
    }

    createScan.mutate({
      data: { targetUrl, tier }
    }, {
      onSuccess: (data) => {
        if (data.checkoutUrl) {
          window.location.href = data.checkoutUrl;
        } else {
          // Used a credit, go to dashboard
          setLocation(`/dashboard?scan=${data.scanId}`);
        }
      }
    });
  };

  const hasCredits = credits && credits.balance > 0;
  const isPack = tier === 'pack_5' || tier === 'pack_20';
  const willUseCredit = hasCredits && !isPack;

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="text-center mb-10">
        <div className="w-16 h-16 bg-primary/10 rounded-2xl flex items-center justify-center mx-auto mb-6 border border-primary/20">
          <Shield className="w-8 h-8 text-primary" />
        </div>
        <h1 className="text-3xl md:text-4xl font-bold tracking-tight mb-3">Launch Security Scan</h1>
        <p className="text-muted-foreground text-lg">Enter your live app URL and we'll analyze it for vulnerabilities.</p>
      </div>

      <div className="glass-panel p-6 sm:p-10 rounded-3xl">
        <form onSubmit={handleSubmit} className="flex flex-col gap-10">
          
          {/* URL Input */}
          <div className="flex flex-col gap-3">
            <label htmlFor="url" className="text-sm font-semibold flex items-center gap-2">
              <Globe className="w-4 h-4 text-primary" /> Target URL
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <Lock className="w-5 h-5 text-muted-foreground" />
              </div>
              <input
                id="url"
                type="text"
                placeholder="https://your-app.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
                className="w-full bg-background border-2 border-white/10 rounded-xl py-4 pl-12 pr-4 text-lg focus:outline-none focus:border-primary focus:ring-4 focus:ring-primary/10 transition-all placeholder:text-muted-foreground/50"
              />
            </div>
            <p className="text-xs text-muted-foreground ml-1">Must be a publicly accessible URL. Do not scan sites you don't own.</p>
          </div>

          {/* Tier Selection */}
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <label className="text-sm font-semibold flex items-center gap-2">
                <Zap className="w-4 h-4 text-primary" /> Select Plan
              </label>
              
              {!loadingCredits && hasCredits && (
                <div className="flex items-center gap-1.5 px-3 py-1 bg-primary/10 border border-primary/20 rounded-full text-xs font-medium text-primary">
                  <CreditCard className="w-3.5 h-3.5" />
                  {credits.balance} Credits Available
                </div>
              )}
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {TIERS.map((t) => (
                <label 
                  key={t.id}
                  className={cn(
                    "relative flex flex-col p-5 rounded-2xl cursor-pointer transition-all border-2",
                    tier === t.id 
                      ? "bg-primary/5 border-primary shadow-[0_0_20px_rgba(20,184,120,0.15)]" 
                      : "bg-secondary/50 border-white/5 hover:bg-secondary hover:border-white/10"
                  )}
                >
                  <input
                    type="radio"
                    name="tier"
                    value={t.id}
                    checked={tier === t.id}
                    onChange={() => setTier(t.id as ScanTier)}
                    className="sr-only"
                  />
                  {t.popular && (
                    <span className="absolute -top-3 right-4 px-2 py-0.5 bg-primary text-primary-foreground text-[10px] font-bold uppercase tracking-wider rounded-full">
                      Recommended
                    </span>
                  )}
                  <div className="flex justify-between items-start mb-2">
                    <div>
                      <div className="font-bold text-lg">{t.name}</div>
                      <div className="text-sm text-muted-foreground">{t.desc}</div>
                    </div>
                    <div className="font-display font-bold text-xl">{t.price}</div>
                  </div>
                  <ul className="mt-4 flex flex-col gap-1.5 flex-1">
                    {t.features.map((f, i) => (
                      <li key={i} className="text-xs flex items-center gap-1.5 text-muted-foreground">
                        <CheckCircle2 className="w-3.5 h-3.5 text-primary/70 shrink-0" /> {f}
                      </li>
                    ))}
                  </ul>
                  
                  <div className={cn(
                    "mt-5 w-full py-2 rounded-lg text-center text-sm font-semibold transition-colors",
                    tier === t.id ? "bg-primary text-primary-foreground" : "bg-white/5 text-muted-foreground"
                  )}>
                    Select Plan
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Submit */}
          <div className="pt-6 border-t border-white/5 flex flex-col items-center">
            <button
              type="submit"
              disabled={createScan.isPending || !url}
              className="w-full sm:w-auto min-w-[240px] px-8 py-4 bg-primary text-primary-foreground text-lg font-bold rounded-xl shadow-[0_0_30px_rgba(20,184,120,0.25)] hover:shadow-[0_0_40px_rgba(20,184,120,0.4)] disabled:opacity-50 disabled:hover:shadow-[0_0_30px_rgba(20,184,120,0.25)] disabled:cursor-not-allowed transition-all duration-300 flex items-center justify-center gap-2"
            >
              {createScan.isPending ? (
                <><Loader2 className="w-5 h-5 animate-spin" /> Initializing...</>
              ) : willUseCredit ? (
                <><Zap className="w-5 h-5" /> Start Scan (Uses 1 Credit)</>
              ) : (
                <><CreditCard className="w-5 h-5" /> Proceed to Checkout</>
              )}
            </button>
            {createScan.isError && (
              <p className="mt-4 text-red-400 text-sm">{createScan.error.message || "Failed to create scan"}</p>
            )}
          </div>

        </form>
      </div>
    </div>
  );
}
