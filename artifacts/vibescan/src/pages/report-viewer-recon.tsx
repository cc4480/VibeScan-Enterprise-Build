/** The reconnaissance card: DNS, subdomains and open ports. */
import { Globe, Network } from "lucide-react";
import { cn } from "@/lib/utils";
import { useState } from "react";

// ─── Recon card ───────────────────────────────────────────────────────────────

export const DANGEROUS_RECON_PORTS = new Set([23, 445, 2375, 6379, 27017, 9200, 1433, 3306, 5432, 3389, 11211, 5984, 1521, 27018]);

export const MEDIUM_RECON_PORTS = new Set([2376, 8888, 9000]);

export interface ReconData {
  subdomains?: Array<{ subdomain: string; ip?: string | null; cname?: string | null; source: string }>;
  openPorts?: Array<{ port: number; service: string; banner?: string | null }>;
  dnsRecords?: Array<{ type: string; value: string; ttl?: number }>;
  reconDurationMs?: number;
}

export function ReconCard({ recon }: { recon: ReconData }) {
  const [section, setSection] = useState<"ports" | "dns" | "subdomains">("ports");

  const portCount = recon.openPorts?.length ?? 0;
  const dnsCount = recon.dnsRecords?.length ?? 0;
  const subCount = recon.subdomains?.length ?? 0;

  if (portCount === 0 && dnsCount === 0 && subCount === 0) return null;

  const tabs = [
    { key: "ports" as const,      label: "Open Ports",  count: portCount,  show: true },
    { key: "dns" as const,        label: "DNS Records", count: dnsCount,   show: dnsCount > 0 },
    { key: "subdomains" as const, label: "Subdomains",  count: subCount,   show: subCount > 0 },
  ].filter((t) => t.show);

  return (
    <div className="glass-card rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between p-5 border-b border-white/5">
        <h3 className="text-sm font-bold flex items-center gap-2">
          <Network className="w-4 h-4 text-violet-400" />
          Reconnaissance
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-400 font-medium leading-none">
            network
          </span>
        </h3>
        {recon.reconDurationMs != null && (
          <span className="text-[10px] text-muted-foreground font-mono">
            {(recon.reconDurationMs / 1000).toFixed(1)}s
          </span>
        )}
      </div>

      {/* Tab nav */}
      <div className="flex border-b border-white/5">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setSection(tab.key)}
            className={cn(
              "flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium transition-colors border-b-2 -mb-px",
              section === tab.key
                ? "border-violet-500 text-violet-400"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {tab.label}
            <span className={cn(
              "px-1.5 py-0.5 rounded-full text-[10px] font-bold",
              section === tab.key ? "bg-violet-500/20 text-violet-400" : "bg-secondary text-muted-foreground",
            )}>
              {tab.count}
            </span>
          </button>
        ))}
      </div>

      <div className="p-4 max-h-72 overflow-y-auto">
        {/* Ports */}
        {section === "ports" && (
          portCount > 0 ? (
            <div className="space-y-1.5">
              {recon.openPorts!.map((p, i) => {
                const isDangerous = DANGEROUS_RECON_PORTS.has(p.port);
                const isMedium = MEDIUM_RECON_PORTS.has(p.port);
                return (
                  <div
                    key={i}
                    className={cn(
                      "flex items-start gap-3 p-2.5 rounded-lg text-xs border",
                      isDangerous ? "bg-red-500/5 border-red-500/20" :
                      isMedium   ? "bg-yellow-500/5 border-yellow-500/20" :
                                   "bg-secondary/40 border-white/5",
                    )}
                  >
                    <span className={cn(
                      "font-mono font-bold shrink-0 min-w-[3rem] text-right tabular-nums",
                      isDangerous ? "text-red-400" : isMedium ? "text-yellow-400" : "text-green-400",
                    )}>
                      {p.port}
                    </span>
                    <div className="flex-1 min-w-0">
                      <span className={cn(
                        "font-medium",
                        isDangerous ? "text-red-300" : isMedium ? "text-yellow-300" : "text-foreground/80",
                      )}>
                        {p.service}
                      </span>
                      {p.banner && (
                        <div className="mt-1 font-mono text-[10px] text-muted-foreground truncate" title={p.banner}>
                          {p.banner}
                        </div>
                      )}
                    </div>
                    {isDangerous && (
                      <span className="shrink-0 px-1.5 py-0.5 bg-red-500/15 text-red-400 border border-red-500/25 rounded text-[10px] font-bold leading-none">
                        !
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-muted-foreground">
              No open ports detected in the scanned range.
            </div>
          )
        )}

        {/* DNS */}
        {section === "dns" && (
          dnsCount > 0 ? (
            <div className="space-y-0.5">
              {recon.dnsRecords!.map((r, i) => (
                <div key={i} className="flex items-start gap-2 py-1.5 border-b border-white/5 last:border-0 text-xs">
                  <span className="shrink-0 px-1.5 py-0.5 bg-green-500/10 border border-green-500/20 text-green-400 rounded font-mono text-[10px] font-bold min-w-[3rem] text-center leading-none mt-0.5">
                    {r.type}
                  </span>
                  <span className="font-mono text-muted-foreground break-all leading-relaxed">{r.value}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-muted-foreground">No DNS records found.</div>
          )
        )}

        {/* Subdomains */}
        {section === "subdomains" && (
          subCount > 0 ? (
            <div className="space-y-0.5">
              {recon.subdomains!.map((s, i) => (
                <div key={i} className="flex items-center gap-2 py-1.5 border-b border-white/5 last:border-0 text-xs">
                  <Globe className="w-3 h-3 text-muted-foreground/50 shrink-0" />
                  <span className="font-mono text-foreground/80 truncate flex-1">{s.subdomain}</span>
                  {s.ip && (
                    <span className="font-mono text-muted-foreground text-[10px] shrink-0 tabular-nums">{s.ip}</span>
                  )}
                  <span className={cn(
                    "shrink-0 text-[9px] px-1 py-0.5 rounded font-medium border leading-none",
                    s.source === "crt.sh"
                      ? "bg-sky-500/10 text-sky-400/70 border-sky-500/20"
                      : "bg-secondary text-muted-foreground/50 border-white/5",
                  )}>
                    {s.source}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-muted-foreground">No subdomains discovered.</div>
          )
        )}
      </div>
    </div>
  );
}
