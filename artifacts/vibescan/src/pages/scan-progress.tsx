import { useEffect, useRef, useState } from "react";
import { useLocation, useParams, useSearch } from "wouter";
import { useGetScanStatus } from "@workspace/api-client-react";
import {
  Globe, Lock, FileSearch, Shield, Zap, Cpu, ShieldAlert, Mail, Network,
  MapPin, Code2, Layers, Database, FileText, Cloud, GitBranch, RefreshCw,
  Sparkles, BarChart2, CheckCircle2, Circle, Loader2, XCircle, Clock, AlertTriangle,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Step definitions ─────────────────────────────────────────────────────────
//
// Every step here maps 1-to-1 with a real probe in the API scanner:
//
//   fetch         → runScan() initial fetch + redirect follow
//   crawl         → crawlAndCheck() — basic: root only, deep: up to 20 pages
//   tls           → checkSslLabs() (worker.ts, parallel) + inline TLS detection
//   headers       → inline header analysis in runScan() (CSP, HSTS, X-Frame-Options…)
//   probes        → runAllProbes() — 12 active HTTP probes (open redirect, rate limiting,
//                   HTTP methods, sensitive files, directory listing, SRI, error disclosure,
//                   clickjacking, HTTPS redirect, security.txt, robots.txt, CORS)
//   cors          → analyzeCookies() + checkActiveCors() inside runAllProbes
//   tech          → detectTechnologies() in runScan()
//   cve           → checkForKnownVulnerabilities() via cveCheck.ts
//   dns           → checkDnsSecurity() via dnsChecks.ts (SPF/DMARC/DKIM/DNSSEC)
//   recon         → runRecon() (worker.ts, parallel) + checkSubdomainTakeover()
//   sourcemaps    → checkSourceMaps() + analyzeJwts()
//   nextjs        → runNextjsProbe() (__NEXT_DATA__ prop leaks)
//   graphql       → runGraphqlProbe()
//   baas          → runBaasProbes() (Supabase, Firebase, PocketBase, Appwrite)
//   docs          → runApiDocsProbe()
//   storage       → runStorageProbe()
//   js            → scanJavaScriptForSecrets() — DEEP ONLY
//   pathtraversal → checkPathTraversal()       — DEEP ONLY
//   reprobe       → reprobe() + corroborateMerge() in worker.ts
//   ai            → callDeepSeek()             — DEEP ONLY
//   score         → computeRiskScore() / computeGrade()

interface ScanStep {
  id: string;
  label: string;
  sublabel: string;
  icon: React.ComponentType<{ className?: string }>;
  phase: "scanning" | "analyzing";
  ms: number;
  deepOnly?: boolean;
}

const ALL_STEPS: ScanStep[] = [
  // ── Scanning phase ────────────────────────────────────────────────────────
  {
    id: "fetch",
    label: "Connecting to target",
    sublabel: "Fetching the page and following redirects",
    icon: Globe,
    phase: "scanning",
    ms: 2000,
  },
  {
    id: "crawl",
    label: "Page crawl & content scan",
    sublabel: "Deep scan crawls up to 20 inner pages; basic scans the root",
    icon: FileSearch,
    phase: "scanning",
    ms: 4000,
  },
  {
    id: "tls",
    label: "HTTPS & TLS certificate",
    sublabel: "Full TLS assessment via SSL Labs — protocols, ciphers, certificate expiry",
    icon: Lock,
    phase: "scanning",
    ms: 8000,
  },
  {
    id: "headers",
    label: "Security headers review",
    sublabel: "CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, mixed content",
    icon: Shield,
    phase: "scanning",
    ms: 3000,
  },
  {
    id: "probes",
    label: "Active HTTP security probes",
    sublabel: "Open redirects, rate limiting, HTTP methods, sensitive file exposure, SRI, directory listing, error disclosure",
    icon: Zap,
    phase: "scanning",
    ms: 5000,
  },
  {
    id: "cors",
    label: "CORS & cookie security",
    sublabel: "Cross-origin policy audit and cookie flag review (Secure, HttpOnly, SameSite)",
    icon: ShieldAlert,
    phase: "scanning",
    ms: 3000,
  },
  {
    id: "tech",
    label: "Technology fingerprinting",
    sublabel: "Identifying 50+ frameworks, servers, CDNs, analytics tools, and JS libraries",
    icon: Cpu,
    phase: "scanning",
    ms: 2000,
  },
  {
    id: "cve",
    label: "Known CVE & version audit",
    sublabel: "Detected framework versions matched against the NVD vulnerability database",
    icon: ShieldAlert,
    phase: "scanning",
    ms: 4000,
  },
  {
    id: "dns",
    label: "DNS & email security",
    sublabel: "SPF, DMARC, DKIM, and DNSSEC record validation",
    icon: Mail,
    phase: "scanning",
    ms: 4000,
  },
  {
    id: "recon",
    label: "Subdomain & port recon",
    sublabel: "crt.sh subdomain enumeration, CNAME takeover check, dangerous port scan",
    icon: Network,
    phase: "scanning",
    ms: 6000,
  },
  {
    id: "sourcemaps",
    label: "Source map & JWT exposure",
    sublabel: "Discovering exposed .map files and analysing JWT role claims in headers and HTML",
    icon: MapPin,
    phase: "scanning",
    ms: 3000,
  },
  {
    id: "nextjs",
    label: "Framework-specific probes",
    sublabel: "Next.js __NEXT_DATA__ prop leaks, build manifest and route exposure",
    icon: GitBranch,
    phase: "scanning",
    ms: 4000,
  },
  {
    id: "graphql",
    label: "GraphQL endpoint discovery",
    sublabel: "Introspection and field-suggestion leak testing",
    icon: Layers,
    phase: "scanning",
    ms: 5000,
  },
  {
    id: "baas",
    label: "BaaS security analysis",
    sublabel: "Supabase RLS, Firebase rules, PocketBase, and Appwrite open-data checks",
    icon: Database,
    phase: "scanning",
    ms: 5000,
  },
  {
    id: "docs",
    label: "API documentation exposure",
    sublabel: "Swagger, OpenAPI, and ReDoc endpoint discovery",
    icon: FileText,
    phase: "scanning",
    ms: 4000,
  },
  {
    id: "storage",
    label: "Cloud storage listing",
    sublabel: "Publicly listable S3, GCS, and Azure Blob containers",
    icon: Cloud,
    phase: "scanning",
    ms: 4000,
  },
  {
    id: "js",
    label: "JavaScript secret scanning",
    sublabel: "Scanning inline scripts and JS bundles for exposed API keys, tokens, and credentials",
    icon: Code2,
    phase: "scanning",
    ms: 6000,
    deepOnly: true,
  },
  {
    id: "pathtraversal",
    label: "Path traversal testing",
    sublabel: "Active directory and path traversal probing across URL parameters",
    icon: FileSearch,
    phase: "scanning",
    ms: 5000,
    deepOnly: true,
  },
  {
    id: "reprobe",
    label: "Cross-verifying findings",
    sublabel: "Re-probing borderline results and merging duplicate root-cause findings",
    icon: RefreshCw,
    phase: "scanning",
    ms: 5000,
  },
  // ── Analyzing phase ───────────────────────────────────────────────────────
  {
    id: "ai",
    label: "AI-powered security analysis",
    sublabel: "DeepSeek generating prioritised findings, attack chains, and your remediation guide",
    icon: Sparkles,
    phase: "analyzing",
    ms: 20000,
    deepOnly: true,
  },
  {
    id: "score",
    label: "Computing risk score & grade",
    sublabel: "Scoring all findings and writing your executive summary",
    icon: BarChart2,
    phase: "analyzing",
    ms: 3000,
  },
];

type StepStatus = "pending" | "running" | "done";

function getVisibleSteps(tier: string): ScanStep[] {
  return ALL_STEPS.filter((s) => tier === "deep" || !s.deepOnly);
}

function computeStepStatuses(
  steps: ScanStep[],
  scanStatus: string,
  scanningElapsedMs: number,
  analyzingElapsedMs: number,
): StepStatus[] {
  const scanningSteps = steps.filter((s) => s.phase === "scanning");
  const analyzingSteps = steps.filter((s) => s.phase === "analyzing");

  if (
    scanStatus === "queued" ||
    scanStatus === "paid" ||
    scanStatus === "pending"
  ) {
    return steps.map(() => "pending");
  }

  if (scanStatus === "failed") {
    return steps.map(() => "pending");
  }

  if (scanStatus === "scanning") {
    // Advance through scanning steps based on elapsed time.
    // The last step is always "running" while the backend still reports "scanning" —
    // we never mark it done until the status actually transitions.
    let accumulated = 0;
    let activeIdx = scanningSteps.length - 1;
    for (let i = 0; i < scanningSteps.length; i++) {
      if (scanningElapsedMs < accumulated + scanningSteps[i].ms) {
        activeIdx = i;
        break;
      }
      accumulated += scanningSteps[i].ms;
    }
    return steps.map((step) => {
      if (step.phase === "analyzing") return "pending";
      const idx = scanningSteps.indexOf(step);
      if (idx < activeIdx) return "done";
      if (idx === activeIdx) return "running";
      return "pending";
    });
  }

  if (scanStatus === "analyzing") {
    let accumulated = 0;
    let activeIdx = analyzingSteps.length - 1;
    for (let i = 0; i < analyzingSteps.length; i++) {
      if (analyzingElapsedMs < accumulated + analyzingSteps[i].ms) {
        activeIdx = i;
        break;
      }
      accumulated += analyzingSteps[i].ms;
    }
    return steps.map((step) => {
      if (step.phase === "scanning") return "done";
      const idx = analyzingSteps.indexOf(step);
      if (idx < activeIdx) return "done";
      if (idx === activeIdx) return "running";
      return "pending";
    });
  }

  if (scanStatus === "complete") {
    return steps.map(() => "done");
  }

  return steps.map(() => "pending");
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getDomain(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

const STATUS_LABEL: Record<string, string> = {
  pending: "Waiting…",
  paid: "Payment confirmed — queuing…",
  queued: "In queue — waiting for a worker slot",
  scanning: "Scanning your site…",
  analyzing: "Generating your security report…",
  complete: "All done — redirecting to your report",
  failed: "Scan failed",
};

// ─── Page component ───────────────────────────────────────────────────────────

export default function ScanProgressPage() {
  const params = useParams<{ id: string }>();
  const scanId = params.id;
  const search = useSearch();
  const [, setLocation] = useLocation();

  const tier = new URLSearchParams(search).get("tier") ?? "deep";

  const analyzingStartRef = useRef<number | null>(null);
  const redirectedRef = useRef(false);

  // Tick every 500ms to advance step animations based on elapsed time
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((n) => n + 1), 500);
    return () => clearInterval(id);
  }, []);

  // ── Status polling ────────────────────────────────────────────────────────
  const { data, isLoading, isError } = useGetScanStatus(scanId, {
    query: {
      refetchInterval: (query) => {
        const s = (query.state.data as { status?: string } | undefined)
          ?.status;
        if (s === "complete" || s === "failed") return false;
        return 2000;
      },
    },
  });

  // ── Note when analyzing phase starts ─────────────────────────────────────
  useEffect(() => {
    if (data?.status === "analyzing" && !analyzingStartRef.current) {
      analyzingStartRef.current = Date.now();
    }
  }, [data?.status]);

  // ── Redirect to report on complete ───────────────────────────────────────
  useEffect(() => {
    if (data?.status === "complete" && data.reportId && !redirectedRef.current) {
      redirectedRef.current = true;
      const t = setTimeout(() => setLocation(`/report/${data.reportId}`), 1500);
      return () => clearTimeout(t);
    }
    return undefined;
  }, [data?.status, data?.reportId, setLocation]);

  // ── Elapsed time ──────────────────────────────────────────────────────────
  const startedAt = data?.startedAt ? new Date(data.startedAt).getTime() : null;
  const scanningElapsedMs = startedAt ? Math.max(0, Date.now() - startedAt) : 0;
  const analyzingElapsedMs = analyzingStartRef.current
    ? Math.max(0, Date.now() - analyzingStartRef.current)
    : 0;

  // ── Derived state ─────────────────────────────────────────────────────────
  const steps = getVisibleSteps(tier);
  const statuses = computeStepStatuses(
    steps,
    data?.status ?? "queued",
    scanningElapsedMs,
    analyzingElapsedMs,
  );

  const doneCount = statuses.filter((s) => s === "done").length;
  const progress = data?.progress ?? 0;
  const domain = data?.targetUrl ? getDomain(data.targetUrl) : "target";
  const isFailed = data?.status === "failed";
  const isComplete = data?.status === "complete";
  const isQueued =
    !data?.status ||
    data.status === "queued" ||
    data.status === "paid" ||
    data.status === "pending";

  // ── Loading / error guards ─────────────────────────────────────────────────
  if (isLoading && !data) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-12 text-center">
        <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <p className="text-muted-foreground">Could not load scan status.</p>
        <button
          onClick={() => setLocation("/dashboard")}
          className="mt-4 text-sm text-primary hover:underline"
        >
          Back to dashboard
        </button>
      </div>
    );
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="max-w-2xl mx-auto px-4 sm:px-6 py-8">

      {/* ── Header ── */}
      <div className="text-center mb-8">
        <div
          className={cn(
            "w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-5 border",
            isComplete
              ? "bg-green-500/10 border-green-500/20"
              : isFailed
                ? "bg-red-500/10 border-red-500/20"
                : "bg-primary/10 border-primary/20",
          )}
        >
          {isComplete ? (
            <CheckCircle2 className="w-8 h-8 text-green-500" />
          ) : isFailed ? (
            <XCircle className="w-8 h-8 text-red-400" />
          ) : isQueued ? (
            <Clock className="w-8 h-8 text-primary" />
          ) : (
            <Loader2 className="w-8 h-8 text-primary animate-spin" />
          )}
        </div>

        <div className="flex items-center justify-center gap-2 mb-1.5">
          <h1 className="text-2xl font-bold tracking-tight">
            {isComplete ? "Scan Complete" : isFailed ? "Scan Failed" : domain}
          </h1>
          <span
            className={cn(
              "text-[11px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border",
              tier === "deep"
                ? "bg-primary/10 border-primary/20 text-primary"
                : "bg-white/5 border-white/10 text-muted-foreground",
            )}
          >
            {tier === "deep" ? "Deep" : "Basic"}
          </span>
        </div>

        <p className="text-sm text-muted-foreground">
          {STATUS_LABEL[data?.status ?? "queued"] ?? "Processing…"}
        </p>
      </div>

      {/* ── Steps card ── */}
      <div className="glass-panel rounded-3xl overflow-hidden">
        <div className="px-4 py-5 flex flex-col gap-0.5">
          {steps.map((step, i) => {
            const stepStatus = statuses[i];
            const Icon = step.icon;
            const isRunning = stepStatus === "running";
            const isDone = stepStatus === "done";

            return (
              <div
                key={step.id}
                className={cn(
                  "flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-500",
                  isRunning && "bg-primary/5 border border-primary/15",
                  isDone && "opacity-50",
                  !isRunning && !isDone && "opacity-20",
                )}
              >
                {/* Status dot */}
                <div className="shrink-0 w-5 flex justify-center">
                  {isDone && <CheckCircle2 className="w-4 h-4 text-green-500" />}
                  {isRunning && (
                    <Loader2 className="w-4 h-4 text-primary animate-spin" />
                  )}
                  {!isDone && !isRunning && (
                    <Circle className="w-3.5 h-3.5 text-muted-foreground/30" />
                  )}
                </div>

                {/* Step icon */}
                <div
                  className={cn(
                    "shrink-0 w-7 h-7 rounded-lg flex items-center justify-center",
                    isRunning ? "bg-primary/10" : "bg-white/5",
                  )}
                >
                  <Icon
                    className={cn(
                      "w-3.5 h-3.5",
                      isRunning ? "text-primary" : "text-muted-foreground",
                    )}
                  />
                </div>

                {/* Labels */}
                <div className="flex-1 min-w-0">
                  <span
                    className={cn(
                      "text-sm",
                      isRunning
                        ? "font-semibold text-foreground"
                        : "text-muted-foreground",
                    )}
                  >
                    {step.label}
                  </span>
                  {isRunning && (
                    <p className="text-xs text-muted-foreground/60 truncate leading-snug mt-0.5">
                      {step.sublabel}
                    </p>
                  )}
                </div>

                {isRunning && (
                  <span className="shrink-0 text-[10px] font-semibold text-primary/60 tracking-wide uppercase">
                    running
                  </span>
                )}
              </div>
            );
          })}
        </div>

        {/* ── Progress footer ── */}
        <div className="border-t border-white/5 px-6 py-5">
          <div className="flex justify-between text-xs text-muted-foreground mb-2">
            <span>
              {doneCount} / {steps.length} checks complete
            </span>
            <span>{progress}%</span>
          </div>
          <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
            <div
              className={cn(
                "h-full rounded-full transition-all duration-700 ease-out",
                isComplete
                  ? "bg-green-500"
                  : isFailed
                    ? "bg-red-500"
                    : "bg-primary",
              )}
              style={{ width: `${progress}%` }}
            />
          </div>

          {isQueued && (
            <p className="text-xs text-muted-foreground/50 text-center mt-3">
              Your scan will begin shortly…
            </p>
          )}
          {isComplete && (
            <p className="text-xs text-green-500/80 text-center mt-3 flex items-center justify-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Report ready — redirecting…
            </p>
          )}
          {isFailed && (
            <p className="text-xs text-red-400/70 text-center mt-3">
              {data?.error
                ? `Error: ${data.error}`
                : "Something went wrong during the scan."}{" "}
              <button
                onClick={() => setLocation("/dashboard")}
                className="underline hover:text-red-400"
              >
                Go to dashboard
              </button>
            </p>
          )}
        </div>
      </div>

      {/* ── Footer nav ── */}
      <div className="text-center mt-6">
        <button
          onClick={() => setLocation("/dashboard")}
          className="text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          ← Back to dashboard
        </button>
      </div>
    </div>
  );
}
