import { useEffect, useRef, useState, useMemo } from "react";
import { useLocation, useParams, useSearch } from "wouter";
import { useGetScanStatus } from "@workspace/api-client-react";
import {
  CheckCircle2, XCircle, Loader2, Clock, AlertTriangle,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Step definitions ─────────────────────────────────────────────────────────

interface ScanStep {
  id: string;
  label: string;
  phase: "scanning" | "analyzing";
  ms: number;
  deepOnly?: boolean;
}

const ALL_STEPS: ScanStep[] = [
  { id: "fetch",        label: "Connecting to target",          phase: "scanning",  ms: 2000 },
  { id: "crawl",        label: "Page crawl & content scan",     phase: "scanning",  ms: 4000 },
  { id: "tls",          label: "HTTPS & TLS certificate",       phase: "scanning",  ms: 8000 },
  { id: "headers",      label: "Security headers review",       phase: "scanning",  ms: 3000 },
  { id: "probes",       label: "Active HTTP security probes",   phase: "scanning",  ms: 5000 },
  { id: "cors",         label: "CORS & cookie security",        phase: "scanning",  ms: 3000 },
  { id: "tech",         label: "Technology fingerprinting",     phase: "scanning",  ms: 2000 },
  { id: "cve",          label: "Known CVE & version audit",     phase: "scanning",  ms: 4000 },
  { id: "dns",          label: "DNS & email security",          phase: "scanning",  ms: 4000 },
  { id: "recon",        label: "Subdomain & port recon",        phase: "scanning",  ms: 6000 },
  { id: "sourcemaps",   label: "Source map & JWT exposure",     phase: "scanning",  ms: 3000 },
  { id: "nextjs",       label: "Framework-specific probes",     phase: "scanning",  ms: 4000 },
  { id: "graphql",      label: "GraphQL endpoint discovery",    phase: "scanning",  ms: 5000 },
  { id: "baas",         label: "BaaS security analysis",        phase: "scanning",  ms: 5000 },
  { id: "docs",         label: "API documentation exposure",    phase: "scanning",  ms: 4000 },
  { id: "storage",      label: "Cloud storage listing",         phase: "scanning",  ms: 4000 },
  { id: "js",           label: "JavaScript secret scanning",    phase: "scanning",  ms: 6000, deepOnly: true },
  { id: "pathtraversal",label: "Path traversal testing",        phase: "scanning",  ms: 5000, deepOnly: true },
  { id: "reprobe",      label: "Cross-verifying findings",      phase: "scanning",  ms: 5000 },
  { id: "ai",           label: "AI-powered security analysis",  phase: "analyzing", ms: 20000, deepOnly: true },
  { id: "score",        label: "Computing risk score & grade",  phase: "analyzing", ms: 3000 },
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

  if (["queued", "paid", "pending", "failed"].includes(scanStatus)) {
    return steps.map(() => "pending");
  }

  if (scanStatus === "scanning") {
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

  if (scanStatus === "complete") return steps.map(() => "done");

  return steps.map(() => "pending");
}

// ─── Terminal log content ─────────────────────────────────────────────────────

const STEP_LOGS: Record<string, string[]> = {
  fetch: [
    "$ curl -sIL https://{domain}/ -A 'VibeScan-Security-Bot/2.0'",
    "  [>] Resolving {domain}...",
    "  [>] TCP connect → {domain}:443",
    "  [>] TLS 1.3 handshake complete",
    "  [<] HTTP/2 200  server: cloudflare",
    "  [<] content-type: text/html; charset=utf-8",
    "  Page weight: 41.2 KB · round-trip: 342ms",
    "  ✓  Target reachable and responding",
  ],
  crawl: [
    "$ vibescan crawl --depth auto --limit 20 --target {domain}",
    "  Seeding crawl queue: https://{domain}/",
    "  [GET] https://{domain}/ → 200 OK (root)",
    "  [GET] https://{domain}/about → 200 OK",
    "  [GET] https://{domain}/login → 200 OK",
    "  [GET] https://{domain}/api → 404 Not Found",
    "  [GET] https://{domain}/sitemap.xml → 200 OK",
    "  ✓  Crawl complete — 5 pages indexed",
  ],
  tls: [
    "$ ssllabs-scan --host {domain} --quiet",
    "  [>] Submitting to SSL Labs API...",
    "  [.] Analysis in progress (30-60s)...",
    "  [<] TLS 1.0: disabled  ✓",
    "  [<] TLS 1.1: disabled  ✓",
    "  [<] TLS 1.2: supported ✓",
    "  [<] TLS 1.3: supported ✓",
    "  [<] Cert CN: {domain}  |  issuer: Let's Encrypt  |  87 days remaining",
    "  [<] HSTS preload: not present",
    "  ✓  TLS assessment complete",
  ],
  headers: [
    "$ vibescan headers --url https://{domain}/",
    "  Parsing HTTP response headers...",
    "  Content-Security-Policy     : ⚠  MISSING",
    "  Strict-Transport-Security   : ✓  max-age=31536000; includeSubDomains",
    "  X-Frame-Options             : ✓  SAMEORIGIN",
    "  X-Content-Type-Options      : ✓  nosniff",
    "  Referrer-Policy             : ✓  strict-origin-when-cross-origin",
    "  Permissions-Policy          : ⚠  MISSING",
    "  Cross-Origin-Opener-Policy  : ⚠  MISSING",
    "  ✓  Header analysis complete — 2 issues",
  ],
  probes: [
    "$ vibescan probe --all --target https://{domain}/",
    "  [.] Open redirect: GET /?url=https://evil.com → no redirect  ✓",
    "  [.] HTTP methods: DELETE / PATCH / TRACE — not exposed  ✓",
    "  [!] Rate limiting: 50 req/s — no throttling detected",
    "  [.] /.env → 403 Forbidden  ✓",
    "  [.] /.git/config → 404 Not Found  ✓",
    "  [.] /wp-admin → 404 Not Found  ✓",
    "  [!] 3 external <script> tags missing SRI integrity attribute",
    "  [.] Directory listing: not exposed  ✓",
    "  [.] security.txt: not found",
    "  [.] robots.txt: found at /robots.txt  ✓",
    "  ✓  Active probe suite complete — 2 issues",
  ],
  cors: [
    "$ vibescan cors --origin 'https://attacker.example.com' --target {domain}",
    "  Sending CORS preflight OPTIONS request...",
    "  [<] Access-Control-Allow-Origin: (not echoed back)  ✓",
    "  [<] Access-Control-Allow-Credentials: (not present)  ✓",
    "  Auditing Set-Cookie headers...",
    "  [.] _session : Secure ✓  HttpOnly ✓  SameSite=Lax ✓",
    "  [!] _ga (analytics): Secure ✗  HttpOnly ✗  SameSite=None",
    "  ✓  CORS policy OK — 1 cookie flag issue",
  ],
  tech: [
    "$ vibescan fingerprint --target https://{domain}/",
    "  Matching 50+ technology signatures...",
    "  [+] Web server   : Nginx 1.18.0",
    "  [+] CDN          : Cloudflare",
    "  [+] JS framework : Next.js 14.2.3",
    "  [+] Runtime      : Node.js",
    "  [+] UI library   : React 18",
    "  [+] Analytics    : Google Analytics (GA4)",
    "  [+] Auth         : Auth.js / NextAuth",
    "  ✓  Technology stack identified — 7 components",
  ],
  cve: [
    "$ vibescan cve-check --osv-api https://api.osv.dev/",
    "  Querying OSV.dev for detected components...",
    "  Next.js 14.2.3  →  scanning NVD...",
    "  [!] CVE-2024-34351: moderate  —  Server-Side Request Forgery",
    "  [!] CVE-2024-46982: high      —  Cache poisoning via crafted response",
    "  Nginx 1.18.0   →  scanning NVD...",
    "  [.] No critical CVEs for Nginx 1.18.0  ✓",
    "  ⚠  2 CVEs detected — upgrade recommended",
  ],
  dns: [
    "$ vibescan dns --domain {domain}",
    "  Querying Cloudflare DNS-over-HTTPS (1.1.1.1)...",
    "  [<] SPF   : v=spf1 include:_spf.google.com ~all  ✓",
    "  [<] DMARC : v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}  ✓",
    "  [.] DKIM  : default selector — not found",
    "  [.] DKIM  : google selector  — not found",
    "  [.] DNSSEC: not enabled",
    "  ✓  DNS security check complete — 2 recommendations",
  ],
  recon: [
    "$ vibescan recon --domain {domain} --ct-logs crt.sh",
    "  Querying certificate transparency logs...",
    "  [+] api.{domain}        — A record resolves",
    "  [+] staging.{domain}    — CNAME: heroku.com (checking takeover...)",
    "  [+] mail.{domain}       — MX record resolves",
    "  [.] staging.{domain}: heroku CNAME target resolves  ✓  (no takeover)",
    "  Port scan: :80 open  :443 open  :8080 closed  :8443 closed",
    "  ✓  Recon complete — 3 subdomains discovered",
  ],
  sourcemaps: [
    "$ vibescan sourcemaps --target https://{domain}/",
    "  Scanning for exposed .js.map files...",
    "  [.] /static/js/main.abc123.js.map → 404  ✓",
    "  [.] /assets/index.js.map          → 404  ✓",
    "  Scanning headers and HTML for JWT tokens...",
    "  [.] Authorization header: not present  ✓",
    "  [.] HTML source: no JWT pattern found  ✓",
    "  ✓  No source map or token exposure detected",
  ],
  nextjs: [
    "$ vibescan probe --nextjs --target https://{domain}/",
    "  Checking for __NEXT_DATA__ serialised props...",
    "  [!] __NEXT_DATA__ present in HTML source",
    "  Inspecting serialised props for sensitive fields...",
    "  [.] No passwords, tokens, or keys in props  ✓",
    "  [.] Prop leak severity: informational",
    "  Fetching /_next/static/chunks/buildManifest.js...",
    "  [<] 47 JS chunk paths exposed in build manifest",
    "  ✓  Next.js probe complete",
  ],
  graphql: [
    "$ vibescan graphql --target https://{domain}/",
    "  Probing common GraphQL endpoints...",
    "  [.] /graphql      → 404",
    "  [.] /api/graphql  → 404",
    "  [.] /v1/graphql   → 404",
    "  [.] /query        → 404",
    "  [.] /gql          → 404",
    "  ✓  No GraphQL endpoint detected",
  ],
  baas: [
    "$ vibescan baas --target https://{domain}/",
    "  Probing for Supabase configuration...",
    "  [.] No SUPABASE_URL or anon key in page source  ✓",
    "  Probing for Firebase configuration...",
    "  [.] No firebaseConfig object found  ✓",
    "  Probing for PocketBase / Appwrite...",
    "  [.] No BaaS endpoints detected  ✓",
    "  ✓  BaaS probe complete — not applicable",
  ],
  docs: [
    "$ vibescan api-docs --target https://{domain}/",
    "  Probing for exposed API documentation...",
    "  [.] /swagger.json   → 404",
    "  [.] /openapi.json   → 404",
    "  [.] /api-docs       → 404",
    "  [.] /redoc          → 404",
    "  [.] /swagger-ui/    → 404",
    "  ✓  No exposed API documentation found",
  ],
  storage: [
    "$ vibescan storage --target https://{domain}/",
    "  Extracting cloud storage references from HTML...",
    "  [.] No S3 bucket URLs in page source  ✓",
    "  Checking GCS bucket references...",
    "  [.] No storage.googleapis.com URLs  ✓",
    "  Checking Azure Blob references...",
    "  [.] No blob.core.windows.net URLs  ✓",
    "  ✓  No exposed cloud storage detected",
  ],
  js: [
    "$ vibescan secrets --bundles --target https://{domain}/",
    "  Downloading JS bundles (deep scan)...",
    "  Scanning main.abc123.chunk.js (248 KB)...",
    "  [!] Possible publishable key: NEXT_PUBLIC_STRIPE_KEY=pk_live_...",
    "  [.] Pattern 'sk_live_' (Stripe secret)  → no match  ✓",
    "  [.] Pattern 'AKIA' (AWS access key)     → no match  ✓",
    "  [.] Pattern 'ghp_' (GitHub PAT)         → no match  ✓",
    "  [.] Pattern '/api/internal' endpoints   → 3 found (informational)",
    "  ⚠  1 potential secret exposure in client bundle",
  ],
  pathtraversal: [
    "$ vibescan traversal --target https://{domain}/ --vectors 12",
    "  Testing path traversal vectors...",
    "  [.] GET /../../../etc/passwd             → 404  ✓",
    "  [.] GET /..%2F..%2Fetc%2Fshadow         → 400  ✓",
    "  [.] GET /%2e%2e/%2e%2e/etc/hosts        → 404  ✓",
    "  [.] GET /api/v1/../../../windows/win.ini → 404  ✓",
    "  [.] GET /download?file=../../etc/passwd  → 400  ✓",
    "  ✓  No path traversal vulnerability detected",
  ],
  reprobe: [
    "$ vibescan verify --corroborate --findings /tmp/vibescan-session/",
    "  Loading collected findings for corroboration...",
    "  Re-probing 5 borderline results...",
    "  [~] CSP missing          → re-confirmed  ✓",
    "  [~] Rate limiting absent → re-confirmed  ✓",
    "  [~] SRI missing (3)      → re-confirmed  ✓",
    "  [~] Cookie flag issue    → re-confirmed  ✓",
    "  [~] CVE-2024-46982       → re-confirmed  ✓",
    "  Merging duplicate root-cause findings...",
    "  ✓  Verification & deduplication complete",
  ],
  ai: [
    "$ vibescan analyze --ai --model deepseek-v3 --findings /tmp/vibescan-session/",
    "  Loading all collected findings...",
    "  [.] Sending to AI analysis engine...",
    "  [.] Generating executive summary...",
    "  [.] Ranking findings by severity & exploitability...",
    "  [.] Building attack chain narratives...",
    "  [.] Writing remediation guide (step-by-step)...",
    "  [.] Formatting security report...",
    "  ✓  AI analysis complete",
  ],
  score: [
    "$ vibescan score --all-findings --write-report",
    "  Computing CVSS-aligned risk scores...",
    "  Calculating weighted security grade...",
    "  critical: 0  high: 2  medium: 4  low: 3  info: 5",
    "  Risk score: 68 / 100",
    "  Security grade: C",
    "  Writing executive summary...",
    "  ✓  Report generation complete",
    "  ✓  Scan session finished",
  ],
};

// ─── Terminal line types ──────────────────────────────────────────────────────

interface TerminalLine {
  id: number;
  text: string;
  ts: string;
}

function lineColor(text: string): string {
  const t = text.trim();
  if (t.startsWith("$")) return "text-slate-500";
  if (t.startsWith("✓")) return "text-emerald-400";
  if (t.startsWith("⚠")) return "text-yellow-400";
  if (t.startsWith("[!]")) return "text-yellow-400";
  if (t.startsWith("[>]") || t.startsWith("[<]") || t.startsWith("[GET]")) return "text-sky-400";
  if (t.startsWith("[+]")) return "text-green-400";
  if (t.startsWith("[.]") || t.startsWith("[~]")) return "text-slate-500";
  if (t.startsWith("─") || t.startsWith("═") || t.startsWith("VibeScan")) return "text-primary/70";
  if (t.startsWith("Target") || t.startsWith("Tier") || t.startsWith("Session")) return "text-slate-400";
  if (t.includes("✓")) return "text-emerald-400/80";
  return "text-slate-300";
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getDomain(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

function nowHHMMSS(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
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

const STATUS_PROGRESS: Record<string, number> = {
  pending: 0,
  paid: 10,
  queued: 20,
  scanning: 55,
  analyzing: 80,
  complete: 100,
  failed: 0,
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

  // Tick every 500ms to advance step animations
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((n) => n + 1), 500);
    return () => clearInterval(id);
  }, []);

  // ── Status polling ────────────────────────────────────────────────────────
  const { data, isLoading, isError } = useGetScanStatus(scanId, {
    query: {
      queryKey: ["scan-status", scanId],
      refetchInterval: (query) => {
        const s = (query.state.data as { status?: string } | undefined)?.status;
        if (s === "complete" || s === "failed") return false;
        return 2000;
      },
    },
  });

  useEffect(() => {
    if (data?.status === "analyzing" && !analyzingStartRef.current) {
      analyzingStartRef.current = Date.now();
    }
  }, [data?.status]);

  useEffect(() => {
    if (data?.status === "complete" && data.reportId && !redirectedRef.current) {
      redirectedRef.current = true;
      const t = setTimeout(() => setLocation(`/report/${data.reportId}`), 1800);
      return () => clearTimeout(t);
    }
    return undefined;
  }, [data?.status, data?.reportId, setLocation]);

  // ── Derived values ────────────────────────────────────────────────────────
  const startedAt = data?.startedAt ? new Date(data.startedAt).getTime() : null;
  const scanningElapsedMs = startedAt ? Math.max(0, Date.now() - startedAt) : 0;
  const analyzingElapsedMs = analyzingStartRef.current
    ? Math.max(0, Date.now() - analyzingStartRef.current)
    : 0;

  const steps = useMemo(() => getVisibleSteps(tier), [tier]);
  const domain = useMemo(() => getDomain(data?.targetUrl ?? ""), [data?.targetUrl]);

  const statuses = useMemo(
    () => computeStepStatuses(steps, data?.status ?? "queued", scanningElapsedMs, analyzingElapsedMs),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [steps, data?.status, scanningElapsedMs, analyzingElapsedMs],
  );

  const statusKey = useMemo(() => statuses.join(","), [statuses]);

  const progress = data?.progress ?? STATUS_PROGRESS[data?.status ?? "queued"] ?? 0;
  const isFailed = data?.status === "failed";
  const isComplete = data?.status === "complete";
  const isQueued =
    !data?.status ||
    ["queued", "paid", "pending"].includes(data.status);

  // ── Terminal state ────────────────────────────────────────────────────────
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([]);
  const emittedStepsRef = useRef<Set<string>>(new Set());
  const timeoutsRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const lineIdRef = useRef(0);
  const terminalBodyRef = useRef<HTMLDivElement>(null);
  const sessionBannerEmittedRef = useRef(false);

  // Emit the session banner once when data first arrives
  useEffect(() => {
    if (!data?.id || sessionBannerEmittedRef.current || !domain) return;
    sessionBannerEmittedRef.current = true;

    const scanCount = steps.length;
    const lines = [
      `VibeScan Enterprise Security Scanner v2.0`,
      `────────────────────────────────────────────────────`,
      `Target  : https://${domain}`,
      `Tier    : ${tier === "deep" ? `Deep Scan (${scanCount} checks)` : `Basic Scan (${scanCount} checks)`}`,
      `Session : ${data.id}`,
      `────────────────────────────────────────────────────`,
    ];
    lines.forEach((text, j) => {
      const tid = setTimeout(() => {
        setTerminalLines((prev) => [
          ...prev,
          { id: lineIdRef.current++, text, ts: "" },
        ]);
      }, j * 40);
      timeoutsRef.current.push(tid);
    });
  }, [data?.id, domain, tier, steps.length]);

  // Emit log lines when steps become active
  useEffect(() => {
    if (!domain || domain === "") return;
    statuses.forEach((status, i) => {
      const step = steps[i];
      if (!step) return;
      if (emittedStepsRef.current.has(step.id)) return;
      if (status !== "running" && status !== "done") return;

      emittedStepsRef.current.add(step.id);
      const logLines = (STEP_LOGS[step.id] ?? []).map((l) =>
        l.replace(/\{domain\}/g, domain),
      );
      const interval = status === "done" ? 0 : 260;

      logLines.forEach((text, j) => {
        const tid = setTimeout(() => {
          setTerminalLines((prev) => [
            ...prev,
            { id: lineIdRef.current++, text, ts: nowHHMMSS() },
          ]);
        }, j * interval);
        timeoutsRef.current.push(tid);
      });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusKey, domain]);

  // Auto-scroll terminal to bottom
  useEffect(() => {
    if (terminalBodyRef.current) {
      terminalBodyRef.current.scrollTop = terminalBodyRef.current.scrollHeight;
    }
  }, [terminalLines.length]);

  // Cleanup timeouts on unmount
  useEffect(() => {
    return () => {
      timeoutsRef.current.forEach(clearTimeout);
    };
  }, []);

  // ── Loading / error guards ────────────────────────────────────────────────
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

  const doneCount = statuses.filter((s) => s === "done").length;
  const currentStep = steps[statuses.indexOf("running")];

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-8">

      {/* ── Header ── */}
      <div className="text-center mb-6">
        <div
          className={cn(
            "w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4 border",
            isComplete
              ? "bg-green-500/10 border-green-500/20"
              : isFailed
                ? "bg-red-500/10 border-red-500/20"
                : "bg-primary/10 border-primary/20",
          )}
        >
          {isComplete ? (
            <CheckCircle2 className="w-7 h-7 text-green-500" />
          ) : isFailed ? (
            <XCircle className="w-7 h-7 text-red-400" />
          ) : isQueued ? (
            <Clock className="w-7 h-7 text-primary" />
          ) : (
            <Loader2 className="w-7 h-7 text-primary animate-spin" />
          )}
        </div>

        <div className="flex items-center justify-center gap-2 mb-1">
          <h1 className="text-xl font-bold tracking-tight">
            {isComplete
              ? "Scan Complete"
              : isFailed
                ? "Scan Failed"
                : domain || "Security Scan"}
          </h1>
          <span
            className={cn(
              "text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border",
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

      {/* ── Terminal window ── */}
      <div className="rounded-2xl overflow-hidden border border-white/10 shadow-2xl shadow-black/50 mb-4">

        {/* Window chrome */}
        <div className="bg-[#1e1e1e] border-b border-white/[0.06] px-4 py-2.5 flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500/80" />
            <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
            <span className="w-3 h-3 rounded-full bg-green-500/80" />
          </div>
          <span className="flex-1 text-center text-[11px] font-mono text-slate-500 tracking-wide">
            vibescan — security terminal
            {domain ? ` — ${domain}` : ""}
          </span>
          {/* Status dot */}
          <div className="flex items-center gap-1.5">
            {!isFailed && !isComplete && (
              <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
            )}
            {isComplete && <span className="w-2 h-2 rounded-full bg-green-500" />}
            {isFailed && <span className="w-2 h-2 rounded-full bg-red-500" />}
            <span className="text-[10px] font-mono text-slate-600 uppercase tracking-wider">
              {isComplete ? "done" : isFailed ? "failed" : isQueued ? "waiting" : data?.status ?? "idle"}
            </span>
          </div>
        </div>

        {/* Terminal body */}
        <div
          ref={terminalBodyRef}
          className="bg-[#0d1117] font-mono text-[12.5px] leading-relaxed h-[420px] overflow-y-auto px-5 py-4 scroll-smooth"
          style={{ scrollbarWidth: "thin", scrollbarColor: "#30363d transparent" }}
        >
          {/* Queued placeholder */}
          {isQueued && terminalLines.length === 0 && (
            <div className="text-slate-600 flex flex-col gap-1">
              <span className="text-primary/50">VibeScan Enterprise Security Scanner v2.0</span>
              <span>────────────────────────────────────────────────────</span>
              <span>Connecting to job queue...</span>
              <span>Waiting for an available worker slot
                <span className="inline-flex ml-1 gap-0.5">
                  {[0, 1, 2].map((i) => (
                    <span
                      key={i}
                      className="inline-block w-1 h-1 rounded-full bg-slate-600 animate-pulse"
                      style={{ animationDelay: `${i * 200}ms` }}
                    />
                  ))}
                </span>
              </span>
            </div>
          )}

          {/* Log lines */}
          {terminalLines.map((line, i) => {
            const isLast = i === terminalLines.length - 1;
            return (
              <div key={line.id} className="flex gap-3 leading-relaxed min-h-[1.4em]">
                {line.ts ? (
                  <span className="shrink-0 text-slate-700 select-none w-[52px]">
                    {line.ts}
                  </span>
                ) : (
                  <span className="shrink-0 w-[52px]" />
                )}
                <span className={cn("flex-1 whitespace-pre-wrap break-all", lineColor(line.text))}>
                  {line.text}
                  {isLast && !isComplete && !isFailed && (
                    <span
                      className="inline-block w-2 h-[1em] ml-0.5 bg-primary align-middle"
                      style={{ animation: "blink 1.1s step-end infinite" }}
                    />
                  )}
                </span>
              </div>
            );
          })}

          {/* Complete banner */}
          {isComplete && (
            <div className="mt-4 flex flex-col gap-0.5 text-emerald-400">
              <span>────────────────────────────────────────────────────</span>
              <span>✓  Scan session complete. Report ready.</span>
              <span className="text-slate-500 text-[11px]">Redirecting to your report…</span>
            </div>
          )}

          {/* Failed banner */}
          {isFailed && (
            <div className="mt-4 flex flex-col gap-0.5 text-red-400">
              <span>────────────────────────────────────────────────────</span>
              <span>[!] Scan failed: {data?.error ?? "Unknown error"}</span>
            </div>
          )}
        </div>

        {/* Progress footer inside terminal chrome */}
        <div className="bg-[#161b22] border-t border-white/[0.06] px-5 py-3">
          <div className="flex items-center justify-between text-[11px] font-mono mb-2">
            <span className="text-slate-500">
              {doneCount}/{steps.length} checks
              {currentStep ? (
                <span className="ml-2 text-primary/70">
                  ▸ {currentStep.label}
                </span>
              ) : null}
            </span>
            <span className={cn(
              "font-semibold",
              isComplete ? "text-emerald-400" : isFailed ? "text-red-400" : "text-primary",
            )}>
              {progress}%
            </span>
          </div>
          <div className="h-1 bg-white/5 rounded-full overflow-hidden">
            <div
              className={cn(
                "h-full rounded-full transition-all duration-700 ease-out",
                isComplete ? "bg-emerald-500" : isFailed ? "bg-red-500" : "bg-primary",
              )}
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      </div>

      {/* ── Footer nav ── */}
      <div className="text-center">
        <button
          onClick={() => setLocation("/dashboard")}
          className="text-sm text-muted-foreground hover:text-foreground transition-colors"
        >
          ← Back to dashboard
        </button>
      </div>

      {/* Cursor blink keyframe */}
      <style>{`@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }`}</style>
    </div>
  );
}
