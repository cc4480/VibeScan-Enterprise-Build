import { Link } from "wouter";
import { useListScans, useGetCredits, useGetScanStatus } from "@workspace/api-client-react";
import { Shield, Plus, Clock, CheckCircle2, AlertCircle, RefreshCw, FileText, Loader2, ArrowRight } from "lucide-react";
import { format } from "date-fns";
import { cn, getGradeColor } from "@/lib/utils";
import type { Scan } from "@workspace/api-client-react";

// Individual row component to handle independent polling
function ScanRow({ initialScan }: { initialScan: Scan }) {
  const isPolling = ['pending', 'paid', 'queued', 'scanning', 'analyzing'].includes(initialScan.status);
  
  const { data: statusData } = useGetScanStatus(initialScan.id, {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    query: { refetchInterval: isPolling ? 3000 : false } as any,
  });

  const scan = statusData || initialScan;
  
  const getStatusDisplay = (status: string, progress?: number) => {
    switch (status) {
      case 'complete': return <div className="flex items-center gap-1.5 text-emerald-400"><CheckCircle2 className="w-4 h-4"/> Complete</div>;
      case 'failed': return <div className="flex items-center gap-1.5 text-red-400"><AlertCircle className="w-4 h-4"/> Failed</div>;
      case 'pending':
      case 'paid':
      case 'queued': return <div className="flex items-center gap-1.5 text-muted-foreground"><Clock className="w-4 h-4"/> Queued</div>;
      default: return (
        <div className="flex items-center gap-2 text-primary">
          <Loader2 className="w-4 h-4 animate-spin" />
          <div className="flex flex-col gap-1 w-24">
            <span className="text-xs capitalize">{status}...</span>
            <div className="h-1 w-full bg-secondary rounded-full overflow-hidden">
              <div className="h-full bg-primary transition-all duration-500" style={{ width: `${progress ?? 0}%` }} />
            </div>
          </div>
        </div>
      );
    }
  };

  return (
    <tr className="border-b border-white/5 hover:bg-white/[0.02] transition-colors group">
      <td className="p-4 py-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-secondary flex items-center justify-center border border-white/5">
            <GlobeIcon className="w-5 h-5 text-muted-foreground" />
          </div>
          <div>
            <div className="font-medium text-foreground truncate max-w-[200px] sm:max-w-[300px]">
              {scan.targetUrl}
            </div>
            <div className="text-xs text-muted-foreground mt-1">
              {format(new Date(scan.createdAt), "MMM d, yyyy h:mm a")}
            </div>
          </div>
        </div>
      </td>
      <td className="p-4 hidden sm:table-cell">
        <span className="px-2.5 py-1 rounded-md text-xs font-medium bg-secondary border border-white/5 uppercase tracking-wider">
          {scan.tier.replace('_', ' ')}
        </span>
      </td>
      <td className="p-4">
        {getStatusDisplay(scan.status, 'progress' in scan ? scan.progress : undefined)}
      </td>
      <td className="p-4 hidden md:table-cell">
        {scan.status === 'complete' ? (
          <div className={cn("text-lg font-bold font-display", getGradeColor("A" /* Assuming grade isn't returned in status, it's in report. We'd need to fetch report or add grade to scan schema. Let's just show a checkmark if we don't have grade here */))}>
            {/* Grade usually comes from Report, but we only have Scan object here.
                We'll just show 'Done' or fetch grade if we want. Let's keep it simple. */}
            <Shield className="w-5 h-5 text-emerald-400" />
          </div>
        ) : (
          <span className="text-muted-foreground">-</span>
        )}
      </td>
      <td className="p-4 text-right">
        {scan.status === 'complete' && scan.reportId ? (
          <Link 
            href={`/report/${scan.reportId}`}
            className="inline-flex items-center gap-2 px-4 py-2 bg-secondary hover:bg-white/10 text-foreground text-sm font-medium rounded-lg transition-colors border border-white/5"
          >
            <FileText className="w-4 h-4" /> View Report
          </Link>
        ) : scan.status === 'failed' ? (
          <button className="text-sm text-muted-foreground hover:text-foreground underline decoration-dashed underline-offset-4">
            Details
          </button>
        ) : (
          <span className="text-sm text-muted-foreground">Processing...</span>
        )}
      </td>
    </tr>
  );
}

function GlobeIcon(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>
    </svg>
  )
}

export default function DashboardPage() {
  const { data: scans, isLoading: loadingScans } = useListScans();
  const { data: credits, isLoading: loadingCredits } = useGetCredits();

  if (loadingScans || loadingCredits) {
    return (
      <div className="flex-1 flex items-center justify-center min-h-[60vh]">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  const completedCount = scans?.filter(s => s.status === 'complete').length || 0;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground mt-1">Manage your security scans and reports.</p>
        </div>
        <Link href="/scan" className="px-5 py-2.5 bg-primary text-primary-foreground text-sm font-semibold rounded-lg shadow-[0_0_15px_rgba(20,184,120,0.3)] hover:shadow-[0_0_25px_rgba(20,184,120,0.5)] hover:-translate-y-0.5 transition-all duration-200 flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Scan
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 mb-10">
        <div className="glass-card p-6 rounded-2xl flex flex-col gap-2">
          <div className="text-muted-foreground text-sm font-medium flex items-center gap-2"><RefreshCw className="w-4 h-4"/> Total Scans</div>
          <div className="text-4xl font-display font-bold">{scans?.length || 0}</div>
        </div>
        <div className="glass-card p-6 rounded-2xl flex flex-col gap-2">
          <div className="text-muted-foreground text-sm font-medium flex items-center gap-2"><Shield className="w-4 h-4 text-emerald-400"/> Completed</div>
          <div className="text-4xl font-display font-bold">{completedCount}</div>
        </div>
        <div className="glass-card p-6 rounded-2xl flex flex-col gap-2 relative overflow-hidden group">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
          <div className="text-muted-foreground text-sm font-medium flex items-center gap-2 relative z-10"><Zap className="w-4 h-4 text-primary"/> Available Credits</div>
          <div className="flex items-end justify-between relative z-10">
            <div className="text-4xl font-display font-bold text-primary">{credits?.balance || 0}</div>
            <Link href="/scan" className="text-xs font-medium text-primary hover:underline underline-offset-4 pb-1">Get more &rarr;</Link>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="glass-panel rounded-2xl overflow-hidden">
        {scans && scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-white/10 bg-secondary/50">
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Target</th>
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider hidden sm:table-cell">Tier</th>
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                  <th className="p-4 text-xs font-semibold text-muted-foreground uppercase tracking-wider hidden md:table-cell">Security</th>
                  <th className="p-4 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <ScanRow key={scan.id} initialScan={scan} />
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-24 px-6 text-center flex flex-col items-center">
            <div className="w-16 h-16 bg-secondary rounded-2xl flex items-center justify-center mb-4 border border-white/5">
              <Shield className="w-8 h-8 text-muted-foreground opacity-50" />
            </div>
            <h3 className="text-xl font-bold mb-2">No scans yet</h3>
            <p className="text-muted-foreground max-w-sm mb-6">You haven't run any security scans yet. Launch your first scan to see how secure your app is.</p>
            <Link href="/scan" className="px-6 py-3 bg-secondary hover:bg-white/10 text-foreground font-semibold rounded-xl transition-colors border border-white/5 flex items-center gap-2">
              Start your first scan <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}

function Zap(props: React.SVGProps<SVGSVGElement>) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  )
}
