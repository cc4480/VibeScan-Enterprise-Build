import { cn, getGradeColor } from "@/lib/utils";

/** The grade's own colour: the arc, the glow around it, and (via getGradeColor) the letter. */
export const GRADE_HEX: Record<string, string> = {
  A: "#4ade80",
  B: "#a3e635",
  C: "#facc15",
  D: "#fb923c",
  F: "#f87171",
};

const SIZES = {
  lg: { box: "w-48 h-48", c: 96, r: 88, stroke: 8, disc: "w-36 h-36", letter: "text-6xl", sub: "text-xs", rowGap: "mt-1" },
  md: { box: "w-36 h-36", c: 68, r: 60, stroke: 6, disc: "w-24 h-24", letter: "text-4xl", sub: "text-[10px]", rowGap: "mt-0.5" },
} as const;

/**
 * The report's grade ring, shared by the owner's report and the shared report.
 *
 * The arc is the risk score and takes the grade's colour; a soft halo of the
 * same colour sits behind it, so a C reads as a warm yellow at a glance and an
 * F as red. A scan with no grade (a bot-protection page answered it) gets a
 * neutral ring with no glow: "N/A" must never look like a result.
 */
export function GradeRing({ grade, score, size = "md" }: { grade: string; score: number; size?: keyof typeof SIZES }) {
  const s = SIZES[size];
  const graded = grade in GRADE_HEX;
  const color = graded ? GRADE_HEX[grade] : "#94a3b8";
  const circumference = 2 * Math.PI * s.r;
  const dash = circumference * (1 - (graded ? score / 100 : 1));
  const view = s.c * 2;

  return (
    <div className={cn("relative flex items-center justify-center shrink-0", s.box)}>
      {graded && (
        <div
          aria-hidden
          className="absolute inset-[-14%] rounded-full blur-2xl opacity-40 pointer-events-none"
          style={{ background: `radial-gradient(circle, ${color} 0%, transparent 68%)` }}
        />
      )}
      <svg viewBox={`0 0 ${view} ${view}`} className="w-full h-full transform -rotate-90 absolute inset-0 overflow-visible">
        <circle cx={s.c} cy={s.c} r={s.r} fill="none" stroke="currentColor" strokeWidth={s.stroke} className="text-secondary" />
        <circle
          cx={s.c}
          cy={s.c}
          r={s.r}
          fill="none"
          stroke={color}
          strokeWidth={s.stroke}
          strokeDasharray={circumference}
          strokeDashoffset={dash}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
          style={graded ? { filter: `drop-shadow(0 0 ${size === "lg" ? 10 : 7}px ${color}) drop-shadow(0 0 ${size === "lg" ? 22 : 14}px ${color}66)` } : undefined}
        />
      </svg>
      <div
        className={cn("flex flex-col items-center justify-center bg-background rounded-full border-4 border-card z-10 relative", s.disc)}
        style={graded ? { boxShadow: `0 0 34px ${color}30, inset 0 0 24px ${color}14` } : undefined}
      >
        <div className="absolute inset-0 bg-gradient-to-b from-white/5 to-transparent rounded-full" />
        <span className={cn("font-black font-display leading-none", s.letter, graded ? getGradeColor(grade) : "text-muted-foreground")}>
          {graded ? grade : "—"}
        </span>
        <span className={cn("font-medium text-muted-foreground uppercase tracking-widest text-center leading-tight px-3", s.sub, s.rowGap)}>
          {graded ? `Risk ${score}` : size === "lg" ? "Coverage incomplete" : "Incomplete"}
        </span>
      </div>
    </div>
  );
}
