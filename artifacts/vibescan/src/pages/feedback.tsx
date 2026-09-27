import { useState } from "react";
import { useSeo } from "@/lib/seo";
import { useToast } from "@/hooks/use-toast";
import { Loader2, Star, CheckCircle2 } from "lucide-react";
import { submitFeedback } from "@/lib/feedback-api";

function getFriendlyError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err ?? "");
  if (!msg) return "Something went wrong. Please try again.";
  const clean = msg.replace(/^HTTP \d{3} [^:]+:\s*/, "");
  return clean.length > 160 ? clean.slice(0, 160) + "…" : clean;
}

/** What someone thought after actually scanning an app they own.
 *  No sign-in required — account creation must never be the price of being heard. */
export default function FeedbackPage() {
  useSeo({
    title: "Feedback — SecScan.us",
    description: "Tell us what worked and what didn't after scanning your app.",
  });
  const { toast } = useToast();
  const [message, setMessage] = useState("");
  const [rating, setRating] = useState<number | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [sent, setSent] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!message.trim() || submitting) return;
    setSubmitting(true);
    try {
      await submitFeedback({
        message: message.trim(),
        ...(rating != null ? { rating } : {}),
        context: "feedback-page",
      });
      setSent(true);
    } catch (err) {
      toast({ title: "Couldn't send feedback", description: getFriendlyError(err), variant: "destructive" });
    } finally {
      setSubmitting(false);
    }
  }

  if (sent) {
    return (
      <div className="max-w-xl mx-auto px-6 py-20 text-center">
        <CheckCircle2 className="mx-auto mb-4 h-10 w-10 text-primary" />
        <h1 className="text-2xl font-bold mb-2">Thanks — got it.</h1>
        <p className="text-muted-foreground">
          We read every submission. If you'd like a reply, leave your email next time or reach us
          at reports@secscan.us.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-xl mx-auto px-6 py-16">
      <h1 className="text-2xl md:text-3xl font-bold mb-2">Feedback</h1>
      <p className="text-muted-foreground mb-8">
        You've been testing SecScan on apps you own — tell us what worked, what confused you, or
        what broke. This goes straight to the team, not a queue.
      </p>

      <form onSubmit={handleSubmit} className="space-y-6">
        <div>
          <label className="block text-sm font-medium mb-2">How was it?</label>
          <div className="flex gap-1">
            {[1, 2, 3, 4, 5].map((n) => (
              <button
                key={n}
                type="button"
                aria-label={`${n} star${n === 1 ? "" : "s"}`}
                onClick={() => setRating(rating === n ? null : n)}
                className="p-1"
              >
                <Star
                  className={`h-7 w-7 transition-colors ${
                    rating != null && n <= rating
                      ? "fill-primary text-primary"
                      : "text-white/20"
                  }`}
                />
              </button>
            ))}
          </div>
        </div>

        <div>
          <label htmlFor="feedback-message" className="block text-sm font-medium mb-2">
            Your feedback
          </label>
          <textarea
            id="feedback-message"
            required
            rows={6}
            maxLength={5000}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="What did you scan, and what did you think?"
            className="w-full rounded-md bg-white/5 border border-white/10 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary resize-y"
          />
        </div>

        <button
          type="submit"
          disabled={submitting || !message.trim()}
          className="inline-flex items-center gap-2 rounded-md bg-primary px-5 py-2.5 text-sm font-medium text-primary-foreground disabled:opacity-50"
        >
          {submitting && <Loader2 className="h-4 w-4 animate-spin" />}
          Send feedback
        </button>
      </form>
    </div>
  );
}
