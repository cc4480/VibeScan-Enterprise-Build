import { useSubscriptionCard } from "./monitor-card-state";
import { SubscriptionHeader } from "./monitor-card-header";
import { SubscriptionDrawers } from "./monitor-card-drawers";
import { SubscriptionBanners, ScanInProgressNotice, ScanCadence, SubscriptionLinks } from "./monitor-card-parts";
import { OverviewRow, ChartPanels, AttentionList, GettingStarted, isBrandNew } from "./monitor-card-sections";
import { motion } from "framer-motion";
import { type MonitorSubscription } from "@/lib/monitor-api";

/** One monitored site: status, grade ring, charts, what needs attention, and drawers of detail. */
export function SubscriptionCard({ sub, onCancel }: { sub: MonitorSubscription; onCancel: (id: string) => void }) {
  const card = useSubscriptionCard(sub, onCancel);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      className="glass-card rounded-2xl overflow-hidden"
    >
      <SubscriptionBanners sub={sub} card={card} />

      <div className="p-6">
        <SubscriptionHeader sub={sub} card={card} />
        <ScanInProgressNotice sub={sub} card={card} />
        {isBrandNew(sub) ? (
          // Nothing to chart yet: say where it is and what comes next, not rows of dashes.
          <GettingStarted sub={sub} card={card} />
        ) : (
          <>
            <OverviewRow sub={sub} card={card} />
            <ChartPanels sub={sub} card={card} />
            <AttentionList sub={sub} card={card} />
          </>
        )}
        <ScanCadence sub={sub} card={card} />
        <SubscriptionLinks sub={sub} card={card} />
      </div>

      <SubscriptionDrawers card={card} />
    </motion.div>
  );
}
