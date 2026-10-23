import { useQuery, useQueryClient } from "@tanstack/react-query";
import { customFetch } from "@workspace/api-client-react";
import { Link2, Loader2, Unplug } from "lucide-react";

/**
 * Settings → Connected apps: editors that were connected by signing in (OAuth), as
 * opposed to pasted tokens (listed above). Disconnecting revokes every token the
 * app holds, refresh tokens included, at once.
 */

interface Connection {
  clientId: string;
  name: string;
  connectedAt: string;
  lastUsedAt: string | null;
}

const listConnections = () => customFetch<{ connections: Connection[] }>("/api/account/connections");

function ago(iso: string | null): string {
  if (!iso) return "not used yet";
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 60) return mins <= 1 ? "used just now" : `used ${mins} min ago`;
  const hours = Math.round(mins / 60);
  return hours < 48 ? `used ${hours} h ago` : `used ${Math.round(hours / 24)} days ago`;
}

export function ConnectedAppsSection() {
  const queryClient = useQueryClient();
  const apps = useQuery({ queryKey: ["oauth-connections"], queryFn: listConnections });

  async function disconnect(app: Connection) {
    if (!confirm(`Disconnect ${app.name}? It stops working immediately and has to be connected again.`)) return;
    await customFetch(`/api/account/connections/${app.clientId}`, { method: "DELETE" }).catch(() => {});
    await queryClient.invalidateQueries({ queryKey: ["oauth-connections"] });
  }

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold">Connected apps</h3>
      {apps.isLoading ? (
        <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
      ) : apps.data?.connections.length ? (
        apps.data.connections.map((app) => (
          <div key={app.clientId} className="flex flex-wrap items-center gap-3 rounded-xl border border-white/10 px-4 py-3">
            <Link2 className="w-4 h-4 text-muted-foreground shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="font-medium truncate">{app.name}</div>
              <div className="text-xs text-muted-foreground">Connected {new Date(app.connectedAt).toLocaleDateString()} · {ago(app.lastUsedAt)}</div>
            </div>
            <button type="button" onClick={() => disconnect(app)} className="inline-flex items-center gap-1.5 text-sm text-red-400 hover:text-red-300">
              <Unplug className="w-4 h-4" /> Disconnect
            </button>
          </div>
        ))
      ) : (
        <p className="text-sm text-muted-foreground">
          No apps connected this way. An editor that supports signing in (rather than a pasted token) will ask you here.
        </p>
      )}
    </div>
  );
}
