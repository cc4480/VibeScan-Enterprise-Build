import type { Express } from "express";

/** The SSRF, webhook, GraphQL and app routes. */


export function mountSsrf(app: Express): void {
  // ─────────────────────────────────────────────────────────────────────────────
  // SSRF (ssrfProbe.ts). A real server-side fetch of a caller-supplied URL, no
  // allowlist, no scheme restriction — exactly the shape the probe looks for
  // under a URL-shaped parameter name. The response body is irrelevant to the
  // probe: what proves the vulnerability is the collector recording a callback
  // for the token planted in `url`, which only a server that actually fetched it
  // could produce.
  //
  // SSRF_PROBE_ALLOWLIST, if set, is a comma-separated list of exact
  // "hostname" or "hostname:port" values. When set, this endpoint fetches ONLY
  // those hosts and refuses everything else — including private, loopback and
  // link-local addresses — before this file is ever exposed on a public host.
  //
  // Unset (the default) is what every existing local run depends on: the SSRF
  // finding is proved by a callback to this repo's own OOB collector
  // (lib/oobServer.ts), which in local/CI runs lives at APP_ORIGIN on
  // loopback. A blanket "block private ranges" rule would silently break that
  // collector callback along with the finding. So the restriction is opt-in,
  // set only on the public deployment (scripts/benchmark and secscan-me/),
  // naming that deployment's own collector host explicitly — never opt-out.
  // ─────────────────────────────────────────────────────────────────────────────
  const SSRF_ALLOWLIST = (process.env.SSRF_PROBE_ALLOWLIST ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  // Fail CLOSED in production. The allowlist above is opt-in so local and CI runs
  // keep working unchanged, which means a public deployment that simply forgot
  // to set it would boot as an open SSRF proxy — into cloud metadata and
  // whatever else the host can reach. The runbook calls the variable "not
  // optional"; this makes that true in code rather than in prose. The
  // production Dockerfile sets NODE_ENV=production, so the public image cannot
  // start unrestricted by accident.
  //
  // SSRF_PROBE_UNRESTRICTED=true is the deliberate escape hatch for running the
  // production image locally, on a machine that is not reachable from outside.
  if (
    process.env.NODE_ENV === "production" &&
    SSRF_ALLOWLIST.length === 0 &&
    process.env.SSRF_PROBE_UNRESTRICTED !== "true"
  ) {
    console.error(
      "[vuln-fixture] Refusing to start: NODE_ENV=production with no SSRF_PROBE_ALLOWLIST.\n" +
        "  /api/webhook-preview would be an unrestricted SSRF proxy on a public host.\n" +
        "  Set SSRF_PROBE_ALLOWLIST=<collector-host:port>, or SSRF_PROBE_UNRESTRICTED=true\n" +
        "  ONLY on a machine nothing outside can reach.",
    );
    process.exit(1);
  }

  function ssrfTargetAllowed(rawUrl: string): boolean {
    if (SSRF_ALLOWLIST.length === 0) return true; // unrestricted: local/CI default
    try {
      const u = new URL(rawUrl);
      const host = u.hostname.toLowerCase();
      const hostPort = `${host}:${u.port || (u.protocol === "https:" ? "443" : "80")}`;
      return SSRF_ALLOWLIST.includes(host) || SSRF_ALLOWLIST.includes(hostPort);
    } catch {
      return false;
    }
  }

  app.get("/api/webhook-preview", async (req, res) => {
    const url = String(req.query.url ?? "");
    if (!ssrfTargetAllowed(url)) {
      // Same shape as a real failed fetch — a public deployment must not
      // distinguish "blocked by us" from "unreachable" in its response, or the
      // allowlist itself becomes an oracle for mapping the network from outside.
      res.status(502).json({ error: "could not reach that URL" });
      return;
    }
    try {
      // redirect: "manual" — the allowlist checks only the URL it was given,
      // and fetch() follows redirects by default. This fixture has a planted open
      // redirect on "/" (OPEN_REDIRECT_PARAM_NAMES), so with redirects followed,
      // ?url=https://<allowlisted-host>/?next=http://169.254.169.254/ walks
      // straight past the allowlist into cloud metadata. Any allowlisted host
      // that redirects at all would do the same.
      //
      // Costs the SSRF finding nothing: it is proved by the collector recording a
      // callback for the planted URL itself, never by following a redirect.
      const upstream = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(5_000) });
      res.json({ status: upstream.status, contentType: upstream.headers.get("content-type") });
    } catch {
      res.status(502).json({ error: "could not reach that URL" });
    }
  });

  // ─────────────────────────────────────────────────────────────────────────────
  // GraphQL (graphqlProbe.ts) — introspection enabled, field-suggestion leak.
  // ─────────────────────────────────────────────────────────────────────────────
  function graphqlIntrospectionResult() {
    // hasIntrospectionData requires >=10 types — "real introspection returns 15+
    // built-in types minimum" — so this has to include the spec's own
    // meta-types, not just the schema's own object types, or a real introspection
    // response still reads as "not introspection" to the check.
    const builtIns = ["String", "Int", "Boolean", "ID", "Float", "__Schema", "__Type", "__Field", "__InputValue", "__EnumValue", "__TypeKind", "__Directive", "__DirectiveLocation"];
    return {
      data: {
        __schema: {
          queryType: { name: "Query" },
          types: [
            { name: "Query", kind: "OBJECT" },
            { name: "User", kind: "OBJECT" },
            { name: "Record", kind: "OBJECT" },
            ...builtIns.map((name) => ({ name, kind: name.startsWith("__") ? "OBJECT" : "SCALAR" })),
          ],
        },
      },
    };
  }
  app.post("/graphql", (req, res) => {
    // Batching: an array of operations is run and answered as an array (graphqlExtra.ts).
    if (Array.isArray(req.body)) {
      res.json(req.body.map(() => ({ data: { __typename: "Query" } })));
      return;
    }
    const query = String(req.body?.query ?? "");
    if (/__schema/.test(query)) {
      res.json(graphqlIntrospectionResult());
      return;
    }
    // graphqlProbe.ts's BOGUS_FIELD_QUERY is exactly this field name — matched
    // literally rather than guessed, since a plausible-looking guess (an
    // "unknown username field" story) is still wrong if it isn't the string the
    // check actually sends.
    if (/nonExistentFieldSecScanProbe/.test(query)) {
      res.json({
        errors: [{ message: 'Cannot query field "nonExistentFieldSecScanProbe" on type "Query". Did you mean "record"?', locations: [{ line: 1, column: 3 }] }],
      });
      return;
    }
    res.json({ data: { __typename: "Query" } });
  });
  // crawler-data.ts's inner-route GraphQL check is a GET to {dir}/graphql,
  // expecting either __typename/__schema JSON or a non-empty top-level errors
  // array — real GraphQL servers answer a GET the same way.
  app.get("/app/graphql", (_req, res) => {
    res.json({ errors: [{ message: "Must provide query string." }] });
  });
}
