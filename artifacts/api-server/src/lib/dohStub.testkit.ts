/**
 * A real DNS-over-HTTPS resolver on loopback, for tests of the DNS checks.
 *
 * The checks are pointed here with DOH_ENDPOINT_URL, so the real client makes real HTTP requests: the query string it
 * builds, the retry on SERVFAIL, the filtering of answers by record type and the handling of an unreachable resolver are
 * all production code. This server only decides what the zone contains, and records what it was asked.
 *
 * `useDohStub()` starts the server for the calling test file and clears its state before each test.
 */
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";
import { beforeEach, afterAll } from "vitest";

export const TXT = 16, MX = 15, CNAME = 5, DNSKEY = 48;
const TYPE_NUMBER: Record<string, number> = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, DNSKEY: 48 };

export interface DohAnswer { data: string; type?: number }
export interface DohReply { status: number; answers: DohAnswer[] }

export interface DohStub {
  /** The zone: "name TYPE" to its reply. A name nothing is set for answers NOERROR with no records. */
  set(name: string, type: string, answers: DohAnswer[], status?: number): void;
  /** Replies handed out one per request for this name and type, before the zone is consulted again (a flaky resolver). */
  queue(name: string, type: string, replies: DohReply[]): void;
  /** Decides replies for names the zone and queues do not cover; return undefined to fall through to NOERROR/empty. */
  rule: ((name: string, type: string) => DohReply | undefined) | null;
  /** Every query received, as "name TYPE", in order. */
  asked: string[];
  /** When true the resolver drops every connection without answering, as an unreachable one does. */
  down: boolean;
  /** Reset the zone, queues, rule and history. */
  reset(): void;
  stop(): Promise<void>;
}

const key = (name: string, type: string) => `${name.toLowerCase()} ${type.toUpperCase()}`;

export async function startDohStub(): Promise<DohStub> {
  const sockets = new Set<Socket>();
  const zone = new Map<string, DohReply>();
  const queues = new Map<string, DohReply[]>();
  const state: DohStub = {
    set: (name, type, answers, status = 0) => void zone.set(key(name, type), { status, answers }),
    queue: (name, type, replies) => void queues.set(key(name, type), [...replies]),
    rule: null,
    asked: [],
    down: false,
    reset: () => {
      zone.clear();
      queues.clear();
      state.rule = null;
      state.asked.length = 0;
      state.down = false;
    },
    stop: async () => {},
  };

  const server = http.createServer((req, res) => {
    if (state.down) { req.socket.destroy(); return; }
    const url = new URL(req.url ?? "/", "http://doh.local");
    const name = url.searchParams.get("name") ?? "";
    const type = (url.searchParams.get("type") ?? "A").toUpperCase();
    const k = key(name, type);
    state.asked.push(k);
    const reply = queues.get(k)?.shift() ?? zone.get(k) ?? state.rule?.(name.toLowerCase(), type) ?? { status: 0, answers: [] };
    const wanted = TYPE_NUMBER[type] ?? 1;
    res.writeHead(200, { "content-type": "application/dns-json" });
    res.end(JSON.stringify({
      Status: reply.status,
      ...(reply.answers.length ? { Answer: reply.answers.map((a) => ({ name, type: a.type ?? wanted, TTL: 300, data: a.data })) } : {}),
    }));
  });
  server.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  process.env["DOH_ENDPOINT_URL"] = `http://127.0.0.1:${(server.address() as AddressInfo).port}/dns-query`;

  state.stop = () => new Promise<void>((resolve) => {
    delete process.env["DOH_ENDPOINT_URL"];
    for (const s of sockets) s.destroy();
    server.close(() => resolve());
  });
  return state;
}

/** Start the resolver for this test file, empty before every test, stopped at the end. */
export async function useDohStub(): Promise<DohStub> {
  const doh = await startDohStub();
  beforeEach(() => doh.reset());
  afterAll(() => doh.stop());
  return doh;
}

/** TXT answers for a name: each string is one record. */
export const txt = (...records: string[]): DohAnswer[] => records.map((data) => ({ data: `"${data}"`, type: TXT }));
