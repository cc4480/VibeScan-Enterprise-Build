/**
 * A real HTTP endpoint that receives the mail the real mailer sends.
 *
 * Email is the one place a test cannot be on both ends of the wire: the provider is a third party, and a test must
 * never send real mail. So the mailer is pointed (RESEND_BASE_URL) at this server, and everything up to the network
 * boundary is production code: the suppression checks, the request the mailer builds, its headers and its error
 * handling. This server only records what arrived and answers like the provider does.
 *
 * Call `startMailSink()` BEFORE the first import of anything that sends mail: the base URL is read once, when the
 * mailer module loads.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

export interface SentMail {
  to: string[];
  subject: string;
  html?: string;
  text?: string;
  from?: string;
  authorization?: string;
  /** The audience contact calls (/audiences/...) are recorded too, with their path. */
  path: string;
  body: Record<string, unknown>;
}

export interface MailSink {
  /** Every request received, oldest first. */
  mail: SentMail[];
  /** Answer the next requests with this status, as a provider outage or a rejected key would. 200 restores normal. */
  respondWith(status: number): void;
  clear(): void;
  /** Messages (not audience calls) sent to this address. */
  to(email: string): SentMail[];
  /** The six-digit sign-in code most recently mailed to this address, or undefined. */
  loginCodeTo(email: string): string | undefined;
  stop(): Promise<void>;
}

export async function startMailSink(): Promise<MailSink> {
  const mail: SentMail[] = [];
  let status = 200;
  let n = 0;

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      } catch {
        /* a non-JSON body is recorded as empty */
      }
      const to = Array.isArray(body["to"]) ? (body["to"] as string[]) : typeof body["to"] === "string" ? [body["to"] as string] : [];
      if (status < 300) {
        mail.push({
          to,
          subject: String(body["subject"] ?? ""),
          html: typeof body["html"] === "string" ? (body["html"] as string) : undefined,
          text: typeof body["text"] === "string" ? (body["text"] as string) : undefined,
          from: typeof body["from"] === "string" ? (body["from"] as string) : undefined,
          authorization: req.headers["authorization"],
          path: req.url ?? "",
          body,
        });
      }
      res.statusCode = status;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(status < 300 ? { id: `sink-${++n}` } : { name: "sink_error", message: "the sink was told to refuse", statusCode: status }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));

  process.env["RESEND_BASE_URL"] = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  // The mailer skips sending without a key. This one is accepted by the sink and is worth nothing anywhere else.
  process.env["RESEND_API_KEY"] = "re_test_sink_only";

  const messages = () => mail.filter((m) => m.path.startsWith("/emails"));
  const to = (email: string) => messages().filter((m) => m.to.map((t) => t.toLowerCase()).includes(email.toLowerCase()));
  return {
    mail,
    respondWith: (s) => { status = s; },
    clear: () => { mail.length = 0; status = 200; },
    to,
    loginCodeTo(email) {
      const hit = [...to(email)].reverse().find((m) => /is your .* sign-in code/i.test(m.subject));
      return hit ? hit.subject.match(/^([\d\s]+) is your/)?.[1]?.replace(/\s+/g, "") : undefined;
    },
    stop: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
