import { servers, serve } from "./http.testkit";
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import http from "node:http";
import { scanFetch, scanFetchOrThrow } from "./http.js";

describe("blocked target addresses", () => {
  // The rest of this file drives loopback servers and relies on the self-hosted
  // opt-out being on (vitest.config.ts). These cases turn it off, which is the
  // shipping default and what a hosted deployment runs.
  const optOut = process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
  beforeEach(() => { delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"]; });
  afterEach(() => {
    if (optOut === undefined) delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
    else process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = optOut;
  });

  it("refuses a request aimed straight at cloud metadata", async () => {
    await expect(
      scanFetchOrThrow("http://169.254.169.254/latest/meta-data/"),
    ).rejects.toThrow(/blocked target address/);
  });

  it("returns null rather than throwing on the non-throwing entry point", async () => {
    expect(await scanFetch("http://10.0.0.1/admin")).toBeNull();
  });

  it("refuses to follow a redirect that points at an internal address", async () => {
    // This is why the check sits in the request loop and not only at scan
    // creation: the submitted URL is acceptable and the target supplies the
    // dangerous one. The opt-out is switched off partway through the first hop,
    // so hop 0 is permitted to reach a loopback stand-in and hop 1 is judged
    // under the shipping default.
    const attempted: string[] = [];
    const { port } = await serve((req, res) => {
      attempted.push(req.url ?? "");
      delete process.env["ALLOW_PRIVATE_SCAN_TARGETS"];
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" }).end();
    });

    process.env["ALLOW_PRIVATE_SCAN_TARGETS"] = "true";
    expect(await scanFetch(`http://127.0.0.1:${port}/`)).toBeNull();

    // The loopback server was asked once; the metadata address was never put on the wire.
    expect(attempted).toEqual(["/"]);
  });
});

describe("the timeout covers the response body, not only the headers", () => {
  // The abort timer used to be cleared as soon as fetch() resolved with headers, and the body was
  // then read with no timer at all. A streaming (SSE) chat endpoint is read until the model
  // finishes, and a stalled or never-ending stream hung the caller until the scan-level timeout:
  // "10s" bounded only time-to-headers, so the cost bound the probes advertise held only for the
  // number of requests, not for time.
  it("returns within the timeout when the body never ends, keeping what has arrived", async () => {
    const { port } = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write("data: first token\n\n");
      // Never ended by the server. Torn down late so the test's own cleanup is not left waiting.
      setTimeout(() => res.destroy(), 5_000).unref();
    });
    const started = Date.now();
    const r = await scanFetch(`http://127.0.0.1:${port}/`, { timeoutMs: 400 });
    expect(Date.now() - started).toBeLessThan(3_000);
    expect(r).not.toBeNull();
    expect(r!.status).toBe(200);
    expect(r!.body).toContain("first token");
  });

  it("does not cut off a body that finishes in time", async () => {
    const { port } = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.write("part one, ");
      setTimeout(() => res.end("part two"), 100);
    });
    const r = await scanFetch(`http://127.0.0.1:${port}/`, { timeoutMs: 2_000 });
    expect(r!.body).toBe("part one, part two");
  });

  it("still bounds a redirect hop whose body never ends", async () => {
    const { port } = await serve((req, res) => {
      if (req.url === "/start") {
        res.writeHead(302, { location: "/end" });
        res.write("moved...");
        setTimeout(() => res.destroy(), 5_000).unref();
        return;
      }
      res.writeHead(200).end("landed");
    });
    const started = Date.now();
    const r = await scanFetch(`http://127.0.0.1:${port}/start`, { timeoutMs: 400 });
    expect(Date.now() - started).toBeLessThan(3_000);
    expect(r?.body).toBe("landed");
  });
});
