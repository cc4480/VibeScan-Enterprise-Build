/**
 * Shared setup for the real-Postgres route tests (BILLING_TEST_DATABASE_URL).
 *
 * `process.env.DATABASE_URL` has to be set before @workspace/db is first imported, so a test
 * file calls `useRealDb()` at the top, ahead of any import of the db or a route.
 */
import express, { type IRouter } from "express";
import pino from "pino";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

export const TEST_DATABASE_URL = process.env["BILLING_TEST_DATABASE_URL"];
/** `describe` when a database was supplied, `describe.skip` otherwise. */
export const dbSuiteOf = (d: { (n: string, f: () => void): unknown; skip: (n: string, f: () => void) => unknown }) =>
  TEST_DATABASE_URL ? d : d.skip;

export function useRealDb(): void {
  if (TEST_DATABASE_URL) process.env["DATABASE_URL"] = TEST_DATABASE_URL;
}

export const uniqueEmail = (tag: string) => `${tag}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`;

/** Migrates the database and returns the db module. */
export async function openDb() {
  const dbMod = await import("@workspace/db");
  await dbMod.migrateToLatest(TEST_DATABASE_URL!);
  return dbMod;
}

export async function makeUser(dbMod: typeof import("@workspace/db"), tag: string): Promise<string> {
  const [u] = await dbMod.db.insert(dbMod.usersTable).values({ email: uniqueEmail(tag) }).returning({ id: dbMod.usersTable.id });
  return u!.id;
}

export type TestUser = { id: string; email?: string | null };

export interface TestApp {
  server: Server;
  /** `http://127.0.0.1:<port>/api` */
  base: string;
  /** Who the next requests are signed in as; null for signed out. */
  as(user: TestUser | null): void;
}

/** Mounts `router` under /api behind the same `req.isAuthenticated()` / `req.user` / `req.log` shape the real app gives it. */
export function startApp(router: IRouter, opts: { json?: boolean; log?: pino.Logger } = {}): TestApp {
  let current: TestUser | null = null;
  const silentLog = pino({ level: "silent" });
  const app = express();
  if (opts.json !== false) app.use(express.json());
  app.use((req, _res, next) => {
    Object.assign(req, { isAuthenticated: () => current !== null, user: current, log: opts.log ?? silentLog });
    next();
  });
  app.use("/api", router);
  const server = app.listen(0);
  return { server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`, as: (u) => { current = u; } };
}
