import { describe, it, expect, vi, beforeEach } from "vitest";
import type { IRouter } from "express";

const state = vi.hoisted(() => ({
  rows: [] as unknown[],
  updates: [] as Record<string, unknown>[],
}));

vi.mock("drizzle-orm", () => ({ eq: (a: unknown, b: unknown) => ({ a, b }) }));
vi.mock("@workspace/db", () => ({
  usersTable: { id: "id", email: "email", passwordHash: "password_hash", emailVerifiedAt: "email_verified_at" },
  db: {
    select: () => ({ from: () => ({ where: async () => state.rows }) }),
    update: () => ({
      set: (values: Record<string, unknown>) => ({
        where: async () => {
          state.updates.push(values);
          return [];
        },
      }),
    }),
  },
}));
vi.mock("../lib/auth", () => ({
  createSession: vi.fn(async () => "sid"),
  SESSION_COOKIE: "sid",
  SESSION_TTL: 1000,
  clearSession: vi.fn(async () => {}),
  deleteSessionsForUser: vi.fn(async () => {}),
  getSessionId: vi.fn(() => undefined),
}));
vi.mock("../lib/oauthTokens", () => ({ revokeAllAccess: vi.fn(async () => {}) }));
vi.mock("../lib/authTokens", () => ({
  issueToken: vi.fn(async () => "token"),
  redeemToken: vi.fn(async () => ({ ok: false, reason: "invalid" })),
}));
vi.mock("../lib/pendingLogin", () => ({ abandonLoginChallenges: vi.fn(async () => {}) }));
vi.mock("../lib/mailer", () => ({
  sendEmailVerification: vi.fn(async () => {}),
  sendPasswordReset: vi.fn(async () => {}),
}));
vi.mock("../lib/password", () => ({
  hashPassword: vi.fn(async (p: string) => `hash:${p}`),
  verifyPassword: vi.fn(async (p: string, h: string) => h === `hash:${p}`),
}));
vi.mock("../lib/clientIp", () => ({ clientIp: (req: { ip?: string }) => req.ip ?? "unknown" }));

import { registerAccountRecovery } from "./accountRecovery";
import { attempts } from "./accountShared";
import { revokeAllAccess } from "../lib/oauthTokens";
import { deleteSessionsForUser } from "../lib/auth";

type Handler = (req: unknown, res: unknown) => Promise<void>;
const routes = new Map<string, Handler>();
registerAccountRecovery({
  post: (path: string, ...handlers: Handler[]) => {
    routes.set(path, handlers[handlers.length - 1]!);
  },
} as unknown as IRouter);

function makeRes() {
  const res = {
    statusCode: 200,
    body: null as unknown,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(payload: unknown) {
      res.body = payload;
      return res;
    },
    cookie: vi.fn(),
  };
  return res;
}

function makeReq(body: unknown, overrides: Record<string, unknown> = {}) {
  return {
    body,
    ip: "198.51.100.1",
    protocol: "https",
    isAuthenticated: () => false,
    log: { error: vi.fn(), info: vi.fn() },
    ...overrides,
  };
}

const signedIn = { isAuthenticated: () => true, user: { id: "user-1" } };
const OLD = "old-password-123";
const NEW = "brand-new-pass-1";

async function call(path: string, req: unknown) {
  const res = makeRes();
  await routes.get(path)!(req, res);
  return res;
}

beforeEach(() => {
  attempts.clear();
  state.rows = [{ id: "user-1", email: "owner@example.com", passwordHash: `hash:${OLD}` }];
  state.updates = [];
  vi.mocked(revokeAllAccess).mockClear();
  vi.mocked(deleteSessionsForUser).mockClear();
});

describe("POST /account/password/change — what it cuts off", () => {
  it("revokes API tokens and OAuth grants, as a reset does", async () => {
    const res = await call(
      "/account/password/change",
      makeReq({ currentPassword: OLD, newPassword: NEW }, signedIn),
    );

    expect(res.statusCode).toBe(200);
    expect(state.updates.some((u) => u["passwordHash"] === `hash:${NEW}`)).toBe(true);
    expect(revokeAllAccess).toHaveBeenCalledTimes(1);
    expect(revokeAllAccess).toHaveBeenCalledWith("user-1");
    expect(deleteSessionsForUser).toHaveBeenCalledWith("user-1");
  });

  it("revokes nothing when the current password is wrong", async () => {
    const res = await call(
      "/account/password/change",
      makeReq({ currentPassword: "not-the-password", newPassword: NEW }, signedIn),
    );

    expect(res.statusCode).toBe(401);
    expect(revokeAllAccess).not.toHaveBeenCalled();
    expect(state.updates).toHaveLength(0);
  });
});

describe("POST /account/password/forgot — per address", () => {
  const forgot = (email: string, ip: string) => call("/account/password/forgot", makeReq({ email }, { ip }));

  it("refuses the eleventh request for one address, even from a new IP each time", async () => {
    for (let i = 0; i < 10; i++) {
      expect((await forgot("victim@example.com", `198.51.100.${i + 10}`)).statusCode).toBe(200);
    }

    const refused = await forgot("victim@example.com", "203.0.113.200");
    expect(refused.statusCode).toBe(429);
  });

  it("keeps other addresses' allowances separate", async () => {
    for (let i = 0; i < 10; i++) await forgot("victim@example.com", `198.51.100.${i + 10}`);
    await forgot("victim@example.com", "203.0.113.201");

    expect((await forgot("someone-else@example.com", "203.0.113.202")).statusCode).toBe(200);
  });
});
