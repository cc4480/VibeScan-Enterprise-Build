import { type Request, type Response, type NextFunction } from "express";
import type { AuthUser } from "@workspace/api-zod";
import { getSessionId, getSession, updateSession } from "../lib/auth";

async function renewSession(sid: string): Promise<void> {
  try {
    const session = await getSession(sid);
    if (session) await updateSession(sid, session);
  } catch {
    // Non-fatal — renewal failure doesn't break the request
  }
}

declare global {
  namespace Express {
    interface User extends AuthUser {}

    interface Request {
      isAuthenticated(): this is AuthedRequest;
      user?: User | undefined;
    }

    export interface AuthedRequest {
      user: User;
    }
  }
}

export async function authMiddleware(
  req: Request,
  _res: Response,
  next: NextFunction,
) {
  req.isAuthenticated = function (this: Request) {
    return this.user != null;
  } as Request["isAuthenticated"];

  const sid = getSessionId(req);
  if (!sid) {
    next();
    return;
  }

  try {
    const session = await getSession(sid);
    if (session?.user) {
      req.user = session.user;
      // Renew session TTL on every request (sliding window)
      void renewSession(sid);
    }
  } catch (err) {
    req.log?.warn({ err }, "Session lookup failed — proceeding unauthenticated");
  }

  next();
}
