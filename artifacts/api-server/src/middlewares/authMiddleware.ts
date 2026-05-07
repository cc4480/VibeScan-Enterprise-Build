import { type Request, type Response, type NextFunction } from "express";
import type { AuthUser } from "@workspace/api-zod";
import { getSessionId, getSession } from "../lib/auth";

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
    }
  } catch {
    // Non-fatal — proceed unauthenticated
  }

  next();
}
