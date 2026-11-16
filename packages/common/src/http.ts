import type { ErrorRequestHandler, Request, RequestHandler } from "express";
import { ZodError } from "zod";
import type { Principal, Role } from "./principal";
import type { TokenVerifier } from "./tokens";

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export const bearerToken = (req: Request): string | undefined => {
  const [scheme, token] = (req.headers.authorization ?? "").split(" ");
  return scheme === "Bearer" && token ? token : undefined;
};

export const authenticate = async (
  verify: TokenVerifier,
  req: Request,
): Promise<Principal | undefined> => {
  const token = bearerToken(req);
  if (!token) {
    return undefined;
  }
  try {
    return await verify(token);
  } catch {
    return undefined;
  }
};

// Every service calls this itself, so no request is trusted for having come through the gateway.
export const requireRole =
  (verify: TokenVerifier, ...allowed: readonly Role[]): RequestHandler =>
  async (req, res, next) => {
    const principal = await authenticate(verify, req);
    if (!principal) {
      throw new HttpError(401, "Authentication required.");
    }
    if (!allowed.includes(principal.role)) {
      throw new HttpError(403, "Forbidden.");
    }
    res.locals.principal = principal;
    next();
  };

export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  if (err instanceof ZodError) {
    res.status(400).json({ error: "Invalid request.", issues: err.issues });
    return;
  }
  if (isBodyParseError(err)) {
    res.status(err.status).json({ error: "Invalid request body." });
    return;
  }
  // Only the message is logged, because error objects can carry request data.
  console.error(err instanceof Error ? err.message : "Unknown error");
  res.status(500).json({ error: "Internal error." });
};

const isBodyParseError = (err: unknown): err is { status: number } =>
  typeof err === "object" &&
  err !== null &&
  "type" in err &&
  "status" in err &&
  typeof err.status === "number" &&
  err.status >= 400 &&
  err.status < 500;
