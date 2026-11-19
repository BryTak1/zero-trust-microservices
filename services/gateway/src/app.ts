import express, { type Express, type RequestHandler } from "express";
import { rateLimit } from "express-rate-limit";
import {
  authenticate,
  errorHandler,
  HttpError,
  type TokenVerifier,
} from "@zt/common";
import type { AuditSink } from "./auditSink";
import type { DenialTracker } from "./denialTracker";
import { evaluate, type Rule } from "./policy";
import { forward, resolveUpstream, type Upstream } from "./proxy";

export type GatewayDeps = {
  readonly verify: TokenVerifier;
  readonly rules: readonly Rule[];
  readonly denials: DenialTracker;
  readonly audit: AuditSink;
  readonly authUrl: string;
  readonly upstreams: readonly Upstream[];
};

export const createApp = (deps: GatewayDeps): Express => {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "100kb" }));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  // These are the only unauthenticated routes, so they are the ones worth brute-forcing.
  const credentialLimiter = rateLimit({
    windowMs: 60_000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: { error: "Too many requests." },
  });
  app.post("/auth/register", credentialLimiter, (req, res) =>
    forward(req, res, `${deps.authUrl}/register`),
  );
  app.post("/auth/login", credentialLimiter, (req, res) =>
    forward(req, res, `${deps.authUrl}/login`),
  );

  app.use("/api", enforcePolicy(deps));

  app.use(errorHandler);
  return app;
};

// The policy enforcement point: every request is authenticated, authorised and audited.
const enforcePolicy =
  (deps: GatewayDeps): RequestHandler =>
  async (req, res) => {
    const path = req.baseUrl + req.path;
    const principal = await authenticate(deps.verify, req);
    // Anonymous callers all share one identity, so only known principals are tracked;
    // the rate limit on login covers anonymous probing.
    const recentDenials = principal ? deps.denials.count(principal.id) : 0;
    const decision = evaluate(deps.rules, {
      principal,
      method: req.method,
      path,
      recentDenials,
    });
    if (!decision.allowed && principal) {
      deps.denials.record(principal.id);
    }

    const audited = await deps
      .audit({
        occurredAt: new Date().toISOString(),
        subjectId: principal?.id ?? "anonymous",
        role: principal?.role ?? "none",
        method: req.method,
        path: path.slice(0, 256),
        allowed: decision.allowed,
        rule: decision.rule,
      })
      .then(
        () => true,
        () => false,
      );

    if (!decision.allowed) {
      throw principal
        ? new HttpError(403, "Forbidden.")
        : new HttpError(401, "Authentication required.");
    }
    // Fail closed: access that cannot be recorded is not granted.
    if (!audited) {
      throw new HttpError(503, "Audit unavailable.");
    }
    const target = resolveUpstream(deps.upstreams, path);
    if (!target) {
      throw new HttpError(404, "Not found.");
    }
    await forward(req, res, target);
  };
