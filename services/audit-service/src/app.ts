import express, { type Express } from "express";
import { z } from "zod";
import {
  auditEventSchema,
  errorHandler,
  requireRole,
  type TokenVerifier,
} from "@zt/common";
import type { AuditStore } from "./auditStore";

export type AuditAppDeps = {
  readonly verify: TokenVerifier;
  readonly store: AuditStore;
};

export const createApp = ({ verify, store }: AuditAppDeps): Express => {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "10kb" }));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  // Only services may write, so a user cannot forge or flood the audit trail.
  app.post("/events", requireRole(verify, "service"), async (req, res) => {
    await store.append(auditEventSchema.parse(req.body));
    res.status(202).end();
  });

  app.get("/events", requireRole(verify, "admin"), async (req, res) => {
    const { day } = querySchema.parse(req.query);
    res.json(await store.listByDay(day ?? today()));
  });

  app.use(errorHandler);
  return app;
};

const querySchema = z.object({ day: z.iso.date().optional() });

const today = (): string => new Date().toISOString().slice(0, 10);
