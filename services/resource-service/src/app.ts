import { randomUUID } from "node:crypto";
import express, { type Express } from "express";
import { z } from "zod";
import {
  errorHandler,
  HttpError,
  requireRole,
  type Principal,
  type TokenVerifier,
} from "@zt/common";
import type { DocumentRepository } from "./documentRepository";

export type ResourceAppDeps = {
  readonly verify: TokenVerifier;
  readonly documents: DocumentRepository;
};

export const createApp = ({ verify, documents }: ResourceAppDeps): Express => {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "100kb" }));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  // Roles are checked again here; the gateway having allowed a request is not proof enough.
  const readers = requireRole(verify, "employee", "admin");
  const admins = requireRole(verify, "admin");

  app.get("/documents", readers, async (_req, res) => {
    res.json(await documents.list());
  });

  app.get("/documents/:id", readers, async (req, res) => {
    const document = await documents.findById(parseId(req.params.id));
    if (!document) {
      throw new HttpError(404, "Not found.");
    }
    res.json(document);
  });

  app.post("/documents", admins, async (req, res) => {
    const principal = res.locals.principal as Principal;
    const document = {
      id: randomUUID(),
      ...documentSchema.parse(req.body),
      createdBy: principal.id,
    };
    await documents.insert(document);
    res.status(201).json(document);
  });

  app.delete("/documents/:id", admins, async (req, res) => {
    const removed = await documents.remove(parseId(req.params.id));
    if (!removed) {
      throw new HttpError(404, "Not found.");
    }
    res.status(204).end();
  });

  app.use(errorHandler);
  return app;
};

const documentSchema = z.object({
  title: z.string().min(1).max(200),
  body: z.string().max(10_000),
});

const parseId = (id: unknown): string => z.uuid().parse(id);
