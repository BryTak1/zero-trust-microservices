import { z } from "zod";

// The contract between the gateway, which produces events, and the audit service, which stores them.
export const auditEventSchema = z.object({
  occurredAt: z.iso.datetime(),
  subjectId: z.string().min(1).max(64),
  role: z.string().min(1).max(32),
  method: z.string().min(1).max(10),
  path: z.string().min(1).max(256),
  allowed: z.boolean(),
  rule: z.string().min(1).max(64),
});

export type AuditEvent = z.infer<typeof auditEventSchema>;
