import type { AuditEvent } from "@zt/common";

// Deliberately has no update or delete: the audit trail is append-only.
export type AuditStore = {
  readonly append: (event: AuditEvent) => Promise<void>;
  // Day is a UTC date such as "2026-11-16"; newest events come first.
  readonly listByDay: (day: string) => Promise<readonly AuditEvent[]>;
};

export const dayOf = (event: AuditEvent): string => event.occurredAt.slice(0, 10);

export const createInMemoryAuditStore = (): AuditStore => {
  const events: AuditEvent[] = [];
  return {
    append: async (event) => {
      events.unshift(event);
    },
    listByDay: async (day) => events.filter((event) => dayOf(event) === day),
  };
};
