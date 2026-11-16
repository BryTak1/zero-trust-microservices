import type { Client } from "cassandra-driver";
import type { AuditEvent } from "@zt/common";
import { dayOf, type AuditStore } from "./auditStore";

export const createCassandraAuditStore = async (
  client: Client,
): Promise<AuditStore> => {
  await client.connect();
  await client.execute(CREATE_KEYSPACE);
  await client.execute(CREATE_TABLE);
  return {
    append: async (event) => {
      await client.execute(
        INSERT,
        [
          dayOf(event),
          new Date(event.occurredAt),
          event.subjectId,
          event.role,
          event.method,
          event.path,
          event.allowed,
          event.rule,
        ],
        { prepare: true },
      );
    },
    listByDay: async (day) => {
      const result = await client.execute(SELECT, [day], { prepare: true });
      return result.rows.map(
        (row): AuditEvent => ({
          occurredAt: (row["occurred_at"] as Date).toISOString(),
          subjectId: row["subject_id"],
          role: row["role"],
          method: row["method"],
          path: row["path"],
          allowed: row["allowed"],
          rule: row["rule"],
        }),
      );
    },
  };
};

// A single-node demo cluster; a real deployment would use NetworkTopologyStrategy with RF 3.
const CREATE_KEYSPACE = `
  CREATE KEYSPACE IF NOT EXISTS zt_audit
  WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}`;

// Partitioning by day serves the one query we run ("what happened on this day?") from a
// single partition, and the timeuuid clustering key keeps events time-ordered within it.
const CREATE_TABLE = `
  CREATE TABLE IF NOT EXISTS zt_audit.events_by_day (
    day text,
    event_id timeuuid,
    occurred_at timestamp,
    subject_id text,
    role text,
    method text,
    path text,
    allowed boolean,
    rule text,
    PRIMARY KEY ((day), event_id)
  ) WITH CLUSTERING ORDER BY (event_id DESC)`;

const INSERT = `
  INSERT INTO zt_audit.events_by_day
    (day, event_id, occurred_at, subject_id, role, method, path, allowed, rule)
  VALUES (?, now(), ?, ?, ?, ?, ?, ?, ?)`;

const SELECT = `
  SELECT occurred_at, subject_id, role, method, path, allowed, rule
    FROM zt_audit.events_by_day WHERE day = ? LIMIT 200`;
