import { Client } from "cassandra-driver";
import { createRemoteTokenVerifier, envOr, requireEnv } from "@zt/common";
import { createApp } from "./app";
import { createInMemoryAuditStore, type AuditStore } from "./auditStore";
import { createCassandraAuditStore } from "./cassandraAuditStore";

const port = Number(envOr("PORT", "3000"));

// AUDIT_STORE=memory runs the service without Cassandra, for machines short on RAM.
const createStore = (): Promise<AuditStore> =>
  envOr("AUDIT_STORE", "cassandra") === "memory"
    ? Promise.resolve(createInMemoryAuditStore())
    : createCassandraAuditStore(
        new Client({
          contactPoints: requireEnv("CASSANDRA_CONTACT_POINTS").split(","),
          localDataCenter: envOr("CASSANDRA_DATACENTER", "datacenter1"),
        }),
      );

const app = createApp({
  verify: createRemoteTokenVerifier(
    `${requireEnv("AUTH_URL")}/.well-known/jwks.json`,
  ),
  store: await createStore(),
});

app.listen(port, () => {
  console.log(`audit-service listening on ${port}`);
});
