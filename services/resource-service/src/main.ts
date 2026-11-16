import { Pool } from "pg";
import { createRemoteTokenVerifier, envOr, requireEnv } from "@zt/common";
import { createApp } from "./app";
import { createPostgresDocumentRepository } from "./postgresDocumentRepository";

const port = Number(envOr("PORT", "3000"));
const pool = new Pool({ connectionString: requireEnv("DATABASE_URL") });

const app = createApp({
  verify: createRemoteTokenVerifier(
    `${requireEnv("AUTH_URL")}/.well-known/jwks.json`,
  ),
  documents: await createPostgresDocumentRepository(pool),
});

app.listen(port, () => {
  console.log(`resource-service listening on ${port}`);
});
