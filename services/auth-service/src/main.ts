import { Pool } from "pg";
import { envOr, requireEnv } from "@zt/common";
import { createApp } from "./app";
import { totpMfaProvider } from "./mfa";
import { scryptPasswordHasher } from "./passwords";
import { createPostgresUserRepository } from "./postgresUserRepository";
import { createTokenIssuer } from "./tokenIssuer";

const port = Number(envOr("PORT", "3000"));
const pool = new Pool({ connectionString: requireEnv("DATABASE_URL") });

const app = createApp({
  users: await createPostgresUserRepository(pool),
  passwords: scryptPasswordHasher,
  mfa: totpMfaProvider,
  tokens: await createTokenIssuer(),
  serviceClients: { gateway: requireEnv("GATEWAY_CLIENT_SECRET") },
});

app.listen(port, () => {
  console.log(`auth-service listening on ${port}`);
});
