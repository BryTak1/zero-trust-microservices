import { createRemoteTokenVerifier, envOr, requireEnv } from "@zt/common";
import { createApp } from "./app";
import { createHttpAuditSink, createServiceTokenProvider } from "./auditSink";
import { defaultRules } from "./rules";

const port = Number(envOr("PORT", "8080"));
const authUrl = requireEnv("AUTH_URL");
const auditUrl = requireEnv("AUDIT_URL");

const app = createApp({
  verify: createRemoteTokenVerifier(`${authUrl}/.well-known/jwks.json`),
  rules: defaultRules,
  audit: createHttpAuditSink(
    auditUrl,
    createServiceTokenProvider(
      authUrl,
      "gateway",
      requireEnv("GATEWAY_CLIENT_SECRET"),
    ),
  ),
  authUrl,
  upstreams: [
    { prefix: "/api/documents", target: `${requireEnv("RESOURCE_URL")}/documents` },
    { prefix: "/api/audit", target: `${auditUrl}/events` },
  ],
});

app.listen(port, () => {
  console.log(`gateway listening on ${port}`);
});
