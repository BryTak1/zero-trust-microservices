import { createRemoteTokenVerifier, envOr, requireEnv } from "@zt/common";
import { createApp } from "./app";
import { createHttpAuditSink, createServiceTokenProvider } from "./auditSink";
import { createDenialTracker } from "./denialTracker";
import { defaultRules, LOCKOUT_WINDOW_MS } from "./rules";

const port = Number(envOr("PORT", "8080"));
const authUrl = requireEnv("AUTH_URL");
const auditUrl = requireEnv("AUDIT_URL");

const app = createApp({
  verify: createRemoteTokenVerifier(`${authUrl}/.well-known/jwks.json`),
  rules: defaultRules,
  denials: createDenialTracker(LOCKOUT_WINDOW_MS),
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
