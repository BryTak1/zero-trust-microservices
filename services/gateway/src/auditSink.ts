import type { AuditEvent } from "@zt/common";

export type AuditSink = (event: AuditEvent) => Promise<void>;

export type ServiceTokenProvider = () => Promise<string>;

export const createHttpAuditSink =
  (auditUrl: string, serviceToken: ServiceTokenProvider): AuditSink =>
  async (event) => {
    const response = await fetch(`${auditUrl}/events`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${await serviceToken()}`,
      },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      throw new Error(`Audit service responded with ${response.status}`);
    }
  };

// The gateway proves its own identity with a short-lived token, like any user would.
export const createServiceTokenProvider = (
  authUrl: string,
  clientId: string,
  clientSecret: string,
): ServiceTokenProvider => {
  let cached: { token: string; expiresAt: number } | undefined;
  return async () => {
    if (cached && cached.expiresAt > Date.now()) {
      return cached.token;
    }
    const response = await fetch(`${authUrl}/service-token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ clientId, clientSecret }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      throw new Error(`Service token request failed with ${response.status}`);
    }
    const body = (await response.json()) as {
      accessToken: string;
      expiresIn: number;
    };
    cached = {
      token: body.accessToken,
      expiresAt: Date.now() + (body.expiresIn - REFRESH_MARGIN_SECONDS) * 1000,
    };
    return cached.token;
  };
};

const REQUEST_TIMEOUT_MS = 5000;
const REFRESH_MARGIN_SECONDS = 30;
