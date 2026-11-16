// Walks the main path through a running stack: npx tsx scripts/demo.ts
import { randomBytes } from "node:crypto";
import { authenticator } from "otplib";

const GATEWAY = process.env.GATEWAY_URL ?? "http://localhost:8080";

const main = async (): Promise<void> => {
  const email = `demo-${randomBytes(4).toString("hex")}@example.com`;
  const password = randomBytes(16).toString("hex");

  const registered = await call("POST", "/auth/register", { body: { email, password } });
  report("Register a new employee", registered, 201);
  const { totpSecret } = registered.body as { totpSecret: string };

  const loggedIn = await call("POST", "/auth/login", {
    body: { email, password, totpCode: authenticator.generate(totpSecret) },
  });
  report("Log in with password and TOTP code", loggedIn, 200);
  const { accessToken: token } = loggedIn.body as { accessToken: string };

  report("Read documents with a token", await call("GET", "/api/documents", { token }), 200);
  report("Read documents without a token", await call("GET", "/api/documents"), 401);
  report(
    "Create a document as an employee",
    await call("POST", "/api/documents", { token, body: { title: "x", body: "y" } }),
    403,
  );
  report("Read the audit trail as an employee", await call("GET", "/api/audit", { token }), 403);
  report(
    "Path traversal attempt",
    await call("GET", "/api/documents/..%2Fhealth", { token }),
    404,
  );

  console.log(`\nRegistered ${email}. Promote it to admin to try the admin path (see README).`);
  process.exitCode = failures > 0 ? 1 : 0;
};

type Result = { readonly status: number; readonly body: unknown };

let failures = 0;

const report = (step: string, result: Result, expected: number): void => {
  const ok = result.status === expected;
  failures += ok ? 0 : 1;
  console.log(`${ok ? "PASS" : "FAIL"}  ${step}: HTTP ${result.status} (expected ${expected})`);
};

const call = async (
  method: string,
  path: string,
  options: { readonly token?: string; readonly body?: unknown } = {},
): Promise<Result> => {
  const response = await fetch(`${GATEWAY}${path}`, {
    method,
    headers: {
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const text = await response.text();
  return { status: response.status, body: text ? safeJson(text) : undefined };
};

const safeJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

await main();
