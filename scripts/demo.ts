// Walks the Zero Trust checks against a running stack: npm run demo
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { generateKeyPair, SignJWT } from "jose";
import { authenticator } from "otplib";
import { TOKEN_AUDIENCE, TOKEN_ISSUER, type AuditEvent } from "@zt/common";

const GATEWAY = process.env.GATEWAY_URL ?? "http://localhost:8080";

const main = async (): Promise<void> => {
  const email = `demo-${randomBytes(4).toString("hex")}@example.com`;
  const password = randomBytes(16).toString("hex");

  // The numbers in these comments match the #numbers the demo prints next to each result.

  // ── Section 1: Identity ──────────────────────────────────────────────
  section("Identity: a password alone is not enough");

  // #1  POST /auth/register  (gateway forwards to auth-service). Expect 201 and an MFA secret.
  const registered = await call("POST", "/auth/register", { body: { email, password } });
  report("Register a new employee", registered, 201);
  const { totpSecret } = registered.body as { totpSecret: string };

  // #2  POST /auth/login with the right password but a wrong one-time code. Expect 401.
  report(
    "Log in with the wrong one-time code",
    await logIn(email, password, wrongCode(totpSecret)),
    401,
  );

  // #3  POST /auth/login with the right password and code. Expect 200 and a 5-minute token.
  const loggedIn = await logIn(email, password, authenticator.generate(totpSecret));
  report("Log in with the right one-time code", loggedIn, 200);
  const token = accessToken(loggedIn);

  // ── Section 2: Least privilege at the gateway ────────────────────────
  section("Least privilege at the gateway");

  // #4  GET /api/documents as an employee. The staff-read-documents rule allows it. Expect 200.
  report("Read documents with a token", await call("GET", "/api/documents", { token }), 200);

  // #5  GET /api/documents with no token. The gateway does not know the caller. Expect 401.
  report("Read documents without a token", await call("GET", "/api/documents"), 401);

  // #6  POST /api/documents as an employee. No rule allows it, so default-deny. Expect 403.
  report(
    "Employee tries to create a document",
    await call("POST", "/api/documents", { token, body: { title: "x", body: "y" } }),
    403,
  );

  // #7  GET /api/audit as an employee. Only admins may read the audit trail. Expect 403.
  report("Employee tries to read the audit trail", await call("GET", "/api/audit", { token }), 403);

  // #8  GET /api/documents/..%2Fhealth. The proxy rejects the unsafe path. Expect 404.
  report(
    "Path traversal attempt",
    await call("GET", "/api/documents/..%2Fhealth", { token }),
    404,
  );

  // ── Section 3: Backends do not trust the gateway ─────────────────────
  section("Backends do not trust the gateway");

  // #9  GET resource-service:3000/documents directly, skipping the gateway, with no token. Expect 401.
  report("Call resource-service directly with no token", direct("/documents"), 401);

  // #10 The same direct call with an admin token signed by the attacker's own key. Expect 401.
  report(
    "Call resource-service directly with a forged admin token",
    direct("/documents", await forgedAdminToken()),
    401,
  );

  // ── Section 4: Micro-segmentation ────────────────────────────────────
  section("Micro-segmentation: each service reaches only what it needs");

  // #11 to #15 are not HTTP requests: each opens a raw TCP connection from inside a container.
  expectReach("resource-service reaches its own database", reach("resource-service", "postgres-resources", 5432), "reachable");
  expectReach("resource-service cannot reach the auth database", reach("resource-service", "postgres-auth", 5432), "unreachable");
  expectReach("resource-service cannot reach Cassandra", reach("resource-service", "cassandra", 9042), "unreachable");
  expectReach("resource-service cannot reach audit-service", reach("resource-service", "audit-service", 3000), "unreachable");
  expectReach("gateway cannot reach any database", reach("gateway", "postgres-auth", 5432), "unreachable");

  // ── Section 5: Extra rights come from policy ─────────────────────────
  section("Extra rights come from policy, not from the network");

  // Setup, not a check: an SQL UPDATE makes this user an admin, standing in for an admin console.
  promoteToAdmin(email);

  // #16 POST /auth/login again. The new token now carries role "admin". Expect 200.
  const adminLogin = await logIn(email, password, authenticator.generate(totpSecret));
  report("Log in again after promotion to admin", adminLogin, 200);
  const adminToken = accessToken(adminLogin);

  // #17 POST /api/documents as an admin. The admins-manage-documents rule allows it. Expect 201.
  report(
    "Admin creates a document",
    await call("POST", "/api/documents", {
      token: adminToken,
      body: { title: "Runbook", body: "Created during the demo." },
    }),
    201,
  );

  // #18 GET /api/audit as an admin. Expect 200, then print the latest decisions from Cassandra.
  const audit = await call("GET", "/api/audit", { token: adminToken });
  report("Admin reads the audit trail", audit, 200);
  printRecentDecisions(audit.body as readonly AuditEvent[]);

  // ── Section 6: Fail closed ───────────────────────────────────────────
  section("Fail closed: no audit record, no access");

  // #19 Stop audit-service, then GET /api/documents as an admin. The decision can't be
  // recorded, so the gateway refuses. Expect 503.
  compose("stop", "audit-service");
  try {
    report(
      "Read documents while audit-service is down",
      await call("GET", "/api/documents", { token: adminToken }),
      503,
    );
  } finally {
    compose("start", "audit-service");
  }

  // #20 Restart audit-service and repeat the same GET until it works again. Expect 200.
  report(
    "Read documents once audit-service is back",
    await retryUntil(() => call("GET", "/api/documents", { token: adminToken }), 200),
    200,
  );

  // ── Section 7: Adaptive policy ───────────────────────────────────────
  section("Adaptive policy: repeated denials lock the account");

  // #21 POST /api/documents as the employee 5 times. Each is denied and counted. Expect 403 x5.
  const attempts = await repeat(LOCKOUT_ATTEMPTS, () =>
    call("POST", "/api/documents", { token, body: { title: "x", body: "y" } }),
  );
  record(
    `Employee makes ${LOCKOUT_ATTEMPTS} denied write attempts`,
    attempts.every((attempt) => attempt.status === 403),
    `HTTP ${attempts.map((attempt) => attempt.status).join(", ")} (expected all 403)`,
  );

  // #22 GET /api/documents as the same employee, the request that worked in #4. Now the
  // suspicious-activity-lockout rule matches, and a deny beats the allow. Expect 403.
  report(
    "The same employee's normal read is now blocked",
    await call("GET", "/api/documents", { token }),
    403,
  );

  // #23 Not an HTTP request: query Cassandra directly for the newest decision's rule name.
  const rule = latestAuditRule();
  record(
    "The audit trail names the lockout rule",
    rule === "suspicious-activity-lockout",
    `${rule || "nothing"} (expected suspicious-activity-lockout)`,
  );

  console.log(`\n${checks - failures}/${checks} checks passed.`);
  process.exitCode = failures > 0 ? 1 : 0;
};

type Result = { readonly status: number; readonly body: unknown };

type Reach = "reachable" | "unreachable";

const LOCKOUT_ATTEMPTS = 5;

let checks = 0;
let failures = 0;

let sections = 0;

const section = (title: string): void => {
  sections += 1;
  console.log(`\n${sections}. ${title}`);
};

const report = (step: string, result: Result, expected: number): void =>
  record(step, result.status === expected, `HTTP ${result.status} (expected ${expected})`);

const expectReach = (step: string, actual: Reach, expected: Reach): void =>
  record(step, actual === expected, `${actual} (expected ${expected})`);

const record = (step: string, ok: boolean, detail: string): void => {
  checks += 1;
  failures += ok ? 0 : 1;
  console.log(`  ${ok ? "PASS" : "FAIL"}  #${String(checks).padEnd(3)} ${step}: ${detail}`);
};

const call = async (
  method: string,
  path: string,
  options: { readonly token?: string; readonly body?: unknown } = {},
): Promise<Result> => {
  const request = () =>
    fetch(`${GATEWAY}${path}`, {
      method,
      headers: {
        ...(options.body ? { "content-type": "application/json" } : {}),
        ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
  // The slow docker exec checks can outlast the gateway's keep-alive timeout, so a reused
  // connection may already be closed; one retry on a fresh connection covers that.
  const response = await request().catch((error: unknown) => {
    if (isClosedSocket(error)) {
      return request();
    }
    throw error;
  });
  const text = await response.text();
  return { status: response.status, body: text ? safeJson(text) : undefined };
};

const isClosedSocket = (error: unknown): boolean =>
  error instanceof TypeError &&
  typeof error.cause === "object" &&
  error.cause !== null &&
  "code" in error.cause &&
  error.cause.code === "UND_ERR_SOCKET";

const safeJson = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

const logIn = (email: string, password: string, totpCode: string): Promise<Result> =>
  call("POST", "/auth/login", { body: { email, password, totpCode } });

const wrongCode = (totpSecret: string): string =>
  authenticator.generate(totpSecret) === "000000" ? "111111" : "000000";

const accessToken = (result: Result): string =>
  (result.body as { accessToken: string }).accessToken;

// Runs inside the gateway container, because the backends are not reachable from the host.
const direct = (path: string, token?: string): Result => {
  const output = execFileSync(
    "docker",
    [
      "compose", "exec", "-T", "-e", `TOKEN=${token ?? ""}`, "gateway",
      "node", "-e", PROBE, `http://resource-service:3000${path}`,
    ],
    { encoding: "utf8" },
  );
  return { status: Number(output.trim()), body: undefined };
};

const PROBE =
  "fetch(process.argv[1],{headers:process.env.TOKEN?{authorization:'Bearer '+process.env.TOKEN}:{}})" +
  ".then(r=>console.log(r.status))";

// The same claims a real admin token carries, signed with a key the auth service never published.
const forgedAdminToken = async (): Promise<string> => {
  const { privateKey } = await generateKeyPair("ES256");
  return new SignJWT({ role: "admin" })
    .setProtectedHeader({ alg: "ES256" })
    .setSubject("attacker")
    .setIssuer(TOKEN_ISSUER)
    .setAudience(TOKEN_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
};

// Opens a TCP connection from inside a container; a name on no shared network does not even resolve.
const reach = (from: string, host: string, port: number): Reach =>
  execFileSync(
    "docker",
    ["compose", "exec", "-T", from, "node", "-e", TCP_PROBE, host, String(port)],
    { encoding: "utf8" },
  ).trim() as Reach;

const TCP_PROBE =
  "const s=require('net').connect(Number(process.argv[2]),process.argv[1]);s.setTimeout(3000);" +
  "const done=(r)=>{console.log(r);s.destroy()};" +
  "s.on('connect',()=>done('reachable'));s.on('error',()=>done('unreachable'));s.on('timeout',()=>done('unreachable'))";

// Stands in for an admin console, which the project does not have.
const promoteToAdmin = (email: string): void => {
  execFileSync(
    "docker",
    [
      "compose", "exec", "-T", "postgres-auth", "psql", "-U", "auth", "-d", "auth",
      "-v", "ON_ERROR_STOP=1", "-v", `email=${email}`,
    ],
    {
      input: "UPDATE users SET role = 'admin' WHERE email = :'email';",
      stdio: ["pipe", "ignore", "inherit"],
    },
  );
};

const printRecentDecisions = (events: readonly AuditEvent[]): void => {
  console.log("        Latest decisions in Cassandra:");
  events.slice(0, 6).forEach((event) => {
    const verdict = event.allowed ? "allowed" : "denied ";
    console.log(`        ${verdict}  ${event.role.padEnd(8)}  ${event.method.padEnd(6)} ${event.path}  (${event.rule})`);
  });
};

const repeat = async (
  times: number,
  attempt: () => Promise<Result>,
): Promise<readonly Result[]> =>
  times === 0 ? [] : [await attempt(), ...(await repeat(times - 1, attempt))];

// Reads Cassandra directly: the newest event in today's partition, by its rule name.
const latestAuditRule = (): string => {
  const day = new Date().toISOString().slice(0, 10);
  const output = execFileSync(
    "docker",
    [
      "compose", "exec", "-T", "cassandra", "cqlsh", "-e",
      `SELECT rule FROM zt_audit.events_by_day WHERE day = '${day}' LIMIT 1`,
    ],
    { encoding: "utf8" },
  );
  const lines = output.split("\n").map((line) => line.trim()).filter(Boolean);
  return lines[lines.findIndex((line) => /^-+$/.test(line)) + 1] ?? "";
};

const compose = (...args: readonly string[]): void => {
  execFileSync("docker", ["compose", ...args], { stdio: "ignore" });
};

const retryUntil = async (
  attempt: () => Promise<Result>,
  expected: number,
  triesLeft = 30,
): Promise<Result> => {
  const result = await attempt();
  if (result.status === expected || triesLeft === 0) {
    return result;
  }
  await new Promise((resolve) => setTimeout(resolve, 1000));
  return retryUntil(attempt, expected, triesLeft - 1);
};

await main();
