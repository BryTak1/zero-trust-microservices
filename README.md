# Zero Trust Microservices

A small Zero Trust platform built as four microservices, for CMPE 272 (Enterprise Software Platforms).
No request is trusted because of where it comes from: every call is authenticated, authorised against
policy, and recorded.

## Architecture

```mermaid
flowchart LR
    client([Client]) -->|HTTPS in production| gateway
    subgraph internal network
        gateway[gateway<br/>policy enforcement point]
        auth[auth-service<br/>identity, MFA, tokens]
        resource[resource-service<br/>documents API]
        audit[audit-service<br/>append-only trail]
        pg[(Postgres<br/>auth db / resources db)]
        cass[(Cassandra<br/>events_by_day)]
    end
    gateway -->|login, register| auth
    gateway -->|allowed requests + user token| resource
    gateway -->|every decision + service token| audit
    auth --> pg
    resource --> pg
    audit --> cass
    resource -.->|verify token via JWKS| auth
    audit -.->|verify token via JWKS| auth
```

| Service | Responsibility | Store |
|---|---|---|
| `gateway` | Only public entry point. Verifies the token, evaluates policy, audits the decision, forwards. | none |
| `auth-service` | Registration, password + TOTP login, issues 5-minute ES256 tokens, publishes JWKS. | Postgres (`postgres-auth`) |
| `resource-service` | Example protected API (`/documents`). Re-verifies the token and role itself. | Postgres (`postgres-resources`) |
| `audit-service` | Stores every allow/deny decision. Writes need a service token, reads need an admin. | Cassandra |

Postgres holds users and documents because they need uniqueness and consistent reads. Cassandra holds
audit events because they are write-heavy, never updated, and always read by time range; the table is
partitioned by day so that query hits one partition.

### Micro-segmentation

Docker networks join only the containers that must talk, and each Postgres instance has its own login.
Only `edge` can reach the host; every other network is internal.

| Network | Members |
|---|---|
| `edge` | gateway (published on `127.0.0.1:8080`) |
| `gateway-auth`, `gateway-resource`, `gateway-audit` | gateway and that one service |
| `auth-resource`, `auth-audit` | auth-service and the service that fetches its public key |
| `auth-db`, `resource-db`, `audit-db` | each service and its own database |

So the gateway reaches no database, and resource-service cannot reach the audit service, Cassandra
or the auth database.

### Adaptive policy

The gateway counts each user's recent denials. With 5 or more in 60 seconds, the
`suspicious-activity-lockout` rule denies everything, even requests the user is normally allowed.
Denials during the lockout also count, so it lasts as long as the probing does. This turns the
monitoring into an automatic response, and was added as one new rule without changing `evaluate`.

## Run it

Requires Docker. Cassandra needs about 1 GB of RAM and around a minute to start.

```bash
cp .env.example .env   # then fill in both values, e.g. with: openssl rand -hex 32
docker compose up -d --build --wait
```

Run the scripted walkthrough (needs Node 22+ and `npm install` on the host):

```bash
npm run demo
```

It runs 23 checks in seven groups and prints PASS or FAIL for each:

- **Identity:** a wrong one-time code is refused, and the right one issues a token.
- **Least privilege:** requests with no token, an employee writing or reading the audit trail, and a path traversal attempt are all refused.
- **Backends do not trust the gateway:** calling `resource-service` directly, with no token or a forged admin token, is refused.
- **Micro-segmentation:** from inside the containers, resource-service reaches its own database but not the auth database, Cassandra or the audit service, and the gateway reaches no database.
- **Policy grants rights:** after promotion to admin, the same user can create documents and read the audit trail, and the latest decisions are printed from Cassandra.
- **Fail closed:** with `audit-service` stopped, requests get 503; once it is back, access returns.
- **Adaptive policy:** after 5 denied attempts, the user's normal reads are blocked too, and Cassandra records the `suspicious-activity-lockout` rule.

The script briefly stops and restarts `audit-service`, and promotes its test user to admin directly in Postgres.

To use the admin API by hand, promote an account, then log in again:

```bash
docker compose exec postgres-auth psql -U auth -d auth -c "UPDATE users SET role='admin' WHERE email='<email>'"
```

An admin can `POST`/`DELETE` `/api/documents` and read `GET /api/audit?day=YYYY-MM-DD`.

### API (through the gateway on `localhost:8080`)

| Method and path | Who | Notes |
|---|---|---|
| `POST /auth/register` | anyone | `{email, password}` (12+ chars). Returns the TOTP secret once. |
| `POST /auth/login` | anyone | `{email, password, totpCode}`. Returns `accessToken`. |
| `GET /api/documents`, `GET /api/documents/:id` | employee, admin | |
| `POST /api/documents`, `DELETE /api/documents/:id` | admin | |
| `GET /api/audit` | admin | Optional `?day=`; defaults to today (UTC). |

## Development

```bash
npm install
npm test
npm run typecheck
```

To install a package inside a running container, name the service and working directory:

```bash
docker compose exec -w /app gateway npm install <package> -w @zt/gateway
```

Set `AUDIT_STORE=memory` on `audit-service` to run without Cassandra.

## SOLID in this codebase

The code is functional (factory functions and plain data, no classes apart from one error type), so
"interface" below means a TypeScript type that describes a set of functions.

- **Single responsibility.** One service per concern; inside a service, `app.ts` is HTTP only,
  domain logic (`accounts.ts`, `policy.ts`) is pure, and storage sits in its own file.
- **Open/closed.** `evaluate` in `gateway/src/policy.ts` never changes; new access rules are new
  entries in `rules.ts`.
- **Liskov substitution.** `createInMemoryUserRepository` and `createPostgresUserRepository` both
  satisfy `UserRepository`; the same holds for the document and audit stores, and tests rely on it.
- **Interface segregation.** Small, single-purpose types: `TokenVerifier`, `AuditSink`,
  `PasswordHasher`, `MfaProvider`. `AuditStore` has no update or delete at all.
- **Dependency inversion.** Each `main.ts` is the composition root that picks concrete
  implementations; everything else receives its dependencies as arguments.

## Threat model (STRIDE)

| Threat | Mitigation |
|---|---|
| Spoofing | scrypt password hashes, mandatory TOTP, ES256-signed 5-minute tokens, service identity for the gateway. |
| Tampering | Schema validation on every body, parameterised SQL/CQL, strict path allowlist in the proxy. |
| Repudiation | Every decision (allow and deny) is audited; access is refused if it cannot be recorded. |
| Information disclosure | Uniform login errors, no secrets or tokens in logs, signing key never leaves memory. |
| Denial of service | Rate limit on login/register, body size limits, upstream timeouts. |
| Elevation of privilege | Deny by default, deny overrides allow, registration cannot set a role, services re-check roles, repeated denials trigger a lockout, and network segmentation limits what a compromised service can reach. |

### Known limitations

- Traffic inside the Compose network is plain HTTP. Production would add TLS at the gateway and mTLS between services.
- Cassandra runs without authentication; only audit-service shares a network with it. Each Postgres login is the superuser of its own instance.
- Lockout counts live in the gateway's memory, so they reset on restart and would need a shared store, such as Redis, with several gateways.
- TOTP secrets are stored unencrypted, and a code can be replayed within its 30-second window.
- There is no enrolment-confirmation step, token revocation, or admin API; roles are changed in SQL.
- The rate limit is per client IP as seen by the gateway, so it needs `trust proxy` configured behind a load balancer.
- Registration reveals whether an email is already taken.
