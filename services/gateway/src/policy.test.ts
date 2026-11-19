import { describe, expect, it } from "vitest";
import type { Principal } from "@zt/common";
import { DEFAULT_DENY, evaluate, type Rule } from "./policy";
import { defaultRules, LOCKOUT_THRESHOLD } from "./rules";

const employee: Principal = { id: "u1", role: "employee" };
const admin: Principal = { id: "u2", role: "admin" };
const service: Principal = { id: "gateway", role: "service" };

const decide = (
  principal: Principal | undefined,
  method: string,
  path: string,
  recentDenials = 0,
) => evaluate(defaultRules, { principal, method, path, recentDenials });

describe("evaluate", () => {
  it("denies by default when no rule matches", () => {
    expect(
      evaluate([], { principal: admin, method: "GET", path: "/api/x", recentDenials: 0 }),
    ).toEqual({
      allowed: false,
      rule: DEFAULT_DENY,
    });
  });

  it("lets a deny override an allow regardless of order", () => {
    const rules: readonly Rule[] = [
      { name: "allow-all", effect: "allow", matches: () => true },
      { name: "deny-all", effect: "deny", matches: () => true },
    ];
    expect(
      evaluate(rules, { principal: admin, method: "GET", path: "/", recentDenials: 0 }),
    ).toEqual({
      allowed: false,
      rule: "deny-all",
    });
  });
});

describe("defaultRules", () => {
  it("denies anonymous requests", () => {
    expect(decide(undefined, "GET", "/api/documents").allowed).toBe(false);
  });

  it("lets employees read documents but not change them", () => {
    expect(decide(employee, "GET", "/api/documents/123").allowed).toBe(true);
    expect(decide(employee, "POST", "/api/documents").allowed).toBe(false);
    expect(decide(employee, "DELETE", "/api/documents/123").allowed).toBe(false);
  });

  it("lets admins manage documents and read the audit trail", () => {
    expect(decide(admin, "DELETE", "/api/documents/123").allowed).toBe(true);
    expect(decide(admin, "GET", "/api/audit").allowed).toBe(true);
  });

  it("keeps the audit trail read-only and admin-only", () => {
    expect(decide(employee, "GET", "/api/audit").allowed).toBe(false);
    expect(decide(admin, "POST", "/api/audit").allowed).toBe(false);
  });

  it("does not treat a look-alike prefix as a match", () => {
    expect(decide(employee, "GET", "/api/documents-private").allowed).toBe(false);
  });

  it("locks out a principal with repeated recent denials, even for allowed requests", () => {
    expect(decide(employee, "GET", "/api/documents", LOCKOUT_THRESHOLD - 1).allowed).toBe(true);
    expect(decide(employee, "GET", "/api/documents", LOCKOUT_THRESHOLD)).toEqual({
      allowed: false,
      rule: "suspicious-activity-lockout",
    });
  });

  it("blocks service tokens at the edge", () => {
    expect(decide(service, "GET", "/api/documents")).toEqual({
      allowed: false,
      rule: "service-tokens-blocked-at-edge",
    });
  });
});
