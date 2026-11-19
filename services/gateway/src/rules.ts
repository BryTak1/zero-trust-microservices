import type { Role } from "@zt/common";
import type { AccessRequest, Rule } from "./policy";

export const LOCKOUT_THRESHOLD = 5;
export const LOCKOUT_WINDOW_MS = 60_000;

export const defaultRules: readonly Rule[] = [
  // Denials during a lockout also count, so the lockout lasts as long as the probing does.
  {
    name: "suspicious-activity-lockout",
    effect: "deny",
    matches: (request) => request.recentDenials >= LOCKOUT_THRESHOLD,
  },
  {
    name: "service-tokens-blocked-at-edge",
    effect: "deny",
    matches: (request) => request.principal?.role === "service",
  },
  {
    name: "staff-read-documents",
    effect: "allow",
    matches: (request) =>
      hasRole(request, "employee", "admin") &&
      request.method === "GET" &&
      isUnder(request.path, "/api/documents"),
  },
  {
    name: "admins-manage-documents",
    effect: "allow",
    matches: (request) =>
      hasRole(request, "admin") && isUnder(request.path, "/api/documents"),
  },
  {
    name: "admins-read-audit",
    effect: "allow",
    matches: (request) =>
      hasRole(request, "admin") &&
      request.method === "GET" &&
      isUnder(request.path, "/api/audit"),
  },
];

const hasRole = (request: AccessRequest, ...roles: readonly Role[]): boolean =>
  request.principal !== undefined && roles.includes(request.principal.role);

const isUnder = (path: string, prefix: string): boolean =>
  path === prefix || path.startsWith(`${prefix}/`);
