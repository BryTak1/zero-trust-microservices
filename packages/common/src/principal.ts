export const ROLES = ["employee", "admin", "service"] as const;

export type Role = (typeof ROLES)[number];

export type Principal = {
  readonly id: string;
  readonly role: Role;
};

export const TOKEN_ISSUER = "zt-auth-service";
export const TOKEN_AUDIENCE = "zt-platform";
