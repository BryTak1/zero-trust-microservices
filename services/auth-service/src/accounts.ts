import { randomUUID } from "node:crypto";
import type { Principal } from "@zt/common";
import type { MfaProvider } from "./mfa";
import type { PasswordHasher } from "./passwords";
import type { UserRepository } from "./userRepository";

export type AccountDeps = {
  readonly users: UserRepository;
  readonly passwords: PasswordHasher;
  readonly mfa: MfaProvider;
};

export type Enrollment = {
  readonly userId: string;
  readonly totpSecret: string;
  readonly totpUri: string;
};

export const register = async (
  deps: AccountDeps,
  email: string,
  password: string,
): Promise<Enrollment | undefined> => {
  const totpSecret = deps.mfa.generateSecret();
  const user = {
    id: randomUUID(),
    email: normalizeEmail(email),
    passwordHash: await deps.passwords.hash(password),
    totpSecret,
    // Self-registration never grants more than the lowest role.
    role: "employee" as const,
  };
  const created = await deps.users.insert(user);
  return created
    ? {
        userId: user.id,
        totpSecret,
        totpUri: deps.mfa.enrollmentUri(user.email, totpSecret),
      }
    : undefined;
};

export const login = async (
  deps: AccountDeps,
  email: string,
  password: string,
  totpCode: string,
): Promise<Principal | undefined> => {
  const user = await deps.users.findByEmail(normalizeEmail(email));
  // The hash is checked even for unknown emails so response time does not reveal which emails exist.
  const passwordOk = await deps.passwords.verify(
    password,
    user?.passwordHash ?? UNUSABLE_HASH,
  );
  if (!user || !passwordOk || !deps.mfa.check(totpCode, user.totpSecret)) {
    return undefined;
  }
  return { id: user.id, role: user.role };
};

const UNUSABLE_HASH = `${Buffer.alloc(16).toString("base64")}$${Buffer.alloc(64).toString("base64")}`;

const normalizeEmail = (email: string): string => email.trim().toLowerCase();
