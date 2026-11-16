import { describe, expect, it } from "vitest";
import { login, register, type AccountDeps } from "./accounts";
import type { MfaProvider } from "./mfa";
import { scryptPasswordHasher } from "./passwords";
import { createInMemoryUserRepository } from "./userRepository";

// A stand-in for TOTP: any implementation of MfaProvider can replace the real one.
const fixedCodeMfa: MfaProvider = {
  generateSecret: () => "secret",
  enrollmentUri: (email, secret) => `otpauth://test/${email}?secret=${secret}`,
  check: (code, secret) => secret === "secret" && code === "123456",
};

const createDeps = (): AccountDeps => ({
  users: createInMemoryUserRepository(),
  passwords: scryptPasswordHasher,
  mfa: fixedCodeMfa,
});

const PASSWORD = "correct horse battery";

describe("register", () => {
  it("creates an employee and returns MFA enrollment details", async () => {
    const deps = createDeps();
    const enrollment = await register(deps, "Ada@Example.com", PASSWORD);
    expect(enrollment?.totpUri).toContain("ada@example.com");
    const stored = await deps.users.findByEmail("ada@example.com");
    expect(stored?.role).toBe("employee");
    expect(stored?.passwordHash).not.toContain(PASSWORD);
  });

  it("refuses a duplicate email", async () => {
    const deps = createDeps();
    await register(deps, "ada@example.com", PASSWORD);
    expect(await register(deps, "ADA@example.com", PASSWORD)).toBeUndefined();
  });
});

describe("login", () => {
  it("succeeds only with the right password and MFA code", async () => {
    const deps = createDeps();
    const enrollment = await register(deps, "ada@example.com", PASSWORD);

    expect(await login(deps, "ada@example.com", PASSWORD, "123456")).toEqual({
      id: enrollment?.userId,
      role: "employee",
    });
    expect(await login(deps, "ada@example.com", "wrong password!", "123456")).toBeUndefined();
    expect(await login(deps, "ada@example.com", PASSWORD, "000000")).toBeUndefined();
  });

  it("rejects an unknown email", async () => {
    expect(await login(createDeps(), "nobody@example.com", PASSWORD, "123456")).toBeUndefined();
  });
});
