import type { Role } from "@zt/common";

export type User = {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly totpSecret: string;
  readonly role: Role;
};

export type UserRepository = {
  readonly findByEmail: (email: string) => Promise<User | undefined>;
  // Resolves to false when the email is already taken.
  readonly insert: (user: User) => Promise<boolean>;
};

export const createInMemoryUserRepository = (): UserRepository => {
  const users = new Map<string, User>();
  return {
    findByEmail: async (email) => users.get(email),
    insert: async (user) => {
      if (users.has(user.email)) {
        return false;
      }
      users.set(user.email, user);
      return true;
    },
  };
};
