import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

export type PasswordHasher = {
  readonly hash: (password: string) => Promise<string>;
  readonly verify: (password: string, stored: string) => Promise<boolean>;
};

export const scryptPasswordHasher: PasswordHasher = {
  hash: async (password) => {
    const salt = randomBytes(16);
    const key = await derive(password, salt);
    return `${salt.toString("base64")}$${key.toString("base64")}`;
  },
  verify: async (password, stored) => {
    const [salt, key] = stored.split("$");
    if (!salt || !key) {
      return false;
    }
    const expected = Buffer.from(key, "base64");
    const actual = await derive(password, Buffer.from(salt, "base64"));
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  },
};

const KEY_LENGTH = 64;

const scryptAsync = promisify(scrypt) as (
  password: string,
  salt: Buffer,
  keyLength: number,
) => Promise<Buffer>;

const derive = (password: string, salt: Buffer): Promise<Buffer> =>
  scryptAsync(password, salt, KEY_LENGTH);
