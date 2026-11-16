import type { Pool } from "pg";
import type { User, UserRepository } from "./userRepository";

export const createPostgresUserRepository = async (
  pool: Pool,
): Promise<UserRepository> => {
  await pool.query(SCHEMA);
  return {
    findByEmail: async (email) => {
      const { rows } = await pool.query(
        `SELECT id, email, password_hash AS "passwordHash",
                totp_secret AS "totpSecret", role
           FROM users WHERE email = $1`,
        [email],
      );
      return rows[0] as User | undefined;
    },
    insert: async (user) => {
      const { rowCount } = await pool.query(
        `INSERT INTO users (id, email, password_hash, totp_secret, role)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (email) DO NOTHING`,
        [user.id, user.email, user.passwordHash, user.totpSecret, user.role],
      );
      return rowCount === 1;
    },
  };
};

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
