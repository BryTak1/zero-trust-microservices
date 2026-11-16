import type { Pool } from "pg";
import type { Document, DocumentRepository } from "./documentRepository";

export const createPostgresDocumentRepository = async (
  pool: Pool,
): Promise<DocumentRepository> => {
  await pool.query(SCHEMA);
  return {
    list: async () => {
      const { rows } = await pool.query(`${SELECT} ORDER BY created_at DESC LIMIT 100`);
      return rows as Document[];
    },
    findById: async (id) => {
      const { rows } = await pool.query(`${SELECT} WHERE id = $1`, [id]);
      return rows[0] as Document | undefined;
    },
    insert: async (document) => {
      await pool.query(
        `INSERT INTO documents (id, title, body, created_by) VALUES ($1, $2, $3, $4)`,
        [document.id, document.title, document.body, document.createdBy],
      );
    },
    remove: async (id) => {
      const { rowCount } = await pool.query(`DELETE FROM documents WHERE id = $1`, [id]);
      return rowCount === 1;
    },
  };
};

const SELECT = `SELECT id, title, body, created_by AS "createdBy" FROM documents`;

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;
