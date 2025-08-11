import fs from "fs";
import path from "path";
import sqlite3 from "sqlite3";
import { promisify } from "util";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

sqlite3.verbose();

const DATA_DIR = path.join(__dirname, "..", "data");
const DB_PATH = path.join(DATA_DIR, "app.sqlite");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(DB_PATH);

db.runAsync = promisify(db.run.bind(db));
db.getAsync = promisify(db.get.bind(db));
db.allAsync = promisify(db.all.bind(db));

async function migrate() {
  await db.runAsync(`PRAGMA journal_mode = WAL;`);

  await db.runAsync(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      salt TEXT NOT NULL,
      hash TEXT NOT NULL,
      createdAt INTEGER NOT NULL,
      failed INTEGER DEFAULT 0,
      lockUntil INTEGER DEFAULT 0
    )
  `);

  await db.runAsync(`
    CREATE TABLE IF NOT EXISTS tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      name TEXT NOT NULL,
      tokenHash TEXT NOT NULL,
      createdAt INTEGER NOT NULL,
      lastUsedAt INTEGER,
      expiresAt INTEGER,
      revoked INTEGER DEFAULT 0,
      FOREIGN KEY(userId) REFERENCES users(id)
    )
  `);

  await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(tokenHash)`);
  await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(userId)`);
}

export { db, migrate, DB_PATH };
