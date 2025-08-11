import { db } from "../db/db.js";
import { generateSalt, hashPassword } from "../helpers/helpers.js";

async function createUser(username, password) {
  const salt = generateSalt();
  const hash = await hashPassword(password, salt);
  await db.runAsync(
    `INSERT INTO users (username, salt, hash, createdAt) VALUES (?, ?, ?, ?)`,
    [username.trim(), salt, hash, Date.now()]
  );
}

function findUserByUsername(username) {
  return db.getAsync(`SELECT * FROM users WHERE username = ?`, [username.trim()]);
}

async function recordFailedLogin(user) {
  const failed = (user.failed || 0) + 1;
  let lockUntil = user.lockUntil || 0;
  if (failed >= 5) {
    const backoff = Math.min(60_000 * 2 ** (failed - 5), 30 * 60_000); // máx 30m
    lockUntil = Date.now() + backoff;
  }
  await db.runAsync(`UPDATE users SET failed = ?, lockUntil = ? WHERE id = ?`, [failed, lockUntil, user.id]);
  return { failed, lockUntil };
}

function resetFailures(userId) {
  return db.runAsync(`UPDATE users SET failed = 0, lockUntil = 0 WHERE id = ?`, [userId]);
}

export {
  createUser,
  findUserByUsername,
  recordFailedLogin,
  resetFailures
};
