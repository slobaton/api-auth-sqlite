import { db } from "../db/db.js";

// Crear token opaco
async function createToken(userId, name, ttlMs, tokenValue, tokenHash) {
  const now = Date.now();
  const expiresAt = ttlMs ? now + ttlMs : null;

  await db.runAsync(
    `INSERT INTO tokens (userId, name, tokenHash, createdAt, expiresAt, revoked)
     VALUES (?, ?, ?, ?, ?, 0)`,
    [userId, name, tokenHash, now, expiresAt]
  );

  // Aquí devolvemos el valor real del token
  return { token: tokenValue, expiresAt };
}

function findTokenByHash(tokenHash) {
  return db.getAsync(`SELECT * FROM tokens WHERE tokenHash = ?`, [tokenHash]);
}

function markTokenUsed(tokenId, whenMs) {
  return db.runAsync(`UPDATE tokens SET lastUsedAt = ? WHERE id = ?`, [whenMs || Date.now(), tokenId]);
}

function revokeToken(tokenId, userId) {
  return db.runAsync(`UPDATE tokens SET revoked = 1 WHERE id = ? AND userId = ?`, [tokenId, userId]);
}

export {
  createToken,
  findTokenByHash,
  markTokenUsed,
  revokeToken
};
