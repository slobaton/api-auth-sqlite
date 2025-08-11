import crypto from "crypto";
import { findTokenByHash, markTokenUsed } from "../tokens/tokens.js";

// Password hashing
function generateSalt() {
  return crypto.randomBytes(16).toString("base64");
}
function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, key) => {
      if (err) return reject(err);
      resolve(key.toString("base64"));
    });
  });
}

// Validaciones
function validateUsername(u) { return /^[a-zA-Z0-9_.-]{3,30}$/.test(u || ""); }
function validatePassword(pw) { return typeof pw === "string" && pw.length >= 8 && pw.length <= 128; }

// Token
function generateTokenValue() { return crypto.randomBytes(32).toString("base64url"); }
function hashTokenValue(tokenValue) { return crypto.createHash("sha256").update(tokenValue).digest("hex"); }

// Middleware Bearer
function bearerAuth() {
  return async (req, res, next) => {
    try {
      const auth = req.headers.authorization || "";
      if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "Falta token Bearer" });
      const tokenValue = auth.slice(7).trim();
      if (!tokenValue) return res.status(401).json({ error: "Token vacío" });

      const row = await findTokenByHash(hashTokenValue(tokenValue));
      if (!row || row.revoked) return res.status(401).json({ error: "Token inválido" });
      if (row.expiresAt && Date.now() > row.expiresAt) return res.status(401).json({ error: "Token expirado" });

      req.auth = { tokenId: row.id, userId: row.userId };
      await markTokenUsed(row.id, Date.now());
      next();
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Error de autenticación" });
    }
  };
}

export {
  generateSalt,
  hashPassword,
  validateUsername,
  validatePassword,
  generateTokenValue,
  hashTokenValue,
  bearerAuth
};
