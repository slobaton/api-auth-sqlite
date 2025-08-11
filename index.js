import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cors from "cors";
import crypto from "crypto";

import { migrate } from "./db/db.js";
import {
  validateUsername,
  validatePassword,
  hashPassword,
  generateTokenValue,
  hashTokenValue,
  bearerAuth
} from "./helpers/helpers.js";
import {
  createUser,
  findUserByUsername,
  recordFailedLogin,
  resetFailures
} from "./users/users.js";
import {
  createToken,
  revokeToken
} from "./tokens/tokens.js";

const PORT = process.env.PORT || 8080;
const ORIGIN = process.env.ORIGIN || "http://localhost:5173";
const ACCESS_TTL_MS = 1000 * 60 * 60 * 8; // 8h

await migrate();

const app = express();

app.use(helmet({
  contentSecurityPolicy: false,           // sólo API JSON
  referrerPolicy: { policy: "no-referrer" },
  frameguard: { action: "deny" }
}));
app.use(cors({ origin: ORIGIN, credentials: false })); // sin cookies
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(rateLimit({ windowMs: 60_000, max: 100 }));

app.get("/health", (_, res) => res.json({ ok: true }));

// Registro
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!validateUsername(username)) return res.status(400).json({ error: "Usuario inválido" });
    if (!validatePassword(password)) return res.status(400).json({ error: "Password inválido" });

    await createUser(username, password);
    res.status(201).json({ message: "Usuario creado" });
  } catch (err) {
    if (err && err.code === "SQLITE_CONSTRAINT") return res.status(409).json({ error: "Usuario ya existe" });
    console.error(err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Login emite token opaco
app.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!validateUsername(username) || !validatePassword(password))
    return res.status(400).json({ error: "Credenciales inválidas" });

  const user = await findUserByUsername(username);
  if (!user) return res.status(401).json({ error: "Usuario o contraseña incorrectos" });

  if (user.lockUntil && Date.now() < user.lockUntil) {
    const seconds = Math.ceil((user.lockUntil - Date.now()) / 1000);
    return res.status(429).json({ error: `Cuenta bloqueada. Intenta en ${seconds}s.` });
  }

  const computed = await hashPassword(password, user.salt);
  const ok = crypto.timingSafeEqual(Buffer.from(computed, "base64"), Buffer.from(user.hash, "base64"));
  if (!ok) {
    await recordFailedLogin(user);
    return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
  }

  await resetFailures(user.id);

  const tokenValue = generateTokenValue();
  const tokenHash  = hashTokenValue(tokenValue);
  const token = await createToken(user.id, "login", ACCESS_TTL_MS, tokenValue, tokenHash);

  res.json({ ok: true, token: token.token, expiresAt: token.expiresAt, user: { id: user.id, username: user.username } });
});

// Ruta protegida
app.get("/me", bearerAuth(), (req, res) => {
  res.json({ userId: req.auth.userId });
});

// Logout revoca token actual
app.post("/logout", bearerAuth(), async (req, res) => {
  try {
    await revokeToken(req.auth.tokenId, req.auth.userId);
    res.json({ message: "Token revocado" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "No se pudo revocar el token" });
  }
});

app.listen(PORT, () => console.log(`API en http://localhost:${PORT}`));
