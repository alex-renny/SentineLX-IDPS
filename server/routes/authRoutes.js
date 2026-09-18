import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import { audit } from "../services/auditService.js";
const router = express.Router();
router.post("/login", async (req, res) => {
  const username = String(req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const configuredUser = String(process.env.SENTINELX_ADMIN_USERNAME || process.env.ADMIN_USERNAME || "admin").trim().toLowerCase();
  const hash = process.env.SENTINELX_ADMIN_PASSWORD_HASH || process.env.ADMIN_PASSWORD_HASH || "";
  const secret = process.env.SENTINELX_JWT_SECRET || process.env.JWT_SECRET || "";
  if (!hash || secret.length < 32) return res.status(503).json({ success: false, message: "Authentication is not configured" });
  let user;
  if (username === configuredUser) {
    if (password.length <= 256 && await bcrypt.compare(password, hash)) user = { id: "bootstrap-admin", username: configuredUser, role: "admin" };
  } else if (password.length <= 256) {
    const databaseUser = await User.findOne({ username }).select("+passwordHash");
    if (databaseUser && !databaseUser.active) return res.status(403).json({ success: false, message: "Account is disabled" });
    if (databaseUser && await bcrypt.compare(password, databaseUser.passwordHash)) user = { id: databaseUser.id, username: databaseUser.username, role: databaseUser.role };
  }
  if (!user) { audit("AUTHENTICATION_FAILURE", { username }); return res.status(401).json({ success: false, message: "Invalid credentials" }); }
  const token = jwt.sign(user, secret, { algorithm: "HS256", expiresIn: "8h", issuer: "sentinelx-idps", audience: "sentinelx-ui" });
  audit("AUTHENTICATION_SUCCESS", { username: user.username, role: user.role });
  return res.json({ success: true, token, user });
});
export default router;
