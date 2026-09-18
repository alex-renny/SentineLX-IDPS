import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { audit } from "../services/auditService.js";
const router = express.Router();
router.post("/login", async (req, res) => { const username = String(req.body?.username || "").trim(); const password = String(req.body?.password || ""); const configuredUser = process.env.SENTINELX_ADMIN_USERNAME || process.env.ADMIN_USERNAME || "admin"; const hash = process.env.SENTINELX_ADMIN_PASSWORD_HASH || process.env.ADMIN_PASSWORD_HASH || ""; const secret = process.env.SENTINELX_JWT_SECRET || process.env.JWT_SECRET || ""; if (!hash || secret.length < 32) return res.status(503).json({ success: false, message: "Authentication is not configured" }); const valid = username === configuredUser && password.length <= 256 && await bcrypt.compare(password, hash); if (!valid) { audit("AUTHENTICATION_FAILURE", { username }); return res.status(401).json({ success: false, message: "Invalid credentials" }); } const token = jwt.sign({ sub: configuredUser, role: "admin" }, secret, { algorithm: "HS256", expiresIn: "8h", issuer: "sentinelx-idps", audience: "sentinelx-ui" }); audit("AUTHENTICATION_SUCCESS", { username: configuredUser }); res.json({ success: true, token, user: { username: configuredUser, role: "admin" } }); });
export default router;
