import express from "express";
import bcrypt from "bcrypt";
import mongoose from "mongoose";
import User from "../models/User.js";
import { requireAdmin } from "../middleware/auth.js";
import { audit } from "../services/auditService.js";

const router = express.Router();
const roles = ["admin", "user"];
const bootstrapUsername = () => String(process.env.SENTINELX_ADMIN_USERNAME || process.env.ADMIN_USERNAME || "admin").trim().toLowerCase();
const publicUser = (user) => ({ id: user.id || user._id?.toString(), username: user.username, email: user.email || "", role: user.role, active: user.active, createdAt: user.createdAt, updatedAt: user.updatedAt, source: "MongoDB" });
const validPassword = (password) => typeof password === "string" && password.length >= 8 && password.length <= 256;

function validId(id, res) {
  if (mongoose.isObjectIdOrHexString(id)) return true;
  res.status(400).json({ success: false, message: "Invalid user id" });
  return false;
}

async function ensureAdminRemains(target, changes) {
  const removesActiveAdmin = target.role === "admin" && target.active && (changes.active === false || changes.role === "user" || changes.delete === true);
  if (removesActiveAdmin && await User.countDocuments({ role: "admin", active: true }) <= 1) {
    const error = new Error("Cannot remove the last active database administrator");
    error.statusCode = 409;
    throw error;
  }
}

router.use(requireAdmin);

router.get("/", async (_req, res) => {
  try {
    const users = await User.find().sort({ username: 1 }).lean();
    const bootstrap = { id: "bootstrap-admin", username: bootstrapUsername(), email: "", role: "admin", active: true, source: "environment", createdAt: null, updatedAt: null };
    res.json({ success: true, users: [bootstrap, ...users.map(publicUser)] });
  } catch {
    res.status(500).json({ success: false, message: "Unable to list users" });
  }
});

router.post("/", async (req, res) => {
  try {
    const username = String(req.body?.username || "").trim().toLowerCase();
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = req.body?.password;
    const role = String(req.body?.role || "user").toLowerCase();
    if (username.length < 3 || username.length > 50 || !validPassword(password) || !roles.includes(role)) return res.status(400).json({ success: false, message: "Provide a username, password of at least 8 characters, and valid role" });
    if (username === bootstrapUsername()) return res.status(409).json({ success: false, message: "Username is reserved for the bootstrap administrator" });
    const user = await User.create({ username, email: email || undefined, passwordHash: await bcrypt.hash(password, 12), role });
    audit("USER_CREATED", { actor: req.user.username, target: user.username, role: user.role });
    res.status(201).json({ success: true, user: publicUser(user) });
  } catch (error) {
    if (error?.code === 11000) return res.status(409).json({ success: false, message: "Username already exists" });
    return res.status(400).json({ success: false, message: error.message || "Unable to create user" });
  }
});

router.patch("/:id", async (req, res) => {
  if (!validId(req.params.id, res)) return;
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    const changes = {};
    if (req.body?.email !== undefined) changes.email = String(req.body.email || "").trim().toLowerCase() || undefined;
    if (req.body?.role !== undefined) { changes.role = String(req.body.role).toLowerCase(); if (!roles.includes(changes.role)) return res.status(400).json({ success: false, message: "Invalid role" }); }
    if (req.body?.active !== undefined) { if (typeof req.body.active !== "boolean") return res.status(400).json({ success: false, message: "Active must be a boolean" }); changes.active = req.body.active; }
    await ensureAdminRemains(user, changes);
    Object.assign(user, changes);
    await user.save();
    const event = changes.active === false ? "USER_DISABLED" : changes.active === true ? "USER_ENABLED" : "USER_UPDATED";
    audit(event, { actor: req.user.username, target: user.username, role: user.role });
    res.json({ success: true, user: publicUser(user) });
  } catch (error) { res.status(error.statusCode || 400).json({ success: false, message: error.message || "Unable to update user" }); }
});

router.delete("/:id", async (req, res) => {
  if (!validId(req.params.id, res)) return;
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    await ensureAdminRemains(user, { delete: true });
    await user.deleteOne();
    audit("USER_DELETED", { actor: req.user.username, target: user.username, role: user.role });
    res.json({ success: true, message: "User deleted" });
  } catch (error) { res.status(error.statusCode || 500).json({ success: false, message: error.message || "Unable to delete user" }); }
});

router.post("/:id/reset-password", async (req, res) => {
  if (!validId(req.params.id, res)) return;
  try {
    const password = req.body?.password;
    if (!validPassword(password)) return res.status(400).json({ success: false, message: "Password must be between 8 and 256 characters" });
    const user = await User.findById(req.params.id).select("+passwordHash");
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    user.passwordHash = await bcrypt.hash(password, 12);
    await user.save();
    audit("USER_PASSWORD_RESET", { actor: req.user.username, target: user.username, role: user.role });
    res.json({ success: true, message: "Password reset" });
  } catch { res.status(500).json({ success: false, message: "Unable to reset password" }); }
});

export default router;
