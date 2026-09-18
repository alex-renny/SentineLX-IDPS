import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import compression from "compression";
import http from "http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Server } from "socket.io";
import rateLimit from "express-rate-limit";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import systemRoutes from "./routes/systemRoutes.js";
import networkRoutes from "./routes/networkRoutes.js";
import detectionRoutes from "./routes/detectionRoutes.js";
import alertRoutes from "./routes/alertRoutes.js";
import reportRoutes from "./routes/reportRoutes.js";
import settingsRoutes from "./routes/settingsRoutes.js";
import authRoutes from "./routes/authRoutes.js";
import userRoutes from "./routes/userRoutes.js";
import { applyRuntimeSettings, getSettings } from "./services/settingsService.js";
import { authenticate, requireRole, verifySocket } from "./middleware/auth.js";
import { allowMethods, rejectMongoOperators } from "./middleware/security.js";

import connectDB from "./config/db.js";
import { initializeAlertService ,getEngineStatus,} from "./services/alertService.js";

import {
  startDetectionWorker,
  stopDetectionWorker,
} from "./services/detectionWorker.js";

dotenv.config({
  path: path.resolve(__dirname, ".env"),
  override: false,
});

if (!process.env.SENTINELX_ADMIN_USERNAME) {
  process.env.SENTINELX_ADMIN_USERNAME = "admin";
}

if (!process.env.SENTINELX_JWT_SECRET && process.env.JWT_SECRET) {
  process.env.SENTINELX_JWT_SECRET = process.env.JWT_SECRET;
}

const app = express();

/* ============================================================
   DATABASE
   ============================================================ */

connectDB().then(async () => {
  try {
    applyRuntimeSettings(await getSettings());
  } catch (error) {
    console.warn("Using default runtime settings:", error.message);
  }
  startDetectionWorker();
});

/* ============================================================
   MIDDLEWARE
   ============================================================ */

app.use(
  cors({
    origin: (origin, callback) => callback(null, !origin || (process.env.SENTINELX_CORS_ORIGINS || "http://localhost:5173").split(",").map((item) => item.trim()).includes(origin)),
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(helmet({ crossOriginResourcePolicy: { policy: "same-origin" } }));
app.use(compression());
app.use(express.json({ limit: "100kb", strict: true }));
app.use(allowMethods);
app.use(rejectMongoOperators);
app.use(morgan("dev"));
app.use("/api", rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: "draft-8", legacyHeaders: false, message: { success: false, message: "Too many requests" } }));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: "draft-8", legacyHeaders: false }));

/* ============================================================
   API ROUTES
   ============================================================ */

app.use("/api/auth", authRoutes);
app.use("/api", authenticate, requireRole("admin", "user"));
app.use("/api/system", systemRoutes);
app.use("/api/network", networkRoutes);
app.use("/api/detection", detectionRoutes);
app.use("/api/alerts", alertRoutes);
app.use("/api/reports", reportRoutes);
app.use("/api/settings", settingsRoutes);
app.use("/api/users", userRoutes);

/* ============================================================
   ROOT
   ============================================================ */

app.get("/", (req, res) => {
  res.json({
    success: true,
    project: "SentinelX IDPS",
    version: "1.0.0",
    status: "Running",
  });
});

/* ============================================================
   HTTP SERVER
   ============================================================ */

const PORT = process.env.PORT || 5000;

const server = http.createServer(app);

/* ============================================================
   SOCKET.IO
   ============================================================ */

const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"],
  },
});

/* ============================================================
   ALERT SERVICE
   ============================================================ */

initializeAlertService(io);

/* ============================================================
   SOCKET CONNECTIONS
   ============================================================ */

io.on("connection", (socket) => {
  console.log(`🔌 Dashboard connected: ${socket.id}`);

  // Send current engine status to newly connected dashboard
  socket.emit("ENGINE_STATUS", {
    status: getEngineStatus(),
    timestamp: new Date().toISOString(),
  });

  socket.on("disconnect", () => {
    console.log(`🔌 Dashboard disconnected: ${socket.id}`);
  });
});

/* ============================================================
   START SERVER
   ============================================================ */

server.listen(PORT, () => {
  console.log(`🚀 SentinelX Server Running on Port ${PORT}`);
  console.log(`🔌 Socket.IO Ready`);

});
app.get("/health", (_req, res) => res.json({ success: true, status: "ok" }));
app.use((error, _req, res, _next) => {
  if (error instanceof SyntaxError && "body" in error) return res.status(400).json({ success: false, message: "Invalid JSON request" });
  console.error("Unhandled API error:", error.message);
  return res.status(500).json({ success: false, message: "Internal server error" });
});
io.use(verifySocket);

/* ============================================================
   GRACEFUL SHUTDOWN
   ============================================================ */

process.on("SIGINT", () => {
  console.log("\n🛑 Shutting down SentinelX...");

  stopDetectionWorker();

  server.close(() => {
    console.log("✅ Server stopped");
    process.exit(0);
  });
});

process.on("SIGTERM", () => {
  console.log("\n🛑 SIGTERM received. Shutting down...");

  stopDetectionWorker();

  server.close(() => {
    console.log("✅ Server stopped");
    process.exit(0);
  });
});
