import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import compression from "compression";
import http from "http";
import { Server } from "socket.io";

import systemRoutes from "./routes/systemRoutes.js";
import networkRoutes from "./routes/networkRoutes.js";
import detectionRoutes from "./routes/detectionRoutes.js";
import alertRoutes from "./routes/alertRoutes.js";

import connectDB from "./config/db.js";
import { initializeAlertService } from "./services/alertService.js";

import {
  startDetectionWorker,
  stopDetectionWorker,
} from "./services/detectionWorker.js";

dotenv.config();

const app = express();

/* ============================================================
   DATABASE
   ============================================================ */

connectDB();

/* ============================================================
   MIDDLEWARE
   ============================================================ */

app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"],
  })
);

app.use(helmet());
app.use(compression());
app.use(express.json());
app.use(morgan("dev"));

/* ============================================================
   API ROUTES
   ============================================================ */

app.use("/api/system", systemRoutes);
app.use("/api/network", networkRoutes);
app.use("/api/detection", detectionRoutes);
app.use("/api/alerts", alertRoutes);

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

  startDetectionWorker();
});

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