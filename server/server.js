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

import connectDB from "./config/db.js";
import { initializeAlertService } from "./services/alertService.js";

import {
  startDetectionWorker,
  stopDetectionWorker
} from "./services/detectionWorker.js";

dotenv.config();

const app = express();

/*
|--------------------------------------------------------------------------
| Database
|--------------------------------------------------------------------------
*/

connectDB();

/*
|--------------------------------------------------------------------------
| Middleware
|--------------------------------------------------------------------------
*/

app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "PUT", "DELETE"]
  })
);

app.use(helmet());
app.use(compression());
app.use(express.json());
app.use(morgan("dev"));

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

app.use("/api/system", systemRoutes);
app.use("/api/network", networkRoutes);
app.use("/api/detection", detectionRoutes);

/*
|--------------------------------------------------------------------------
| Root
|--------------------------------------------------------------------------
*/

app.get("/", (req, res) => {
  res.json({
    success: true,
    project: "SentinelX IDPS",
    version: "1.0.0",
    status: "Running"
  });
});

/*
|--------------------------------------------------------------------------
| HTTP Server
|--------------------------------------------------------------------------
*/

const PORT = process.env.PORT || 5000;

const server = http.createServer(app);

/*
|--------------------------------------------------------------------------
| Socket.IO
|--------------------------------------------------------------------------
*/

const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"]
  }
});

/*
|--------------------------------------------------------------------------
| Alert Service
|--------------------------------------------------------------------------
*/

initializeAlertService(io);

/*
|--------------------------------------------------------------------------
| Socket Connections
|--------------------------------------------------------------------------
*/

io.on("connection", (socket) => {
  console.log(`🔌 Dashboard connected: ${socket.id}`);

  socket.on("disconnect", () => {
    console.log(`🔌 Dashboard disconnected: ${socket.id}`);
  });
});

/*
|--------------------------------------------------------------------------
| Start Server
|--------------------------------------------------------------------------
*/

server.listen(PORT, () => {
  console.log(`🚀 SentinelX Server Running on Port ${PORT}`);
  console.log(`🔌 Socket.IO Ready`);

  startDetectionWorker();
});
process.on("SIGINT", () => {
  console.log("\n🛑 Shutting down SentinelX...");

  stopDetectionWorker();

  server.close(() => {
    process.exit(0);
  });
});