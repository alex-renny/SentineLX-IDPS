import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import compression from "compression";
import systemRoutes from "./routes/systemRoutes.js";

import connectDB from "./config/db.js";

dotenv.config();

const app = express();

connectDB();

app.use(cors());
app.use(helmet());
app.use(compression());
app.use(express.json());
app.use(morgan("dev"));
app.use("/api/system", systemRoutes);

app.get("/", (req, res) => {
  res.json({
    success: true,
    project: "SentinelX IDPS",
    version: "1.0.0",
    status: "Running"
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 SentinelX Server Running on Port ${PORT}`);
});