import express from "express";
import { getSystemStats } from "../services/systemMonitor.js";

const router = express.Router();

router.get("/stats", async (req, res) => {
  try {
    const stats = await getSystemStats();

    res.json({
      success: true,
      data: stats
    });

  } catch (error) {
    console.error("System monitoring error:", error.message);

    res.status(500).json({
      success: false,
      message: "Unable to retrieve system statistics"
    });
  }
});

export default router;